package authz

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"
	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"go.uber.org/zap"
)

// SPOCPAuthorizer uses a SPOCP engine for query authorization.
//
// Queries are converted to SPOCP S-expressions and evaluated against
// a policy ruleset. This allows fine-grained control over what AuthZEN
// queries are permitted through the proxy.
type SPOCPAuthorizer struct {
	engine *spocp.Engine
	logger *zap.Logger
	mu     sync.RWMutex
}

// SPOCPConfig configures the SPOCP authorizer.
type SPOCPConfig struct {
	// RulesFile is the path to the SPOCP rules file.
	// If empty, default rules are used.
	RulesFile string

	// DefaultRules are rule elements to use if no rules file is specified.
	// If both are empty, default wallet rules are used.
	DefaultRules []sexp.Element
}

// NewSPOCPAuthorizer creates a new SPOCP-based authorizer.
func NewSPOCPAuthorizer(cfg *SPOCPConfig, logger *zap.Logger) (*SPOCPAuthorizer, error) {
	engine := spocp.NewEngine()
	auth := &SPOCPAuthorizer{
		engine: engine,
		logger: logger.Named("spocp-authz"),
	}

	// Load rules
	if cfg != nil && cfg.RulesFile != "" {
		if err := auth.LoadRulesFile(cfg.RulesFile); err != nil {
			return nil, fmt.Errorf("failed to load rules file: %w", err)
		}
	} else if cfg != nil && len(cfg.DefaultRules) > 0 {
		for _, rule := range cfg.DefaultRules {
			engine.AddRuleElement(rule)
		}
	} else {
		// Use default wallet rules
		for _, rule := range DefaultWalletRules() {
			engine.AddRuleElement(rule)
		}
	}

	auth.logger.Info("SPOCP authorizer initialized",
		zap.Int("rule_count", engine.RuleCount()),
	)

	return auth, nil
}

// LoadRulesFile loads SPOCP rules from a file.
// Rules are in canonical S-expression format and can span multiple lines.
// Comments (lines starting with #, ;, or //) are ignored.
func (a *SPOCPAuthorizer) LoadRulesFile(path string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Use go-spocp's built-in file loading which supports:
	// - Multi-line S-expressions
	// - Comments (#, ;, //)
	// - Whitespace handling
	cleanPath := filepath.Clean(path)
	if err := a.engine.LoadRulesFromFile(cleanPath); err != nil {
		return fmt.Errorf("failed to load rules from %s: %w", cleanPath, err)
	}

	return nil
}

// Authorize implements Authorizer.
func (a *SPOCPAuthorizer) Authorize(ctx context.Context, req *AuthorizationRequest) error {
	if req.Request == nil {
		return ErrInvalidQuery
	}

	// Build SPOCP query from AuthZEN request
	query := a.buildQuery(req)

	a.mu.RLock()
	authorized := a.engine.QueryElement(query)
	a.mu.RUnlock()

	if !authorized {
		a.logger.Debug("query denied by policy",
			zap.String("tenant_id", req.TenantID),
			zap.String("subject_id", req.Request.Subject.ID),
			zap.String("resource_type", req.Request.Resource.Type),
			zap.String("action", getActionName(req.Request)),
		)
		return ErrUnauthorized
	}

	return nil
}

// buildQuery converts an AuthorizationRequest to a SPOCP S-expression.
//
// The query structure is:
// (authzen
//
//	(tenant <tenant_id>)
//	(action <action_name>)
//	(resource (type <type>)(id <id>))
//	(subject (type <type>)(id <id>)))
func (a *SPOCPAuthorizer) buildQuery(req *AuthorizationRequest) sexp.Element {
	// Build tenant element
	tenantElem := sexp.NewList("tenant", sexp.NewAtom(req.TenantID))

	// Build action element
	actionName := getActionName(req.Request)
	var actionElem sexp.Element
	if actionName != "" {
		actionElem = sexp.NewList("action", sexp.NewAtom(actionName))
	} else {
		actionElem = sexp.NewList("action") // empty action = resolution
	}

	// Build resource element
	resourceType := req.Request.Resource.Type
	if resourceType == "" {
		resourceType = "resolution"
	}
	resourceElem := sexp.NewList("resource",
		sexp.NewList("type", sexp.NewAtom(resourceType)),
		sexp.NewList("id", sexp.NewAtom(req.Request.Resource.ID)),
	)

	// Build subject element
	subjectElem := sexp.NewList("subject",
		sexp.NewList("type", sexp.NewAtom(req.Request.Subject.Type)),
		sexp.NewList("id", sexp.NewAtom(req.Request.Subject.ID)),
	)

	// Combine into full query
	return sexp.NewList("authzen",
		tenantElem,
		actionElem,
		resourceElem,
		subjectElem,
	)
}

func getActionName(req *gotrust.EvaluationRequest) string {
	if req.Action != nil {
		return req.Action.Name
	}
	return ""
}

// DefaultWalletRules returns the default SPOCP rules for wallet trust queries.
//
// These rules allow standard wallet operations while blocking potentially
// dangerous or resource-intensive queries.
func DefaultWalletRules() []sexp.Element {
	// Set of allowed actions
	allowedActions := &starform.Set{
		Elements: []sexp.Element{
			sexp.NewAtom("credential-issuer"),
			sexp.NewAtom("credential-verifier"),
			sexp.NewAtom("wallet-provider"),
			sexp.NewAtom("pid-provider"),
			sexp.NewAtom("mdl-issuer"),
		},
	}

	// Set of allowed resource types for key material
	allowedKeyTypes := &starform.Set{
		Elements: []sexp.Element{
			sexp.NewAtom("jwk"),
			sexp.NewAtom("x5c"),
			sexp.NewAtom("x509_san_dns"),
		},
	}

	return []sexp.Element{
		// Rule 1: Allow credential evaluation with standard key types
		// (authzen (tenant)(action <credential-issuer|credential-verifier|...>)(resource (type <jwk|x5c|...>)(id))(subject (type key)(id)))
		sexp.NewList("authzen",
			sexp.NewList("tenant"),                 // any tenant
			sexp.NewList("action", allowedActions), // allowed actions
			sexp.NewList("resource",
				sexp.NewList("type", allowedKeyTypes), // allowed key types
				sexp.NewList("id"),                    // any id
			),
			sexp.NewList("subject",
				sexp.NewList("type", sexp.NewAtom("key")), // type must be "key"
				sexp.NewList("id"),                        // any id
			),
		),

		// Rule 2: Allow resolution-only requests for DIDs
		// (authzen (tenant)(action)(resource (type resolution)(id))(subject (type key)(id did:*)))
		sexp.NewList("authzen",
			sexp.NewList("tenant"),
			sexp.NewList("action"), // empty action = resolution
			sexp.NewList("resource",
				sexp.NewList("type", sexp.NewAtom("resolution")),
				sexp.NewList("id"),
			),
			sexp.NewList("subject",
				sexp.NewList("type", sexp.NewAtom("key")),
				sexp.NewList("id", &starform.Prefix{Value: "did:"}), // DID prefix
			),
		),

		// Rule 3: Allow resolution for OIDF entities (https://)
		sexp.NewList("authzen",
			sexp.NewList("tenant"),
			sexp.NewList("action"),
			sexp.NewList("resource",
				sexp.NewList("type", sexp.NewAtom("resolution")),
				sexp.NewList("id"),
			),
			sexp.NewList("subject",
				sexp.NewList("type", sexp.NewAtom("key")),
				sexp.NewList("id", &starform.Prefix{Value: "https://"}),
			),
		),

		// Rule 4: Allow resolution for HTTP URLs (dev environments)
		sexp.NewList("authzen",
			sexp.NewList("tenant"),
			sexp.NewList("action"),
			sexp.NewList("resource",
				sexp.NewList("type", sexp.NewAtom("resolution")),
				sexp.NewList("id"),
			),
			sexp.NewList("subject",
				sexp.NewList("type", sexp.NewAtom("key")),
				sexp.NewList("id", &starform.Prefix{Value: "http://"}),
			),
		),
	}
}

// ProductionWalletRules returns stricter rules for production deployments.
func ProductionWalletRules() []sexp.Element {
	return []sexp.Element{
		// Only allow credential evaluation with x5c (certificate chains)
		sexp.NewList("authzen",
			sexp.NewList("tenant"),
			sexp.NewList("action", &starform.Set{Elements: []sexp.Element{
				sexp.NewAtom("credential-issuer"),
				sexp.NewAtom("credential-verifier"),
			}}),
			sexp.NewList("resource",
				sexp.NewList("type", sexp.NewAtom("x5c")),
				sexp.NewList("id"),
			),
			sexp.NewList("subject",
				sexp.NewList("type", sexp.NewAtom("key")),
				sexp.NewList("id"),
			),
		),

		// Allow DID resolution only (HTTPS only in production)
		sexp.NewList("authzen",
			sexp.NewList("tenant"),
			sexp.NewList("action"),
			sexp.NewList("resource",
				sexp.NewList("type", sexp.NewAtom("resolution")),
				sexp.NewList("id"),
			),
			sexp.NewList("subject",
				sexp.NewList("type", sexp.NewAtom("key")),
				sexp.NewList("id", &starform.Prefix{Value: "did:web:"}),
			),
		),

		// Allow OIDF entity resolution (HTTPS only)
		sexp.NewList("authzen",
			sexp.NewList("tenant"),
			sexp.NewList("action"),
			sexp.NewList("resource",
				sexp.NewList("type", sexp.NewAtom("resolution")),
				sexp.NewList("id"),
			),
			sexp.NewList("subject",
				sexp.NewList("type", sexp.NewAtom("key")),
				sexp.NewList("id", &starform.Prefix{Value: "https://"}),
			),
		),
	}
}
