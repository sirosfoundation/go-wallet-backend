// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
)

// tenantTransport is an HTTP RoundTripper that adds X-Tenant-ID from context.
type tenantTransport struct {
	base http.RoundTripper
}

func (t *tenantTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Extract tenant ID from context and add to request
	if tenantID := TenantFromContext(req.Context()); tenantID != "" {
		// Clone request to avoid mutating the original
		req2 := req.Clone(req.Context())
		req2.Header.Set("X-Tenant-ID", tenantID)
		req = req2
	}
	return t.base.RoundTrip(req)
}

// TrustService provides trust evaluation for engine flows.
// All trust evaluation is delegated to a remote trust endpoint (AuthZEN PDP).
// Per ADR-010, no local trust evaluation is performed to avoid false positives.
type TrustService struct {
	cfg    *config.Config
	logger *zap.Logger

	// Evaluator cache by endpoint URL
	evaluators   map[string]*authzen.Evaluator
	evaluatorsMu sync.RWMutex
}

// NewTrustService creates a new trust service.
// Trust evaluation is delegated to the configured trust endpoint.
func NewTrustService(cfg *config.Config, logger *zap.Logger) *TrustService {
	return &TrustService{
		cfg:        cfg,
		logger:     logger.Named("trust"),
		evaluators: make(map[string]*authzen.Evaluator),
	}
}

// KeyMaterial represents cryptographic key material for trust evaluation.
// When provided, the key is validated against the subject binding.
// When nil, resolution-only mode is used (only works for DIDs).
type KeyMaterial struct {
	// Type indicates the key format: "x5c" or "jwk"
	Type string
	// X5C contains base64-encoded DER certificates (for x5c type)
	X5C []string
	// JWK contains JWK(S) data (for jwk type)
	JWK interface{}
}

// GetEvaluator returns an AuthZEN evaluator for the given endpoint.
// Uses the default endpoint if endpoint is empty.
// Returns nil if no trust endpoint is configured.
func (ts *TrustService) GetEvaluator(endpoint string) (*authzen.Evaluator, error) {
	if endpoint == "" {
		endpoint = ts.cfg.Trust.DefaultEndpoint
	}
	if endpoint == "" {
		return nil, nil // No trust configured
	}

	// Check cache
	ts.evaluatorsMu.RLock()
	eval, ok := ts.evaluators[endpoint]
	ts.evaluatorsMu.RUnlock()
	if ok {
		return eval, nil
	}

	// Create new evaluator
	ts.evaluatorsMu.Lock()
	defer ts.evaluatorsMu.Unlock()

	// Double-check after acquiring write lock
	if eval, ok := ts.evaluators[endpoint]; ok {
		return eval, nil
	}

	timeout := time.Duration(ts.cfg.Trust.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Create HTTP client with tenant transport for X-Tenant-ID propagation
	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &tenantTransport{
			base: http.DefaultTransport,
		},
	}

	// Create AuthZEN evaluator for this endpoint
	eval, err := authzen.NewEvaluatorWithHTTPClient(&authzen.Config{
		BaseURL: endpoint,
		Timeout: timeout,
	}, httpClient)
	if err != nil {
		return nil, err
	}

	ts.evaluators[endpoint] = eval
	ts.logger.Debug("Created trust evaluator", zap.String("endpoint", endpoint))
	return eval, nil
}

// EvaluateIssuer evaluates trust for a credential issuer via the trust endpoint.
// If keyMaterial is provided, validates the subject-to-key binding.
// If keyMaterial is nil, performs resolution-only (only works for DIDs).
func (ts *TrustService) EvaluateIssuer(ctx context.Context, issuerID string, trustEndpoint string, keyMaterial *KeyMaterial) (*TrustInfo, error) {
	eval, err := ts.GetEvaluator(trustEndpoint)
	if err != nil {
		return nil, err
	}
	if eval == nil {
		// No trust configured - return default trust info
		return &TrustInfo{
			Trusted:   true,
			Framework: "none",
			Reason:    "Trust evaluation not configured",
		}, nil
	}

	// Create evaluation request
	req := &trust.EvaluationRequest{
		Subject: trust.Subject{
			Type: trust.SubjectTypeKey,
			ID:   issuerID,
		},
	}
	req.SubjectID = issuerID
	req.Role = trust.RoleCredentialIssuer

	// Set key material if provided
	if keyMaterial != nil {
		switch keyMaterial.Type {
		case "x5c":
			req.KeyType = trust.KeyTypeX5C
			req.Resource = trust.Resource{
				Type: trust.ResourceTypeX5C,
				ID:   issuerID,
				Key:  keyMaterial.X5C,
			}
			req.Key = keyMaterial.X5C
			ts.logger.Debug("Trust evaluation with x5c",
				zap.String("issuer", issuerID),
				zap.Int("cert_count", len(keyMaterial.X5C)))
		case "jwk":
			req.KeyType = trust.KeyTypeJWK
			req.Resource = trust.Resource{
				Type: trust.ResourceTypeJWK,
				ID:   issuerID,
				Key:  keyMaterial.JWK,
			}
			req.Key = keyMaterial.JWK
			ts.logger.Debug("Trust evaluation with JWK",
				zap.String("issuer", issuerID))
		}
	} else {
		// Resolution-only mode (for DIDs)
		ts.logger.Debug("Trust evaluation resolution-only",
			zap.String("issuer", issuerID))
	}

	// Delegate evaluation to the trust endpoint
	resp, err := eval.Evaluate(ctx, req)
	if err != nil {
		ts.logger.Warn("Trust evaluation error",
			zap.String("issuer", issuerID),
			zap.Error(err))
		return &TrustInfo{
			Trusted:   false,
			Framework: "authzen",
			Reason:    "Trust evaluation failed: " + err.Error(),
		}, nil
	}

	return &TrustInfo{
		Trusted:   resp.Decision,
		Framework: "authzen",
		Reason:    resp.Reason,
	}, nil
}

// EvaluateVerifier evaluates trust for a credential verifier via the trust endpoint.
// If keyMaterial is provided, validates the subject-to-key binding.
// If keyMaterial is nil, performs resolution-only (only works for DIDs).
func (ts *TrustService) EvaluateVerifier(ctx context.Context, verifierID string, trustEndpoint string, keyMaterial *KeyMaterial) (*TrustInfo, error) {
	eval, err := ts.GetEvaluator(trustEndpoint)
	if err != nil {
		return nil, err
	}
	if eval == nil {
		// No trust configured - return default trust info
		return &TrustInfo{
			Trusted:   true,
			Framework: "none",
			Reason:    "Trust evaluation not configured",
		}, nil
	}

	// Create evaluation request
	req := &trust.EvaluationRequest{
		Subject: trust.Subject{
			Type: trust.SubjectTypeKey,
			ID:   verifierID,
		},
	}
	req.SubjectID = verifierID
	req.Role = trust.RoleCredentialVerifier

	// Set key material if provided
	if keyMaterial != nil {
		switch keyMaterial.Type {
		case "x5c":
			req.KeyType = trust.KeyTypeX5C
			req.Resource = trust.Resource{
				Type: trust.ResourceTypeX5C,
				ID:   verifierID,
				Key:  keyMaterial.X5C,
			}
			req.Key = keyMaterial.X5C
			ts.logger.Debug("Trust evaluation with x5c",
				zap.String("verifier", verifierID),
				zap.Int("cert_count", len(keyMaterial.X5C)))
		case "jwk":
			req.KeyType = trust.KeyTypeJWK
			req.Resource = trust.Resource{
				Type: trust.ResourceTypeJWK,
				ID:   verifierID,
				Key:  keyMaterial.JWK,
			}
			req.Key = keyMaterial.JWK
			ts.logger.Debug("Trust evaluation with JWK",
				zap.String("verifier", verifierID))
		}
	} else {
		// Resolution-only mode (for DIDs)
		ts.logger.Debug("Trust evaluation resolution-only",
			zap.String("verifier", verifierID))
	}

	// Delegate evaluation to the trust endpoint
	resp, err := eval.Evaluate(ctx, req)
	if err != nil {
		ts.logger.Warn("Trust evaluation error",
			zap.String("verifier", verifierID),
			zap.Error(err))
		return &TrustInfo{
			Trusted:   false,
			Framework: "authzen",
			Reason:    "Trust evaluation failed: " + err.Error(),
		}, nil
	}

	return &TrustInfo{
		Trusted:   resp.Decision,
		Framework: "authzen",
		Reason:    resp.Reason,
	}, nil
}
