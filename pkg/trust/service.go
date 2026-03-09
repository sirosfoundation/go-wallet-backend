// Package trust provides a plugin-based trust evaluation system for the wallet backend.
//
// The Service type provides trust evaluation for both engine (WebSocket) and
// HTTP service layers, with independent configuration for issuer (OID4VCI)
// and verifier (OID4VP) flows.

package trust

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Context keys for tenant propagation across trust evaluation boundaries.
type contextKey string

const (
	// TenantIDContextKey is the context key for tenant ID propagation to PDP requests.
	TenantIDContextKey contextKey = "trust_tenant_id"
)

// ContextWithTenant returns a context with the tenant ID set for trust evaluation.
func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantIDContextKey, tenantID)
}

// TenantFromContext extracts the tenant ID from context.
func TenantFromContext(ctx context.Context) string {
	if tenantID, ok := ctx.Value(TenantIDContextKey).(string); ok {
		return tenantID
	}
	return ""
}

// TenantTransport is an HTTP RoundTripper that adds X-Tenant-ID from context.
// Exported so evaluator factories can use it for tenant propagation.
type TenantTransport struct {
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *TenantTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if tenantID := TenantFromContext(req.Context()); tenantID != "" {
		req2 := req.Clone(req.Context())
		req2.Header.Set("X-Tenant-ID", tenantID)
		req = req2
	}
	if t.Base != nil {
		return t.Base.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
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

// TrustInfo contains trust evaluation results.
type TrustInfo struct {
	Trusted      bool     `json:"trusted"`
	Framework    string   `json:"framework,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Certificates []string `json:"certificates,omitempty"`
}

// EvaluatorFactory creates a TrustEvaluator for a given PDP endpoint.
// It receives the endpoint URL and timeout; the implementation is responsible
// for configuring HTTP clients, transport (e.g., tenant header propagation), etc.
type EvaluatorFactory func(endpoint string, timeout time.Duration) (TrustEvaluator, error)

// Service provides trust evaluation for credential flows.
// All trust evaluation is delegated to a remote trust endpoint (AuthZEN PDP).
// Per ADR-010, no local trust evaluation is performed to avoid false positives.
//
// Service supports independent configuration for issuer and verifier flows,
// with per-flow PDP URLs and the ability to disable trust evaluation per flow.
// The same Service instance is used by both engine and HTTP service layers.
type Service struct {
	cfg              *config.Config
	logger           *zap.Logger
	evaluatorFactory EvaluatorFactory

	// Evaluator cache by endpoint URL
	evaluators   map[string]TrustEvaluator
	evaluatorsMu sync.RWMutex
}

// NewService creates a new trust service with the given evaluator factory.
// The factory is called on demand to create evaluators for PDP endpoints.
func NewService(cfg *config.Config, logger *zap.Logger, factory EvaluatorFactory) *Service {
	return &Service{
		cfg:              cfg,
		logger:           logger.Named("trust"),
		evaluatorFactory: factory,
		evaluators:       make(map[string]TrustEvaluator),
	}
}

// GetEvaluator returns a TrustEvaluator for the given endpoint.
// Returns nil if endpoint is empty (operating in "allow all" mode).
// Evaluators are cached by endpoint URL for reuse.
func (s *Service) GetEvaluator(endpoint string) (TrustEvaluator, error) {
	if endpoint == "" {
		return nil, nil
	}

	// Check cache
	s.evaluatorsMu.RLock()
	eval, ok := s.evaluators[endpoint]
	s.evaluatorsMu.RUnlock()
	if ok {
		return eval, nil
	}

	// Create new evaluator
	s.evaluatorsMu.Lock()
	defer s.evaluatorsMu.Unlock()

	// Double-check after acquiring write lock
	if eval, ok := s.evaluators[endpoint]; ok {
		return eval, nil
	}

	timeout := time.Duration(s.cfg.Trust.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	eval, err := s.evaluatorFactory(endpoint, timeout)
	if err != nil {
		return nil, err
	}

	s.evaluators[endpoint] = eval
	s.logger.Debug("Created trust evaluator", zap.String("endpoint", endpoint))
	return eval, nil
}

// resolveIssuerEndpoint determines the effective PDP endpoint for an issuer evaluation.
// Priority: session-level override > per-flow config > global config.
func (s *Service) resolveIssuerEndpoint(sessionEndpoint string) string {
	if sessionEndpoint != "" {
		return sessionEndpoint
	}
	return s.cfg.Trust.GetIssuerPDPURL()
}

// resolveVerifierEndpoint determines the effective PDP endpoint for a verifier evaluation.
// Priority: session-level override > per-flow config > global config.
func (s *Service) resolveVerifierEndpoint(sessionEndpoint string) string {
	if sessionEndpoint != "" {
		return sessionEndpoint
	}
	return s.cfg.Trust.GetVerifierPDPURL()
}

// EvaluateIssuer evaluates trust for a credential issuer via the trust endpoint.
//
// The trustEndpoint parameter allows session-level overrides (e.g., from JWT claims).
// If empty, the per-flow issuer PDP URL is used; if that's empty, the global PDP URL.
// If no PDP URL is resolved, returns "allow all" (trusted=true).
//
// If keyMaterial is provided, validates the subject-to-key binding.
// If keyMaterial is nil, performs resolution-only (only works for DIDs).
func (s *Service) EvaluateIssuer(ctx context.Context, issuerID string, trustEndpoint string, keyMaterial *KeyMaterial) (*TrustInfo, error) {
	endpoint := s.resolveIssuerEndpoint(trustEndpoint)
	return s.evaluate(ctx, issuerID, endpoint, RoleCredentialIssuer, keyMaterial, "issuer")
}

// EvaluateVerifier evaluates trust for a credential verifier via the trust endpoint.
//
// The trustEndpoint parameter allows session-level overrides (e.g., from JWT claims).
// If empty, the per-flow verifier PDP URL is used; if that's empty, the global PDP URL.
// If no PDP URL is resolved, returns "allow all" (trusted=true).
//
// If keyMaterial is provided, validates the subject-to-key binding.
// If keyMaterial is nil, performs resolution-only (only works for DIDs).
func (s *Service) EvaluateVerifier(ctx context.Context, verifierID string, trustEndpoint string, keyMaterial *KeyMaterial) (*TrustInfo, error) {
	endpoint := s.resolveVerifierEndpoint(trustEndpoint)
	return s.evaluate(ctx, verifierID, endpoint, RoleCredentialVerifier, keyMaterial, "verifier")
}

// evaluate is the shared implementation for both issuer and verifier trust evaluation.
func (s *Service) evaluate(ctx context.Context, subjectID string, endpoint string, role Role, keyMaterial *KeyMaterial, logLabel string) (*TrustInfo, error) {
	eval, err := s.GetEvaluator(endpoint)
	if err != nil {
		return nil, err
	}
	if eval == nil {
		return &TrustInfo{
			Trusted:   true,
			Framework: "none",
			Reason:    "Trust evaluation not configured",
		}, nil
	}

	// Create evaluation request
	req := &EvaluationRequest{
		Subject: Subject{
			Type: SubjectTypeKey,
			ID:   subjectID,
		},
	}
	req.SubjectID = subjectID
	req.Role = role

	// Set key material if provided
	if keyMaterial != nil {
		switch keyMaterial.Type {
		case "x5c":
			req.KeyType = KeyTypeX5C
			req.Resource = Resource{
				Type: ResourceTypeX5C,
				ID:   subjectID,
				Key:  keyMaterial.X5C,
			}
			req.Key = keyMaterial.X5C
			s.logger.Debug("Trust evaluation with x5c",
				zap.String(logLabel, subjectID),
				zap.Int("cert_count", len(keyMaterial.X5C)))
		case "jwk":
			req.KeyType = KeyTypeJWK
			req.Resource = Resource{
				Type: ResourceTypeJWK,
				ID:   subjectID,
				Key:  keyMaterial.JWK,
			}
			req.Key = keyMaterial.JWK
			s.logger.Debug("Trust evaluation with JWK",
				zap.String(logLabel, subjectID))
		}
	} else {
		s.logger.Debug("Trust evaluation resolution-only",
			zap.String(logLabel, subjectID))
	}

	// Delegate evaluation to the trust endpoint
	resp, err := eval.Evaluate(ctx, req)
	if err != nil {
		s.logger.Warn("Trust evaluation error",
			zap.String(logLabel, subjectID),
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

// IsIssuerTrustEnabled returns whether trust evaluation is enabled for issuer flows
// based on the current configuration.
func (s *Service) IsIssuerTrustEnabled() bool {
	return s.cfg.Trust.IsIssuerTrustEnabled()
}

// IsVerifierTrustEnabled returns whether trust evaluation is enabled for verifier flows
// based on the current configuration.
func (s *Service) IsVerifierTrustEnabled() bool {
	return s.cfg.Trust.IsVerifierTrustEnabled()
}
