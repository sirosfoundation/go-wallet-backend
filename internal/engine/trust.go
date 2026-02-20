// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
)

// TrustService provides trust evaluation for engine flows.
// It manages evaluators per trust endpoint with caching.
type TrustService struct {
	cfg    *config.Config
	logger *zap.Logger

	// Evaluator cache by endpoint URL
	evaluators   map[string]*authzen.Evaluator
	evaluatorsMu sync.RWMutex
}

// NewTrustService creates a new trust service.
func NewTrustService(cfg *config.Config, logger *zap.Logger) *TrustService {
	return &TrustService{
		cfg:        cfg,
		logger:     logger.Named("trust"),
		evaluators: make(map[string]*authzen.Evaluator),
	}
}

// GetEvaluator returns an evaluator for the given endpoint.
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

	eval, err := authzen.NewEvaluator(&authzen.Config{
		BaseURL: endpoint,
		Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	ts.evaluators[endpoint] = eval
	ts.logger.Debug("Created trust evaluator", zap.String("endpoint", endpoint))
	return eval, nil
}

// EvaluateIssuer evaluates trust for a credential issuer.
func (ts *TrustService) EvaluateIssuer(ctx context.Context, issuerID string, trustEndpoint string) (*TrustInfo, error) {
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
		Resource: trust.Resource{
			Type: trust.ResourceTypeJWK,
			ID:   issuerID,
		},
	}
	req.SubjectID = issuerID
	req.KeyType = trust.KeyTypeJWK
	req.Role = trust.RoleCredentialIssuer

	// Evaluate
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

// EvaluateVerifier evaluates trust for a credential verifier.
func (ts *TrustService) EvaluateVerifier(ctx context.Context, verifierID string, trustEndpoint string) (*TrustInfo, error) {
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
		Resource: trust.Resource{
			Type: trust.ResourceTypeJWK,
			ID:   verifierID,
		},
	}
	req.SubjectID = verifierID
	req.KeyType = trust.KeyTypeJWK
	req.Role = trust.RoleCredentialVerifier

	// Evaluate
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
