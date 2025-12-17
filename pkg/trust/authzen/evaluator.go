// Package authzen provides an AuthZEN-based trust evaluator using go-trust.
//
// This evaluator delegates trust decisions to an external AuthZEN PDP service
// (such as go-trust). It supports complex trust evaluation scenarios including
// ETSI TSL validation, OpenID Federation, and DID resolution.
package authzen

import (
	"context"
	"fmt"
	"sync"
	"time"

	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// Evaluator delegates trust evaluation to an AuthZEN PDP service.
type Evaluator struct {
	client       *authzenclient.Client
	mu           sync.RWMutex
	healthy      bool
	lastCheck    time.Time
	healthPeriod time.Duration
}

// Config holds configuration for the AuthZEN evaluator.
type Config struct {
	// BaseURL is the base URL of the AuthZEN PDP service.
	BaseURL string
	// Timeout is the HTTP request timeout (default 30s).
	Timeout time.Duration
	// HealthCheckPeriod is how often to check PDP health (default 1m).
	HealthCheckPeriod time.Duration
}

// NewEvaluator creates a new AuthZEN evaluator.
func NewEvaluator(cfg *Config) (*Evaluator, error) {
	if cfg == nil || cfg.BaseURL == "" {
		return nil, fmt.Errorf("BaseURL is required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	healthPeriod := cfg.HealthCheckPeriod
	if healthPeriod == 0 {
		healthPeriod = 1 * time.Minute
	}

	client := authzenclient.New(cfg.BaseURL, authzenclient.WithTimeout(timeout))

	return &Evaluator{
		client:       client,
		healthy:      true,
		healthPeriod: healthPeriod,
	}, nil
}

// NewEvaluatorWithDiscovery creates an evaluator using AuthZEN discovery.
func NewEvaluatorWithDiscovery(ctx context.Context, baseURL string, timeout time.Duration) (*Evaluator, error) {
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	client, err := authzenclient.Discover(ctx, baseURL, authzenclient.WithTimeout(timeout))
	if err != nil {
		return nil, fmt.Errorf("failed to discover AuthZEN PDP: %w", err)
	}

	return &Evaluator{
		client:       client,
		healthy:      true,
		healthPeriod: 1 * time.Minute,
	}, nil
}

// Name returns the evaluator name.
func (e *Evaluator) Name() string {
	return "authzen"
}

// SupportedResourceTypes returns the types this evaluator handles.
func (e *Evaluator) SupportedResourceTypes() []trust.ResourceType {
	return []trust.ResourceType{
		trust.ResourceTypeX5C,
		trust.ResourceTypeJWK,
	}
}

// Healthy returns whether the evaluator is operational.
func (e *Evaluator) Healthy() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthy
}

// SetHealthy sets the health status (useful for circuit breaker patterns).
func (e *Evaluator) SetHealthy(healthy bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.healthy = healthy
	e.lastCheck = time.Now()
}

// Evaluate performs trust evaluation via the AuthZEN PDP.
func (e *Evaluator) Evaluate(ctx context.Context, req *trust.EvaluationRequest) (*trust.EvaluationResponse, error) {
	// Convert to AuthZEN request format
	authzenReq, err := e.toAuthZENRequest(req)
	if err != nil {
		return &trust.EvaluationResponse{
			Decision: false,
			Reason:   fmt.Sprintf("failed to build AuthZEN request: %v", err),
		}, nil
	}

	// Call the PDP
	resp, err := e.client.Evaluate(ctx, authzenReq)
	if err != nil {
		// Mark as unhealthy on connection errors
		e.SetHealthy(false)
		return &trust.EvaluationResponse{
			Decision: false,
			Reason:   fmt.Sprintf("AuthZEN PDP error: %v", err),
		}, nil
	}

	// Mark as healthy on successful response
	e.SetHealthy(true)

	// Convert response
	return e.fromAuthZENResponse(resp), nil
}

// Resolve performs a resolution-only request (e.g., DID resolution).
func (e *Evaluator) Resolve(ctx context.Context, subjectID string) (*trust.EvaluationResponse, error) {
	resp, err := e.client.Resolve(ctx, subjectID)
	if err != nil {
		e.SetHealthy(false)
		return &trust.EvaluationResponse{
			Decision: false,
			Reason:   fmt.Sprintf("AuthZEN resolution error: %v", err),
		}, nil
	}

	e.SetHealthy(true)
	return e.fromAuthZENResponse(resp), nil
}

// EvaluateX5C is a convenience method for X.509 certificate chain evaluation.
func (e *Evaluator) EvaluateX5C(ctx context.Context, subjectID string, certChain []string, action string) (*trust.EvaluationResponse, error) {
	var actionPtr *gotrust.Action
	if action != "" {
		actionPtr = &gotrust.Action{Name: action}
	}

	resp, err := e.client.EvaluateX5C(ctx, subjectID, certChain, actionPtr)
	if err != nil {
		e.SetHealthy(false)
		return &trust.EvaluationResponse{
			Decision: false,
			Reason:   fmt.Sprintf("AuthZEN X5C evaluation error: %v", err),
		}, nil
	}

	e.SetHealthy(true)
	return e.fromAuthZENResponse(resp), nil
}

// toAuthZENRequest converts our request format to AuthZEN format.
func (e *Evaluator) toAuthZENRequest(req *trust.EvaluationRequest) (*gotrust.EvaluationRequest, error) {
	authzenReq := &gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   req.Subject.ID,
		},
		Resource: gotrust.Resource{
			Type: string(req.Resource.Type),
			ID:   req.Resource.ID,
		},
	}

	// Set resource key based on type
	switch req.Resource.Type {
	case trust.ResourceTypeX5C:
		keys, err := e.extractX5CKeys(req)
		if err != nil {
			return nil, err
		}
		authzenReq.Resource.Key = keys
	case trust.ResourceTypeJWK:
		authzenReq.Resource.Key = []interface{}{req.Resource.Key}
	}

	// Set action if specified
	if req.Action != nil && req.Action.Name != "" {
		authzenReq.Action = &gotrust.Action{Name: req.Action.Name}
	}

	// Copy context
	if req.Context != nil {
		authzenReq.Context = req.Context
	}

	return authzenReq, nil
}

// extractX5CKeys extracts certificate strings for AuthZEN.
func (e *Evaluator) extractX5CKeys(req *trust.EvaluationRequest) ([]interface{}, error) {
	switch key := req.Resource.Key.(type) {
	case []string:
		result := make([]interface{}, len(key))
		for i, s := range key {
			result[i] = s
		}
		return result, nil
	case []interface{}:
		return key, nil
	case nil:
		return nil, fmt.Errorf("no key material provided")
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// fromAuthZENResponse converts AuthZEN response to our format.
func (e *Evaluator) fromAuthZENResponse(resp *gotrust.EvaluationResponse) *trust.EvaluationResponse {
	result := &trust.EvaluationResponse{
		Decision: resp.Decision,
	}

	if resp.Context != nil {
		// Extract reason
		if resp.Context.Reason != nil {
			if errMsg, ok := resp.Context.Reason["error"].(string); ok {
				result.Reason = errMsg
			} else if msg, ok := resp.Context.Reason["message"].(string); ok {
				result.Reason = msg
			}
		}

		// Extract trust metadata
		if resp.Context.TrustMetadata != nil {
			result.TrustMetadata = resp.Context.TrustMetadata
		}
	}

	if result.Reason == "" && result.Decision {
		result.Reason = "trust evaluation successful"
	}

	return result
}
