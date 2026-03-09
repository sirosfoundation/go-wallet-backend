// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
)

// Type aliases for backward compatibility.
// The actual trust evaluation implementation lives in pkg/trust.Service.
type (
	// TrustService provides trust evaluation for engine flows.
	// Deprecated: Use trust.Service directly when writing new code.
	TrustService = trust.Service

	// KeyMaterial represents cryptographic key material for trust evaluation.
	// Deprecated: Use trust.KeyMaterial directly when writing new code.
	KeyMaterial = trust.KeyMaterial
)

// NewTrustService creates a new trust service with the default AuthZEN evaluator factory.
// This is a convenience wrapper for backward compatibility.
func NewTrustService(cfg *config.Config, logger *zap.Logger) *TrustService {
	return trust.NewService(cfg, logger, newAuthZENEvaluatorFactory(cfg))
}

// newAuthZENEvaluatorFactory creates an AuthZEN evaluator factory that uses the
// application HTTP client configuration (proxy, TLS settings) and wraps it with
// tenant-aware transport for multi-tenant PDP routing.
func newAuthZENEvaluatorFactory(cfg *config.Config) trust.EvaluatorFactory {
	return func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		httpClient := cfg.HTTPClient.NewHTTPClient(timeout)
		// Wrap the transport with TenantTransport for multi-tenant support
		httpClient.Transport = &trust.TenantTransport{
			Base: httpClient.Transport,
		}

		return authzen.NewEvaluatorWithHTTPClient(&authzen.Config{
			BaseURL: endpoint,
			Timeout: timeout,
		}, httpClient)
	}
}
