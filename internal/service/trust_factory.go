package service

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
)

// NewTrustService creates a new trust service with the default AuthZEN evaluator factory.
// This is a convenience wrapper for backward compatibility.
func NewTrustService(cfg *config.Config, logger *zap.Logger) *trust.Service {
	return trust.NewService(cfg, logger, newAuthZENEvaluatorFactory(cfg))
}

// newAuthZENEvaluatorFactory creates an AuthZEN evaluator factory that uses the
// application HTTP client configuration (proxy, TLS settings) and wraps it with
// tenant-aware transport for multi-tenant PDP routing.
func newAuthZENEvaluatorFactory(cfg *config.Config) trust.EvaluatorFactory {
	return func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		// Use NewPDPHTTPClient so the SSRF dial restriction is not applied to
		// operator-configured PDP URLs (which may use private/internal addresses).
		// This client also uses PDP-specific TLS settings and no proxy.
		httpClient, err := cfg.Trust.NewPDPHTTPClient(timeout)
		if err != nil {
			return nil, fmt.Errorf("trust: failed to create PDP HTTP client: %w", err)
		}
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
