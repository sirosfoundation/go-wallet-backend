// Package trustfactory provides factory functions for creating trust evaluatorspackage trustfactory

// from configuration.
package trustfactory

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust/x509eval"
)

// NewFromConfig creates a TrustEvaluator based on the configuration.
// Returns nil if trust evaluation is disabled (type="none").
func NewFromConfig(ctx context.Context, cfg *config.TrustConfig) (trust.TrustEvaluator, error) {
	if cfg == nil {
		return nil, nil
	}

	switch cfg.Type {
	case "", "none":
		return nil, nil

	case "x509":
		return newX509Evaluator(cfg.X509)

	case "authzen":
		return newAuthZENEvaluator(ctx, cfg.AuthZEN)

	case "composite":
		return newCompositeEvaluator(ctx, cfg)

	default:
		return nil, fmt.Errorf("unknown trust evaluator type: %s", cfg.Type)
	}
}

// newX509Evaluator creates an X.509 evaluator from config.
func newX509Evaluator(cfg config.X509TrustConfig) (*x509eval.Evaluator, error) {
	x509Cfg := &x509eval.Config{}

	// Load root certificates
	for _, path := range cfg.RootCertPaths {
		certPEM, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read root cert %s: %w", path, err)
		}
		x509Cfg.RootCertificates = append(x509Cfg.RootCertificates, certPEM)
	}

	// Load intermediate certificates
	for _, path := range cfg.IntermediateCertPaths {
		certPEM, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read intermediate cert %s: %w", path, err)
		}
		x509Cfg.IntermediateCertificates = append(x509Cfg.IntermediateCertificates, certPEM)
	}

	return x509eval.NewEvaluator(x509Cfg)
}

// newAuthZENEvaluator creates an AuthZEN evaluator from config.
func newAuthZENEvaluator(ctx context.Context, cfg config.AuthZENConfig) (*authzen.Evaluator, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("authzen.base_url is required")
	}

	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	if cfg.UseDiscovery {
		return authzen.NewEvaluatorWithDiscovery(ctx, cfg.BaseURL, timeout)
	}

	return authzen.NewEvaluator(&authzen.Config{
		BaseURL: cfg.BaseURL,
		Timeout: timeout,
	})
}

// newCompositeEvaluator creates an EvaluatorManager with multiple evaluators.
func newCompositeEvaluator(ctx context.Context, cfg *config.TrustConfig) (*trust.EvaluatorManager, error) {
	manager := trust.NewEvaluatorManager()

	// Add X.509 evaluator if configured
	if len(cfg.X509.RootCertPaths) > 0 {
		x509Eval, err := newX509Evaluator(cfg.X509)
		if err != nil {
			return nil, fmt.Errorf("failed to create x509 evaluator: %w", err)
		}
		manager.AddEvaluator(x509Eval)
	}

	// Add AuthZEN evaluator if configured
	if cfg.AuthZEN.BaseURL != "" {
		authzenEval, err := newAuthZENEvaluator(ctx, cfg.AuthZEN)
		if err != nil {
			return nil, fmt.Errorf("failed to create authzen evaluator: %w", err)
		}
		manager.AddEvaluator(authzenEval)
	}

	return manager, nil
}
