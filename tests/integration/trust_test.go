// Package integration provides integration tests for go-wallet-backend.
package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-trust/pkg/registry/static"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
	"github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// TestTrustService_WithGoTrustTestServer tests TrustService integration
// with go-trust's testserver.
func TestTrustService_WithGoTrustTestServer(t *testing.T) {
	t.Run("AlwaysTrusted registry", func(t *testing.T) {
		// Start testserver with always-trusted registry
		reg := static.NewAlwaysTrustedRegistry("test-always-trusted")
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		// Create trust service pointing to testserver
		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		// Evaluate issuer trust (nil keyMaterial for DID resolution)
		ctx := context.Background()
		info, err := trustService.EvaluateIssuer(ctx, "did:example:issuer", "", nil)

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.True(t, info.Trusted, "AlwaysTrustedRegistry should return trusted=true")
		assert.Equal(t, "authzen", info.Framework)
	})

	t.Run("NeverTrusted registry", func(t *testing.T) {
		// Start testserver with never-trusted registry
		reg := static.NewNeverTrustedRegistry("test-never-trusted")
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		// Create trust service pointing to testserver
		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		// Evaluate issuer trust (nil keyMaterial for DID resolution)
		ctx := context.Background()
		info, err := trustService.EvaluateIssuer(ctx, "did:example:issuer", "", nil)

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.False(t, info.Trusted, "NeverTrustedRegistry should return trusted=false")
		assert.Equal(t, "authzen", info.Framework)
	})

	t.Run("No trust endpoint configured", func(t *testing.T) {
		// Create trust service without endpoint
		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: "", // No endpoint
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		// Evaluate - should return fail-closed (not trusted, no evaluation possible)
		ctx := context.Background()
		info, err := trustService.EvaluateIssuer(ctx, "did:example:issuer", "", nil)

		require.NoError(t, err)
		require.NotNil(t, info)
		// Fail-closed: no PDP configured = not trusted
		assert.False(t, info.Trusted)
		assert.Equal(t, "none", info.Framework)
		assert.Contains(t, info.Reason, "not configured")
	})
}

// TestTrustService_VerifierEvaluation tests verifier trust evaluation.
func TestTrustService_VerifierEvaluation(t *testing.T) {
	t.Run("Verifier trusted", func(t *testing.T) {
		// Start testserver with always-trusted registry
		reg := static.NewAlwaysTrustedRegistry("verifier-trusted")
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		ctx := context.Background()
		info, err := trustService.EvaluateVerifier(ctx, "https://verifier.example.com", "", nil)

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.True(t, info.Trusted)
	})

	t.Run("Verifier untrusted", func(t *testing.T) {
		// Start testserver with never-trusted registry
		reg := static.NewNeverTrustedRegistryWithConfig(static.NeverTrustedConfig{
			Name:   "verifier-deny",
			Reason: "verifier not in allowlist",
		})
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		ctx := context.Background()
		info, err := trustService.EvaluateVerifier(ctx, "https://untrusted-verifier.example.com", "", nil)

		require.NoError(t, err)
		require.NotNil(t, info)
		assert.False(t, info.Trusted)
	})
}

// TestTrustService_EndpointOverride tests per-tenant trust endpoint override.
func TestTrustService_EndpointOverride(t *testing.T) {
	// Start two testservers with different trust policies
	trustedReg := static.NewAlwaysTrustedRegistry("allow-all")
	trustedSrv := testserver.New(testserver.WithRegistry(trustedReg))
	defer trustedSrv.Close()

	deniedReg := static.NewNeverTrustedRegistry("deny-all")
	deniedSrv := testserver.New(testserver.WithRegistry(deniedReg))
	defer deniedSrv.Close()

	// Default endpoint allows everything
	cfg := &config.Config{
		Trust: config.TrustConfig{
			DefaultEndpoint: trustedSrv.URL(),
			Timeout:         10,
		},
	}
	logger, _ := zap.NewDevelopment()
	trustService := engine.NewTrustService(cfg, logger)

	ctx := context.Background()

	// Test with default endpoint (should be trusted)
	info, err := trustService.EvaluateIssuer(ctx, "did:example:issuer", "", nil)
	require.NoError(t, err)
	assert.True(t, info.Trusted, "Default endpoint should allow")

	// Test with override endpoint (should be denied)
	info, err = trustService.EvaluateIssuer(ctx, "did:example:issuer", deniedSrv.URL(), nil)
	require.NoError(t, err)
	assert.False(t, info.Trusted, "Override endpoint should deny")
}

// TestTrustService_EvaluatorCaching tests that evaluators are cached.
func TestTrustService_EvaluatorCaching(t *testing.T) {
	reg := static.NewAlwaysTrustedRegistry("cached")
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	cfg := &config.Config{
		Trust: config.TrustConfig{
			DefaultEndpoint: srv.URL(),
			Timeout:         10,
		},
	}
	logger, _ := zap.NewDevelopment()
	trustService := engine.NewTrustService(cfg, logger)

	// Get evaluator twice - should return same instance
	eval1, err := trustService.GetEvaluator(srv.URL())
	require.NoError(t, err)
	require.NotNil(t, eval1)

	eval2, err := trustService.GetEvaluator(srv.URL())
	require.NoError(t, err)
	require.NotNil(t, eval2)

	// Verify same instance (pointer equality)
	assert.Same(t, eval1, eval2, "Evaluators should be cached")
}

// TestTrustService_Timeout tests that timeout configuration is respected.
func TestTrustService_Timeout(t *testing.T) {
	// Use a standard registry - just verify that short timeout config doesn't break things
	reg := static.NewAlwaysTrustedRegistry("timeout-test")
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	cfg := &config.Config{
		Trust: config.TrustConfig{
			DefaultEndpoint: srv.URL(),
			Timeout:         1, // 1 second timeout
		},
	}
	logger, _ := zap.NewDevelopment()
	trustService := engine.NewTrustService(cfg, logger)

	ctx := context.Background()
	info, err := trustService.EvaluateIssuer(ctx, "did:example:test", "", nil)

	// Should succeed with valid server
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.True(t, info.Trusted)
}

// TestTrustService_ConcurrentRequests tests concurrent trust evaluation.
func TestTrustService_ConcurrentRequests(t *testing.T) {
	reg := static.NewAlwaysTrustedRegistry("concurrent")
	srv := testserver.New(testserver.WithRegistry(reg))
	defer srv.Close()

	cfg := &config.Config{
		Trust: config.TrustConfig{
			DefaultEndpoint: srv.URL(),
			Timeout:         10,
		},
	}
	logger, _ := zap.NewDevelopment()
	trustService := engine.NewTrustService(cfg, logger)

	ctx := context.Background()

	// Run concurrent requests
	const concurrency = 10
	results := make(chan *engine.TrustInfo, concurrency)
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			info, err := trustService.EvaluateIssuer(ctx, "did:example:concurrent-test", "", nil)
			if err != nil {
				errors <- err
				return
			}
			results <- info
		}(i)
	}

	// Collect results
	for i := 0; i < concurrency; i++ {
		select {
		case info := <-results:
			assert.True(t, info.Trusted)
		case err := <-errors:
			t.Errorf("Concurrent request failed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}
}

// TestTrustService_JWKKeyMaterial tests trust evaluation with JWK key material.
func TestTrustService_JWKKeyMaterial(t *testing.T) {
	t.Run("Single JWK trusted", func(t *testing.T) {
		reg := static.NewAlwaysTrustedRegistry("jwk-trusted")
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		ctx := context.Background()
		km := &engine.KeyMaterial{
			Type: "jwk",
			JWK: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
				"kid": "test-key-1",
			},
		}

		info, err := trustService.EvaluateIssuer(ctx, "https://issuer.example.com", "", km)
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.True(t, info.Trusted)
		assert.Equal(t, "authzen", info.Framework)
	})

	t.Run("JWKS wrapper trusted", func(t *testing.T) {
		reg := static.NewAlwaysTrustedRegistry("jwks-trusted")
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		ctx := context.Background()
		// JWKS object with keys array (as returned by fetchJWKS)
		km := &engine.KeyMaterial{
			Type: "jwk",
			JWK: map[string]interface{}{
				"keys": []interface{}{
					map[string]interface{}{
						"kty": "EC",
						"crv": "P-256",
						"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
						"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
						"kid": "key-1",
					},
				},
			},
		}

		info, err := trustService.EvaluateIssuer(ctx, "https://issuer.example.com", "", km)
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.True(t, info.Trusted)
	})

	t.Run("JWK untrusted", func(t *testing.T) {
		reg := static.NewNeverTrustedRegistry("jwk-untrusted")
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		ctx := context.Background()
		km := &engine.KeyMaterial{
			Type: "jwk",
			JWK: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
			},
		}

		info, err := trustService.EvaluateIssuer(ctx, "https://issuer.example.com", "", km)
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.False(t, info.Trusted)
	})

	t.Run("JWK with credential type", func(t *testing.T) {
		reg := static.NewAlwaysTrustedRegistry("jwk-cred-type")
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		ctx := context.Background()
		km := &engine.KeyMaterial{
			Type: "jwk",
			JWK: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
			},
			CredentialType: "urn:eu.europa.ec.eudi:pid:1",
		}

		info, err := trustService.EvaluateIssuer(ctx, "https://issuer.example.com", "", km)
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.True(t, info.Trusted)
	})

	t.Run("Verifier with JWK", func(t *testing.T) {
		reg := static.NewAlwaysTrustedRegistry("verifier-jwk")
		srv := testserver.New(testserver.WithRegistry(reg))
		defer srv.Close()

		cfg := &config.Config{
			Trust: config.TrustConfig{
				DefaultEndpoint: srv.URL(),
				Timeout:         10,
			},
		}
		logger, _ := zap.NewDevelopment()
		trustService := engine.NewTrustService(cfg, logger)

		ctx := context.Background()
		km := &engine.KeyMaterial{
			Type: "jwk",
			JWK: map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
				"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
			},
		}

		info, err := trustService.EvaluateVerifier(ctx, "https://verifier.example.com", "", km)
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.True(t, info.Trusted)
	})
}
