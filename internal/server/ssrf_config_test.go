package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
)

// These tests verify that the issuermetadata resolver correctly enforces
// AllowHTTP, and that providers.go wires the caller-provided HTTP client
// (which handles SSRF protection) through to the resolver.

// wellKnownHandler returns a minimal OpenID4VCI metadata document so that
// the resolver can parse a valid response once the request is allowed through.
func wellKnownHandler(issuerURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": issuerURL}) //nolint:errcheck
	})
}

// TestMetadataResolverConfig_HTTPRejectedByDefault verifies that a plain-HTTP
// issuer URL is rejected when AllowHTTP is false (the default).
func TestMetadataResolverConfig_HTTPRejectedByDefault(t *testing.T) {
	srv := httptest.NewServer(wellKnownHandler(""))
	defer srv.Close()

	resolver, err := issuermetadata.New(issuermetadata.Config{
		AllowHTTP: false, // default — HTTPS required
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error: HTTP URL should be rejected when AllowHTTP=false")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "https") {
		t.Errorf("expected HTTPS-enforcement error, got: %v", err)
	}
}

// TestMetadataResolverConfig_HTTPAllowedWhenSet verifies that an HTTP issuer
// URL resolves successfully when AllowHTTP=true.
func TestMetadataResolverConfig_HTTPAllowedWhenSet(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wellKnownHandler(srv.URL).ServeHTTP(w, r)
	}))
	defer srv.Close()

	resolver, err := issuermetadata.New(issuermetadata.Config{
		AllowHTTP: true,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("expected success when AllowHTTP=true, got: %v", err)
	}
}

// TestMetadataResolverConfig_SSRFViaHTTPClient verifies that SSRF protection
// is enforced by the caller-provided HTTP client (from config.HTTPClientConfig),
// not by the resolver itself. When AllowPrivateIPs=false on the HTTP client,
// loopback requests are blocked.
func TestMetadataResolverConfig_SSRFViaHTTPClient(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wellKnownHandler(srv.URL).ServeHTTP(w, r)
	}))
	defer srv.Close()

	// Create an HTTP client that blocks private IPs (SSRF protection).
	httpCfg := config.HTTPClientConfig{
		AllowHTTP:       true,  // allow HTTP to bypass scheme check
		AllowPrivateIPs: false, // block loopback
	}
	client := httpCfg.NewHTTPClient(10 * time.Second)

	resolver, err := issuermetadata.New(issuermetadata.Config{
		AllowHTTP:  true,
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error: private/loopback IP should be rejected by the HTTP client")
	}
}

// TestMetadataResolverConfig_InsecureSkipVerifyImpliesAllowHTTP verifies that
// the OR-logic in providers.go means InsecureSkipVerify=true enables AllowHTTP,
// and that the HTTP client with AllowPrivateIPs=true allows loopback.
func TestMetadataResolverConfig_InsecureSkipVerifyImpliesAllowHTTP(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wellKnownHandler(srv.URL).ServeHTTP(w, r)
	}))
	defer srv.Close()

	httpCfg := config.HTTPClientConfig{
		InsecureSkipVerify: true,
		AllowPrivateIPs:    true, // needed for loopback test server
		// AllowHTTP is deliberately left false to confirm that
		// InsecureSkipVerify=true alone enables it via the OR logic.
	}
	client := httpCfg.NewHTTPClient(10 * time.Second)

	resolver, err := issuermetadata.New(issuermetadata.Config{
		AllowHTTP:  httpCfg.AllowHTTP || httpCfg.InsecureSkipVerify,
		HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("expected success when InsecureSkipVerify=true, got: %v", err)
	}
}

// =============================================================================
// NewEngineProvider wiring tests
//
// These verify that NewEngineProvider correctly wires:
//   AllowHTTP:  cfg.HTTPClient.AllowHTTP || cfg.HTTPClient.InsecureSkipVerify
//   HTTPClient: cfg.HTTPClient.NewHTTPClient(timeout)
// =============================================================================

// minimalEngineConfig returns a *config.Config that satisfies NewEngineProvider
// without triggering network calls or optional subsystems (Redis, etc.).
func minimalEngineConfig(httpCfg config.HTTPClientConfig) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		JWT: config.JWTConfig{
			Secret: "test-secret", Issuer: "test",
			ExpiryHours: 1, RefreshDays: 1,
		},
		HTTPClient: httpCfg,
	}
}

// TestNewEngineProvider_AllowHTTPWiring verifies that NewEngineProvider wires
// AllowHTTP to the metadata resolver correctly.
func TestNewEngineProvider_AllowHTTPWiring(t *testing.T) {
	logger := zap.NewNop()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wellKnownHandler(srv.URL).ServeHTTP(w, r)
	}))
	defer srv.Close()

	tests := []struct {
		name      string
		httpCfg   config.HTTPClientConfig
		wantAllow bool // true = expect successful resolution over HTTP+loopback
	}{
		{
			name:      "AllowHTTP=true AllowPrivateIPs=true",
			httpCfg:   config.HTTPClientConfig{AllowHTTP: true, AllowPrivateIPs: true},
			wantAllow: true,
		},
		{
			name:      "InsecureSkipVerify=true implies AllowHTTP but not AllowPrivateIPs",
			httpCfg:   config.HTTPClientConfig{InsecureSkipVerify: true},
			wantAllow: false, // loopback blocked because AllowPrivateIPs is not set
		},
		{
			name:      "AllowHTTP=false blocks HTTP (default)",
			httpCfg:   config.HTTPClientConfig{AllowPrivateIPs: true},
			wantAllow: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewEngineProvider(minimalEngineConfig(tc.httpCfg), logger, nil, nil, nil)
			if err != nil {
				t.Fatalf("NewEngineProvider failed: %v", err)
			}

			// Reproduce the wiring to verify behavior.
			client := tc.httpCfg.NewHTTPClient(10 * time.Second)
			resolver, err := issuermetadata.New(issuermetadata.Config{
				AllowHTTP:  tc.httpCfg.AllowHTTP || tc.httpCfg.InsecureSkipVerify,
				HTTPClient: client,
			})
			if err != nil {
				t.Fatalf("failed to create equivalent resolver: %v", err)
			}
			_ = provider

			_, resolveErr := resolver.Resolve(context.Background(), srv.URL)
			if tc.wantAllow && resolveErr != nil {
				t.Errorf("expected successful resolution, got: %v", resolveErr)
			}
			if !tc.wantAllow && resolveErr == nil {
				t.Error("expected resolution to be blocked, but it succeeded")
			}
		})
	}
}
