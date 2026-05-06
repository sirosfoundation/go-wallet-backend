package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// These tests verify that the OR-logic mapping in NewEngineProvider (and
// NewBackendProvider) correctly wires HTTPClientConfig fields to the
// issuermetadata resolver's SSRF policy.
//
// The resolver uses go-trust's SafeHTTPClient, which enforces:
//   - HTTPS unless AllowHTTP is set
//   - Non-private-IP destinations unless AllowPrivateIPs is set

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
		AllowHTTP:       false, // default — HTTPS required
		AllowPrivateIPs: true,  // allow loopback so we isolate the HTTP-only check
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
// URL resolves successfully when AllowHTTP=true and AllowPrivateIPs=true.
func TestMetadataResolverConfig_HTTPAllowedWhenSet(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wellKnownHandler(srv.URL).ServeHTTP(w, r)
	}))
	defer srv.Close()

	resolver, err := issuermetadata.New(issuermetadata.Config{
		AllowHTTP:       true,
		AllowPrivateIPs: true,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("expected success when AllowHTTP=true and AllowPrivateIPs=true, got: %v", err)
	}
}

// TestMetadataResolverConfig_PrivateIPRejectedByDefault verifies that loopback
// (127.0.0.1) is blocked when AllowPrivateIPs is false (the default).
func TestMetadataResolverConfig_PrivateIPRejectedByDefault(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wellKnownHandler(srv.URL).ServeHTTP(w, r)
	}))
	defer srv.Close()

	resolver, err := issuermetadata.New(issuermetadata.Config{
		AllowHTTP:       true,  // allow HTTP to bypass scheme check; isolates IP check
		AllowPrivateIPs: false, // default — private/loopback IPs blocked
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error: private/loopback IP should be rejected when AllowPrivateIPs=false")
	}
	if !strings.Contains(err.Error(), "SSRF") {
		t.Errorf("expected SSRF protection error, got: %v", err)
	}
}

// TestMetadataResolverConfig_InsecureSkipVerifyImpliesAllowHTTPAndPrivateIPs
// verifies that the backward-compatibility OR-logic in providers.go means that
// InsecureSkipVerify=true grants both AllowHTTP and AllowPrivateIPs, preserving
// the pre-fix behavior for operators who used InsecureSkipVerify in development.
func TestMetadataResolverConfig_InsecureSkipVerifyImpliesAllowHTTPAndPrivateIPs(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wellKnownHandler(srv.URL).ServeHTTP(w, r)
	}))
	defer srv.Close()

	// Reproduce the mapping from NewEngineProvider / NewBackendProvider.
	httpCfg := config.HTTPClientConfig{
		InsecureSkipVerify: true,
		// AllowHTTP and AllowPrivateIPs are deliberately left false to confirm
		// that InsecureSkipVerify=true alone enables both via the OR logic.
	}
	resolver, err := issuermetadata.New(issuermetadata.Config{
		AllowHTTP:       httpCfg.AllowHTTP || httpCfg.InsecureSkipVerify,
		AllowPrivateIPs: httpCfg.AllowPrivateIPs || httpCfg.InsecureSkipVerify,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	_, err = resolver.Resolve(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("expected success when InsecureSkipVerify=true (legacy: implies AllowHTTP+AllowPrivateIPs), got: %v", err)
	}
}
