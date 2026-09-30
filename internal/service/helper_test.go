package service

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewHelperService(t *testing.T) {
	logger := zap.NewNop()

	svc := NewHelperService(logger, config.HTTPClientConfig{})

	if svc == nil {
		t.Fatal("expected helper service to not be nil")
	}
}

func TestHelperService_GetCertificateChain_InvalidURL(t *testing.T) {
	logger := zap.NewNop()
	svc := NewHelperService(logger, config.HTTPClientConfig{})
	ctx := context.Background()

	_, err := svc.GetCertificateChain(ctx, "://invalid-url")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestHelperService_GetCertificateChain_HTTPScheme(t *testing.T) {
	logger := zap.NewNop()
	svc := NewHelperService(logger, config.HTTPClientConfig{})
	ctx := context.Background()

	_, err := svc.GetCertificateChain(ctx, "http://example.com")
	if err == nil {
		t.Error("expected error for HTTP scheme (not HTTPS)")
	}
}

func TestHelperService_GetCertificateChain_InvalidHost(t *testing.T) {
	logger := zap.NewNop()
	svc := NewHelperService(logger, config.HTTPClientConfig{})
	ctx := context.Background()

	// Use a hostname that won't resolve
	_, err := svc.GetCertificateChain(ctx, "https://invalid-host-that-does-not-exist.example.invalid:443")
	if err == nil {
		t.Error("expected error for invalid host")
	}
}

// TestHelperService_GetCertificateChain_BlocksPrivateAddresses is a
// regression test for a blind in-cluster SSRF: GetCertificateChain used to
// dial any caller-supplied HTTPS URL with a raw net.Dialer, with no address
// policy at all - unlike every other outbound fetch in this backend, which
// goes through config.HTTPClientConfig.NewHTTPClient's SSRF-guarded
// transport. httptest.NewTLSServer listens on 127.0.0.1 (loopback), so this
// exercises the same "private/loopback address" rejection real in-cluster
// service addresses (e.g. a Kubernetes Service DNS name resolving to a
// ClusterIP) would hit.
func TestHelperService_GetCertificateChain_BlocksPrivateAddresses(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	logger := zap.NewNop()
	svc := NewHelperService(logger, config.HTTPClientConfig{})
	ctx := context.Background()

	_, err := svc.GetCertificateChain(ctx, server.URL)
	if err == nil {
		t.Fatal("expected the loopback address to be rejected by the SSRF guard, got no error")
	}
}

// TestHelperService_GetCertificateChain_AllowPrivateIPsStillWorks proves the
// SSRF-guard integration didn't break the endpoint's actual function: with
// AllowPrivateIPs explicitly set (the same opt-in NewHTTPClient honors for
// every other outbound fetch), GetCertificateChain must still perform a real
// TLS handshake and return the server's actual leaf certificate.
func TestHelperService_GetCertificateChain_AllowPrivateIPsStillWorks(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	logger := zap.NewNop()
	svc := NewHelperService(logger, config.HTTPClientConfig{AllowPrivateIPs: true})
	ctx := context.Background()

	resp, err := svc.GetCertificateChain(ctx, server.URL)
	if err != nil {
		t.Fatalf("expected a successful handshake with AllowPrivateIPs set, got: %v", err)
	}
	if len(resp.X5C) == 0 {
		t.Fatal("expected at least one certificate in the chain")
	}

	got := resp.X5C[0]
	want := base64.StdEncoding.EncodeToString(server.Certificate().Raw)
	if got != want {
		t.Errorf("returned leaf certificate does not match the test server's own certificate:\ngot:  %s\nwant: %s", got, want)
	}
}
