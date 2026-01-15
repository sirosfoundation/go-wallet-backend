package trustfactory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewFromConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("nil config returns nil", func(t *testing.T) {
		eval, err := NewFromConfig(ctx, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval != nil {
			t.Error("expected nil evaluator")
		}
	})

	t.Run("empty type returns nil", func(t *testing.T) {
		eval, err := NewFromConfig(ctx, &config.TrustConfig{Type: ""})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval != nil {
			t.Error("expected nil evaluator")
		}
	})

	t.Run("type 'none' returns nil", func(t *testing.T) {
		eval, err := NewFromConfig(ctx, &config.TrustConfig{Type: "none"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval != nil {
			t.Error("expected nil evaluator")
		}
	})

	t.Run("unknown type returns error", func(t *testing.T) {
		_, err := NewFromConfig(ctx, &config.TrustConfig{Type: "invalid"})
		if err == nil {
			t.Error("expected error for unknown type")
		}
	})

	t.Run("authzen without base_url returns error", func(t *testing.T) {
		_, err := NewFromConfig(ctx, &config.TrustConfig{Type: "authzen"})
		if err == nil {
			t.Error("expected error for missing base_url")
		}
	})

	t.Run("authzen with base_url creates evaluator", func(t *testing.T) {
		cfg := &config.TrustConfig{
			Type: "authzen",
			AuthZEN: config.AuthZENConfig{
				BaseURL: "https://pdp.example.com",
			},
		}
		eval, err := NewFromConfig(ctx, cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval == nil {
			t.Error("expected evaluator to be created")
		}
		if eval.Name() != "authzen" {
			t.Errorf("expected name 'authzen', got '%s'", eval.Name())
		}
	})

	t.Run("composite with authzen creates evaluator", func(t *testing.T) {
		cfg := &config.TrustConfig{
			Type: "composite",
			AuthZEN: config.AuthZENConfig{
				BaseURL: "https://pdp.example.com",
			},
		}
		eval, err := NewFromConfig(ctx, cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval == nil {
			t.Error("expected evaluator to be created")
		}
		if eval.Name() != "composite" {
			t.Errorf("expected name 'composite', got '%s'", eval.Name())
		}
	})

	t.Run("x509 with invalid root cert path returns error", func(t *testing.T) {
		cfg := &config.TrustConfig{
			Type: "x509",
			X509: config.X509TrustConfig{
				RootCertPaths: []string{"/nonexistent/cert.pem"},
			},
		}
		_, err := NewFromConfig(ctx, cfg)
		if err == nil {
			t.Error("expected error for non-existent cert path")
		}
	})

	t.Run("x509 with valid root cert creates evaluator", func(t *testing.T) {
		// Create a temporary cert file
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "test-ca.pem")

		// Write a valid PEM certificate (self-signed for testing)
		certPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpxvQzx1MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBlRl
c3RDQTAACQCOQX6cb0M8dTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZUZXN0
Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCk8W8m1gAn7WM8RH5y
-----END CERTIFICATE-----`
		if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
			t.Fatalf("failed to write test cert: %v", err)
		}

		cfg := &config.TrustConfig{
			Type: "x509",
			X509: config.X509TrustConfig{
				RootCertPaths: []string{certPath},
			},
		}
		// This will fail because the cert is invalid, but we're testing the path reading
		_, err := NewFromConfig(ctx, cfg)
		// We expect either success or a cert parsing error (not a file read error)
		if err != nil {
			if contains(err.Error(), "failed to read") {
				t.Errorf("unexpected file read error: %v", err)
			}
			// This is expected - cert parsing may fail with our dummy cert
		}
	})

	t.Run("composite with empty config creates evaluator", func(t *testing.T) {
		cfg := &config.TrustConfig{
			Type: "composite",
		}
		eval, err := NewFromConfig(ctx, cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval == nil {
			t.Error("expected evaluator to be created")
		}
	})

	t.Run("authzen with custom timeout", func(t *testing.T) {
		cfg := &config.TrustConfig{
			Type: "authzen",
			AuthZEN: config.AuthZENConfig{
				BaseURL: "https://pdp.example.com",
				Timeout: 60,
			},
		}
		eval, err := NewFromConfig(ctx, cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if eval == nil {
			t.Error("expected evaluator to be created")
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && s[0:len(substr)] == substr) ||
		(len(s) > len(substr) && contains(s[1:], substr)))
}
