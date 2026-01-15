package service

import (
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewServices(t *testing.T) {
	store := memory.NewStore()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
	}
	logger := zap.NewNop()

	services := NewServices(store, cfg, logger)

	if services == nil {
		t.Fatal("expected services to not be nil")
	}

	// Verify all services are initialized
	if services.User == nil {
		t.Error("expected User service to be initialized")
	}
	if services.Tenant == nil {
		t.Error("expected Tenant service to be initialized")
	}
	if services.UserTenant == nil {
		t.Error("expected UserTenant service to be initialized")
	}
	if services.WebAuthn == nil {
		t.Error("expected WebAuthn service to be initialized")
	}
	if services.Credential == nil {
		t.Error("expected Credential service to be initialized")
	}
	if services.Presentation == nil {
		t.Error("expected Presentation service to be initialized")
	}
	if services.Issuer == nil {
		t.Error("expected Issuer service to be initialized")
	}
	if services.Verifier == nil {
		t.Error("expected Verifier service to be initialized")
	}
	if services.Keystore == nil {
		t.Error("expected Keystore service to be initialized")
	}
	if services.Proxy == nil {
		t.Error("expected Proxy service to be initialized")
	}
	if services.Helper == nil {
		t.Error("expected Helper service to be initialized")
	}
	if services.WalletProvider == nil {
		t.Error("expected WalletProvider service to be initialized")
	}
}

func TestNewServices_InvalidWebAuthnConfig(t *testing.T) {
	store := memory.NewStore()
	cfg := &config.Config{
		// Missing WebAuthn config (no RPID, etc.)
		JWT: config.JWTConfig{
			Secret:      "test-secret",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
	}
	logger := zap.NewNop()

	services := NewServices(store, cfg, logger)

	// Services should still be created even if WebAuthn fails
	if services == nil {
		t.Fatal("expected services to not be nil")
	}

	// WebAuthn may be nil if config is invalid
	// This is expected behavior - the service logs a warning and continues

	// Other services should still be available
	if services.User == nil {
		t.Error("expected User service to be initialized")
	}
}
