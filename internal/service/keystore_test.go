package service

import (
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewKeystoreService(t *testing.T) {
	store := memory.NewStore()
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	svc := NewKeystoreService(store, cfg, logger)

	if svc == nil {
		t.Fatal("expected keystore service to not be nil")
	}
}

func TestKeystoreService_IsClientConnected(t *testing.T) {
	store := memory.NewStore()
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	svc := NewKeystoreService(store, cfg, logger)

	// No clients connected by default
	if svc.IsClientConnected("nonexistent-user") {
		t.Error("expected no clients to be connected")
	}
}

func TestKeystoreService_Close(t *testing.T) {
	store := memory.NewStore()
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	logger := zap.NewNop()

	svc := NewKeystoreService(store, cfg, logger)

	// Close should not panic
	svc.Close()
}
