package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// =============================================================================
// BackendProvider CheckReady tests
// =============================================================================

func TestBackendProvider_CheckReady_Healthy(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := &mockBackend{healthy: true}

	provider := &BackendProvider{
		store:  store,
		logger: logger,
	}

	err := provider.CheckReady(context.Background())
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestBackendProvider_CheckReady_Unhealthy(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := &mockBackend{healthy: false, err: errors.New("connection refused")}

	provider := &BackendProvider{
		store:  store,
		logger: logger,
	}

	err := provider.CheckReady(context.Background())
	if err == nil {
		t.Error("Expected error for unhealthy backend")
	}
}

func TestBackendProvider_CheckReady_NilStore(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	provider := &BackendProvider{
		store:  nil,
		logger: logger,
	}

	err := provider.CheckReady(context.Background())
	if err == nil {
		t.Error("Expected error for nil store")
	}
	if err.Error() != "storage not initialized" {
		t.Errorf("Expected 'storage not initialized' error, got %v", err)
	}
}

func TestBackendProvider_CheckReady_Timeout(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := &mockBackend{healthy: true, delay: 5 * time.Second}

	provider := &BackendProvider{
		store:  store,
		logger: logger,
	}

	// The provider has a 1s internal timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := provider.CheckReady(ctx)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

// =============================================================================
// EngineProvider CheckReady tests
// =============================================================================

func TestEngineProvider_CheckReady_Healthy(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{}
	manager := wsengine.NewManager(cfg, logger)

	provider := &EngineProvider{
		cfg:     cfg,
		logger:  logger,
		manager: manager,
	}

	err := provider.CheckReady(context.Background())
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestEngineProvider_CheckReady_NilManager(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	provider := &EngineProvider{
		cfg:     &config.Config{},
		logger:  logger,
		manager: nil,
	}

	err := provider.CheckReady(context.Background())
	if err == nil {
		t.Error("Expected error for nil manager")
	}
	if err.Error() != "engine manager not initialized" {
		t.Errorf("Expected 'engine manager not initialized' error, got %v", err)
	}
}

func TestEngineProvider_CheckReady_AfterClose(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := &config.Config{}
	manager := wsengine.NewManager(cfg, logger)

	provider := &EngineProvider{
		cfg:     cfg,
		logger:  logger,
		manager: manager,
	}

	// Close the manager
	provider.Close()

	// Should still be healthy as IsHealthy() checks sessions != nil
	// and closing just clears the map, doesn't nil it
	err := provider.CheckReady(context.Background())
	if err != nil {
		t.Errorf("After close, expected healthy (sessions map still exists), got %v", err)
	}
}

// =============================================================================
// RegistryProvider CheckReady tests
// =============================================================================

func TestRegistryProvider_CheckReady_Healthy(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := registry.DefaultConfig()
	store := registry.NewStore("")

	provider := &RegistryProvider{
		cfg:    cfg,
		logger: logger,
		store:  store,
	}

	err := provider.CheckReady(context.Background())
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestRegistryProvider_CheckReady_NilStore(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := registry.DefaultConfig()

	provider := &RegistryProvider{
		cfg:    cfg,
		logger: logger,
		store:  nil,
	}

	err := provider.CheckReady(context.Background())
	if err == nil {
		t.Error("Expected error for nil store")
	}
	if err.Error() != "registry store not initialized" {
		t.Errorf("Expected 'registry store not initialized' error, got %v", err)
	}
}

func TestRegistryProvider_CheckReady_EmptyStore(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := registry.DefaultConfig()
	cfg.DynamicCache.Enabled = false // Disable dynamic cache
	store := registry.NewStore("")   // Empty store

	provider := &RegistryProvider{
		cfg:    cfg,
		logger: logger,
		store:  store,
	}

	// With dynamic cache disabled and empty store, should still return ok
	err := provider.CheckReady(context.Background())
	if err != nil {
		t.Errorf("Expected no error for empty store with dynamic cache disabled, got %v", err)
	}
}

// =============================================================================
// Mock implementations
// =============================================================================

// mockBackend implements backend.Backend for testing
type mockBackend struct {
	healthy bool
	err     error
	delay   time.Duration
}

func (m *mockBackend) Ping(ctx context.Context) error {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if !m.healthy {
		return m.err
	}
	return nil
}

func (m *mockBackend) Close() error {
	return nil
}

// Implement the rest of the backend.Backend interface with nil returns
func (m *mockBackend) Users() storage.UserStore             { return nil }
func (m *mockBackend) Tenants() storage.TenantStore         { return nil }
func (m *mockBackend) UserTenants() storage.UserTenantStore { return nil }
func (m *mockBackend) Credentials() storage.CredentialStore { return nil }
func (m *mockBackend) Presentations() storage.PresentationStore {
	return nil
}
func (m *mockBackend) Challenges() storage.ChallengeStore { return nil }
func (m *mockBackend) Issuers() storage.IssuerStore       { return nil }
func (m *mockBackend) Verifiers() storage.VerifierStore   { return nil }
func (m *mockBackend) Invites() storage.InviteStore       { return nil }

// Verify mockBackend implements backend.Backend
var _ backend.Backend = (*mockBackend)(nil)
