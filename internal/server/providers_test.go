package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/authz"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// minimalTestConfig returns a config with the minimum fields needed for
// creating AuthProvider/StorageProvider in tests without network calls.
func minimalTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret-key",
			ExpiryHours: 24,
			RefreshDays: 7,
			Issuer:      "test",
		},
		HTTPClient: config.HTTPClientConfig{
			Timeout:         5,
			AllowPrivateIPs: true,
		},
		Security: config.SecurityConfig{
			TokenBlacklist: config.TokenBlacklistConfig{
				Enabled: false,
			},
			ChallengeCleanup: config.ChallengeCleanupConfig{
				Enabled: false,
			},
		},
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled:         true,
			PDPURL:          "https://pdp.example.com",
			Timeout:         30,
			AllowResolution: true,
		},
	}
}

// hasRoute checks whether the given method+path is registered in the router.
func hasRoute(routes gin.RoutesInfo, method, path string) bool {
	for _, r := range routes {
		if r.Method == method && r.Path == path {
			return true
		}
	}
	return false
}

type memoryBackend struct {
	store *memory.Store
}

func (b *memoryBackend) Users() storage.UserStore                 { return b.store.Users() }
func (b *memoryBackend) Tenants() storage.TenantStore             { return b.store.Tenants() }
func (b *memoryBackend) UserTenants() storage.UserTenantStore     { return b.store.UserTenants() }
func (b *memoryBackend) Credentials() storage.CredentialStore     { return b.store.Credentials() }
func (b *memoryBackend) Presentations() storage.PresentationStore { return b.store.Presentations() }
func (b *memoryBackend) Challenges() storage.ChallengeStore       { return b.store.Challenges() }
func (b *memoryBackend) Issuers() storage.IssuerStore             { return b.store.Issuers() }
func (b *memoryBackend) Verifiers() storage.VerifierStore         { return b.store.Verifiers() }
func (b *memoryBackend) Invites() storage.InviteStore             { return b.store.Invites() }
func (b *memoryBackend) Ping(ctx context.Context) error           { return b.store.Ping(ctx) }
func (b *memoryBackend) Close() error                             { return b.store.Close() }

func newTestMemoryBackend(t *testing.T) backend.Backend {
	t.Helper()

	store := memory.NewStore()
	if _, err := store.Tenants().GetByID(context.Background(), domain.DefaultTenantID); err != nil {
		if err := store.Tenants().Create(context.Background(), &domain.Tenant{
			ID:      domain.DefaultTenantID,
			Name:    "Default",
			Enabled: true,
		}); err != nil {
			t.Fatalf("create default tenant: %v", err)
		}
	}
	return &memoryBackend{store: store}
}

func assertNoCacheHeaders(t *testing.T, headers http.Header) {
	t.Helper()

	if got := headers.Get("Cache-Control"); got != "no-store, no-cache, must-revalidate" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := headers.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q", got)
	}
	if got := headers.Get("Expires"); got != "0" {
		t.Errorf("Expires = %q", got)
	}
}

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

// =============================================================================
// BackendProvider RegisterRoutes tests
// =============================================================================

// newTestAuthZENHandler creates a minimal AuthZENProxyHandler for route tests.
func newTestAuthZENHandler(cfg *config.Config, logger *zap.Logger) *api.AuthZENProxyHandler {
	return api.NewAuthZENProxyHandler(
		&cfg.AuthZENProxy,
		authz.NoOpAuthorizer{},
		nil,
		nil,
		nil,
		http.DefaultClient,
		http.DefaultClient,
		logger,
	)
}

func TestBackendProvider_RegisterRoutes_WithAuthZENHandler(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := minimalTestConfig()
	store := &mockBackend{healthy: true}

	authProvider := NewAuthProvider(cfg, store, logger, nil)
	storageProvider := NewStorageProvider(cfg, store, logger, nil)
	authzenHandler := newTestAuthZENHandler(cfg, logger)

	provider := &BackendProvider{
		auth:           authProvider,
		storage:        storageProvider,
		store:          store,
		cfg:            cfg,
		authzenHandler: authzenHandler,
		logger:         logger,
	}

	router := gin.New()
	provider.RegisterRoutes(router)

	routes := router.Routes()
	if !hasRoute(routes, http.MethodPost, "/v1/evaluate") {
		t.Error("expected POST /v1/evaluate to be registered when authzenHandler is set")
	}
	if !hasRoute(routes, http.MethodPost, "/v1/resolve") {
		t.Error("expected POST /v1/resolve to be registered when authzenHandler is set")
	}
}

func TestBackendProvider_RegisterRoutes_WithoutAuthZENHandler(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cfg := minimalTestConfig()
	store := &mockBackend{healthy: true}

	authProvider := NewAuthProvider(cfg, store, logger, nil)
	storageProvider := NewStorageProvider(cfg, store, logger, nil)

	provider := &BackendProvider{
		auth:           authProvider,
		storage:        storageProvider,
		store:          store,
		cfg:            cfg,
		authzenHandler: nil, // no handler → routes must NOT be registered
		logger:         logger,
	}

	router := gin.New()
	provider.RegisterRoutes(router)

	routes := router.Routes()
	if hasRoute(routes, http.MethodPost, "/v1/evaluate") {
		t.Error("expected POST /v1/evaluate NOT to be registered when authzenHandler is nil")
	}
	if hasRoute(routes, http.MethodPost, "/v1/resolve") {
		t.Error("expected POST /v1/resolve NOT to be registered when authzenHandler is nil")
	}
}

func TestAuthProvider_RegisterRoutes_NoCacheCoverage(t *testing.T) {
	logger := zap.NewNop()
	cfg := minimalTestConfig()
	store := newTestMemoryBackend(t)

	provider := NewAuthProvider(cfg, store, logger, nil)
	router := gin.New()
	provider.RegisterRoutes(router)

	t.Run("login route", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/user/login-webauthn-begin", nil)
		router.ServeHTTP(w, req)

		if w.Code == http.StatusNotFound {
			t.Fatal("expected login route to be registered")
		}
		assertNoCacheHeaders(t, w.Header())
	})

	t.Run("session route", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/user/session/account-info", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
		assertNoCacheHeaders(t, w.Header())
	})

	t.Run("public tenant config route", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/tenant/default/config", nil)
		router.ServeHTTP(w, req)

		if w.Code == http.StatusNotFound {
			t.Fatal("expected tenant config route to be registered")
		}
		if got := w.Header().Get("Cache-Control"); got != "" {
			t.Fatalf("Cache-Control = %q, want empty for public route", got)
		}
	})
}

func TestStorageProvider_RegisterRoutes_NoCacheCoverage(t *testing.T) {
	logger := zap.NewNop()
	cfg := minimalTestConfig()
	cfg.Features.CredentialStorageEnabled = true
	store := newTestMemoryBackend(t)

	provider := NewStorageProvider(cfg, store, logger, nil)
	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/storage/vc", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	assertNoCacheHeaders(t, w.Header())
}
