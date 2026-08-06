package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/authz"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
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
func (b *memoryBackend) WalletInstances() storage.WalletInstanceStore {
	return b.store.WalletInstances()
}
func (b *memoryBackend) Ping(ctx context.Context) error { return b.store.Ping(ctx) }
func (b *memoryBackend) Close() error                   { return b.store.Close() }

func newTestMemoryBackend(t *testing.T) backend.Backend {
	t.Helper()

	store := memory.NewStore()
	return &memoryBackend{store: store}
}

func assertNoCacheHeaders(t *testing.T, headers http.Header) {
	t.Helper()

	if got := headers.Get("Cache-Control"); got != middleware.NoCacheControlValue {
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
func (m *mockBackend) Challenges() storage.ChallengeStore           { return nil }
func (m *mockBackend) Issuers() storage.IssuerStore                 { return nil }
func (m *mockBackend) Verifiers() storage.VerifierStore             { return nil }
func (m *mockBackend) Invites() storage.InviteStore                 { return nil }
func (m *mockBackend) WalletInstances() storage.WalletInstanceStore { return nil }

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

// TestBackendProvider_RegisterRoutes_RegistersJWKS is a regression test:
// co-hosted (BackendProvider) mode must expose /.well-known/jwks.json when a
// wallet-provider signing key is configured, so relying parties resolving
// trust via an iss-based WIA (WalletProvider.WIA.Mode == config.WIAModeIETF) can fetch it.
func TestBackendProvider_RegisterRoutes_RegistersJWKS(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writeTestECKeyAndCert(t, dir, "wallet-provider")

	logger := zap.NewNop()
	cfg := minimalTestConfig()
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	store := newTestMemoryBackend(t)

	authProvider := NewAuthProvider(cfg, store, logger, nil)
	storageProvider := NewStorageProvider(cfg, store, logger, nil)

	provider := &BackendProvider{
		auth:    authProvider,
		storage: storageProvider,
		store:   store,
		cfg:     cfg,
		logger:  logger,
	}

	router := gin.New()
	provider.RegisterRoutes(router)

	if !hasRoute(router.Routes(), http.MethodGet, "/.well-known/jwks.json") {
		t.Error("expected GET /.well-known/jwks.json to be registered when a wallet-provider signing key is configured")
	}
}

// TestBackendProvider_RegisterRoutes_NoJWKSWithoutSigningKey documents the
// no-op counterpart: without a configured wallet-provider signing key, the
// route must not be registered at all.
func TestBackendProvider_RegisterRoutes_NoJWKSWithoutSigningKey(t *testing.T) {
	logger := zap.NewNop()
	cfg := minimalTestConfig()
	store := newTestMemoryBackend(t)

	authProvider := NewAuthProvider(cfg, store, logger, nil)
	storageProvider := NewStorageProvider(cfg, store, logger, nil)

	provider := &BackendProvider{
		auth:    authProvider,
		storage: storageProvider,
		store:   store,
		cfg:     cfg,
		logger:  logger,
	}

	router := gin.New()
	provider.RegisterRoutes(router)

	if hasRoute(router.Routes(), http.MethodGet, "/.well-known/jwks.json") {
		t.Error("expected /.well-known/jwks.json NOT to be registered without a wallet-provider signing key")
	}
}

// =============================================================================
// RequireAudience wiring tests: confirm the anonymous ("wallet-registry")
// audience restriction added in providers.go actually takes effect end to
// end, not just that the middleware function itself works in isolation
// (that's covered separately in pkg/middleware).
// =============================================================================

// setupServerTokenValidatorTest starts a local JWKS server and a go-tokenauth
// validator pointed at it, mirroring pkg/middleware's setupTokenAuthTest.
func setupServerTokenValidatorTest(t *testing.T) (*tokenvalidator.Validator, *ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := gojose.JSONWebKey{Key: &key.PublicKey, KeyID: "test-key", Algorithm: string(gojose.ES256)}
	jwks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	v := tokenvalidator.New(tokenvalidator.Config{
		JWKSURL: srv.URL,
		Issuer:  "test-issuer",
	})
	v.Start(context.Background())
	t.Cleanup(v.Stop)

	// Poll until the validator has actually fetched the JWKS, rather than
	// sleeping a fixed duration (flaky under slow/contended CI runners).
	probe := signServerToken(t, key, "test-issuer", claims.AccessTokenClaims{})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := v.Validate(context.Background(), probe); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("validator did not fetch JWKS in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	return v, key, "test-issuer"
}

func signServerToken(t *testing.T, key *ecdsa.PrivateKey, issuer string, cl claims.AccessTokenClaims) string {
	t.Helper()

	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.ES256, Key: key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	cl.Claims = jwt.Claims{
		Issuer:    issuer,
		Subject:   cl.Claims.Subject,
		Audience:  cl.Claims.Audience,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	raw, err := jwt.Signed(signer).Claims(cl).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// newTestBackendProviderWithValidator builds a BackendProvider with a real
// go-tokenauth validator and a seeded "default" tenant, wired the same way
// NewBackendProvider wires it when cfg.AS.Enabled is true - so RequireAudience
// gets added to the AuthZEN proxy routes exactly like it does in production.
func newTestBackendProviderWithValidator(t *testing.T, v *tokenvalidator.Validator) *BackendProvider {
	t.Helper()

	// memory.NewStore() pre-seeds an enabled "default" tenant.
	store := newTestMemoryBackend(t)

	logger := zap.NewNop()
	cfg := minimalTestConfig()

	authProvider := NewAuthProvider(cfg, store, logger, nil)
	authProvider.tokenValidator = v
	storageProvider := NewStorageProvider(cfg, store, logger, nil)
	storageProvider.tokenValidator = v

	return &BackendProvider{
		auth:           authProvider,
		storage:        storageProvider,
		store:          store,
		cfg:            cfg,
		authzenHandler: newTestAuthZENHandler(cfg, logger),
		tokenValidator: v,
		logger:         logger,
	}
}

func TestBackendProvider_RequireAudience_AuthZENProxy_AllowsWalletRegistry(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	provider := newTestBackendProviderWithValidator(t, v)

	token := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Audience: jwt.Audience{"wallet-registry"}},
		TenantID: string(domain.DefaultTenantID),
		TAC:      "r",
		ACR:      "urn:siros:acr:passkey",
	})

	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Fatalf("expected a wallet-registry-audience token to pass RequireAudience, got %d: %s", w.Code, w.Body.String())
	}
	if w.Code == http.StatusNotFound {
		t.Fatalf("route not registered - test would false-pass on a routing regression")
	}
}

func TestBackendProvider_RequireAudience_AuthZENProxy_RejectsOtherAudience(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	provider := newTestBackendProviderWithValidator(t, v)

	token := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Audience: jwt.Audience{"some-other-audience"}},
		TenantID: string(domain.DefaultTenantID),
		TAC:      "r",
		ACR:      "urn:siros:acr:passkey",
	})

	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a token whose audience is neither wallet-registry nor wallet-backend, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthProvider_RequireAudience_RejectsWalletRegistryOnlyToken(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	provider := newTestBackendProviderWithValidator(t, v)

	// A wallet-registry-only (anonymous) token must not be usable on general
	// user-facing routes such as /issuer/all - only on the narrow-purpose
	// routes it's actually scoped to (AuthZEN proxy, engine transport).
	token := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Audience: jwt.Audience{"wallet-registry"}},
		TenantID: string(domain.DefaultTenantID),
		TAC:      "r",
		ACR:      "urn:siros:acr:passkey",
	})

	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuer/all", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a wallet-registry-only token on a general route, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthProvider_RequireAudience_AllowsWalletBackendToken(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	provider := newTestBackendProviderWithValidator(t, v)

	token := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-123", Audience: jwt.Audience{"wallet-backend"}},
		TenantID: string(domain.DefaultTenantID),
		TAC:      "rwl",
		ACR:      "urn:siros:acr:passkey",
	})

	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuer/all", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Fatalf("expected a wallet-backend-audience token to pass RequireAudience, got %d: %s", w.Code, w.Body.String())
	}
	if w.Code == http.StatusNotFound {
		t.Fatalf("route not registered - test would false-pass on a routing regression")
	}
}

// =============================================================================
// requireTACIfEnforced / route-level TAC enforcement tests
// =============================================================================

func TestRequireTACIfEnforced_NoOpWhenValidatorNil(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	// No tokenauth_result set at all - if this enforced anything, it would
	// 401, matching the legacy AuthMiddleware path having no TAC concept.
	r.Use(requireTACIfEnforced(nil, "w"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 200 {
		t.Fatalf("expected no-op (200) when tokenValidator is nil, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRequireTACIfEnforced_EnforcesWhenValidatorSet(t *testing.T) {
	v, _, _ := setupServerTokenValidatorTest(t)

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(func(c *gin.Context) {
		c.Set("tokenauth_result", &claims.Result{TAC: "rl"})
		c.Next()
	})
	r.Use(requireTACIfEnforced(v, "w"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (tac 'rl' lacks 'w') when tokenValidator is set, got %d: %s", w.Code, w.Body.String())
	}
}

// TestStorageProvider_RequireTAC_RejectsInsufficientPermission is an
// end-to-end proof that requireTACIfEnforced is actually wired into a real
// route, not just correct in isolation: a token with tac "rl" (read/list,
// no delete) must be rejected on DELETE /storage/vc/:id.
func TestStorageProvider_RequireTAC_RejectsInsufficientPermission(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	provider := newTestBackendProviderWithValidator(t, v)
	provider.cfg.Features.CredentialStorageEnabled = true

	token := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-123", Audience: jwt.Audience{"wallet-backend"}},
		TenantID: string(domain.DefaultTenantID),
		TAC:      "rl",
		ACR:      "urn:siros:acr:passkey",
	})

	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/storage/vc/some-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a tac=rl token on a delete route, got %d: %s", w.Code, w.Body.String())
	}
}

// TestStorageProvider_RequireTAC_AllowsSufficientPermission is the
// counterpart: a token with 'd' must reach the handler (not be blocked by
// requireTACIfEnforced). It still 404s here - DeleteCredential's own
// business logic correctly reports "no such credential" for an id that was
// never stored in this bare test fixture - so this asserts the response
// body is that handler-level not-found, not gin's router-level "no route
// matches" (which reuses the same status code but a different body).
func TestStorageProvider_RequireTAC_AllowsSufficientPermission(t *testing.T) {
	v, key, issuer := setupServerTokenValidatorTest(t)
	provider := newTestBackendProviderWithValidator(t, v)
	provider.cfg.Features.CredentialStorageEnabled = true

	token := signServerToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-123", Audience: jwt.Audience{"wallet-backend"}},
		TenantID: string(domain.DefaultTenantID),
		TAC:      "rwld",
		ACR:      "urn:siros:acr:passkey",
	})

	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/storage/vc/some-id", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Fatalf("expected a tac=rwld token to pass the TAC gate on a delete route, got 403: %s", w.Body.String())
	}
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "Credential not found") {
		t.Fatalf("expected DeleteCredential's own not-found response for a nonexistent id, got %d: %s", w.Code, w.Body.String())
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

// writeTestECKeyAndCert generates an EC P-256 key + self-signed cert and
// writes them as PEM files in dir, returning (keyPath, certPath).
func writeTestECKeyAndCert(t *testing.T, dir, prefix string) (string, string) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, prefix+"-key.pem")
	certPath := filepath.Join(dir, prefix+"-cert.pem")
	writePEM := func(path, blockType string, der []byte) {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
			t.Fatal(err)
		}
	}
	writePEM(keyPath, "EC PRIVATE KEY", keyDER)
	writePEM(certPath, "CERTIFICATE", certDER)
	return keyPath, certPath
}

// TestNewWalletProviderProvider_WiresTokenValidatorWhenASEnabled is a
// regression test: isolated wallet-provider deployments must accept
// AS-issued access tokens, the same as the co-hosted AuthProvider path.
// Before this fix, RegisterRoutes hardcoded the legacy HMAC-only
// AuthMiddleware regardless of cfg.AS.Enabled, so AS-issued tokens were
// always rejected in isolated mode.
func TestNewWalletProviderProvider_WiresTokenValidatorWhenASEnabled(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writeTestECKeyAndCert(t, dir, "wallet-provider")

	cfg := &config.Config{
		Storage: config.StorageConfig{Type: "memory"},
		Server:  config.ServerConfig{Host: "localhost", Port: 8080, RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:     config.JWTConfig{Secret: "test-secret-that-is-at-least-32-bytes!", Issuer: "test-issuer"},
		AS: config.ASConfig{
			Enabled:     true,
			ExternalURL: "https://as.example.com",
		},
	}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.WIA.RateLimit = config.AuthRateLimitConfig{Enabled: false}

	p, err := NewWalletProviderProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewWalletProviderProvider: %v", err)
	}
	defer func() { _ = p.Close() }()

	if p.tokenValidator == nil {
		t.Fatal("expected tokenValidator to be set when cfg.AS.Enabled is true")
	}
}

// TestNewWalletProviderProvider_NoTokenValidatorWhenASDisabled documents the
// counterpart: without AS enabled, isolated wallet-provider mode falls back
// to legacy HMAC auth, matching AuthProvider's default behavior.
func TestNewWalletProviderProvider_NoTokenValidatorWhenASDisabled(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writeTestECKeyAndCert(t, dir, "wallet-provider")

	cfg := &config.Config{
		Storage: config.StorageConfig{Type: "memory"},
		Server:  config.ServerConfig{Host: "localhost", Port: 8080, RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:     config.JWTConfig{Secret: "test-secret-that-is-at-least-32-bytes!", Issuer: "test-issuer"},
	}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.WIA.RateLimit = config.AuthRateLimitConfig{Enabled: false}

	p, err := NewWalletProviderProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewWalletProviderProvider: %v", err)
	}
	defer func() { _ = p.Close() }()

	if p.tokenValidator != nil {
		t.Fatal("expected tokenValidator to be nil when cfg.AS.Enabled is false")
	}
}

// TestWalletProviderProvider_RegisterRoutes_RegistersJWKS is a regression
// test: standalone wallet-provider mode (RoleWalletProvider without
// RoleBackend) must expose the same /.well-known/jwks.json as the co-hosted
// BackendProvider does, or relying parties resolving trust via an iss-based
// WIA (WalletProvider.WIA.Mode == config.WIAModeIETF) have nowhere to fetch the key when this
// role runs as its own standalone microservice.
func TestWalletProviderProvider_RegisterRoutes_RegistersJWKS(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writeTestECKeyAndCert(t, dir, "wallet-provider")

	cfg := &config.Config{
		Storage: config.StorageConfig{Type: "memory"},
		Server:  config.ServerConfig{Host: "localhost", Port: 8080, RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:     config.JWTConfig{Secret: "test-secret-that-is-at-least-32-bytes!", Issuer: "test-issuer"},
	}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.WIA.RateLimit = config.AuthRateLimitConfig{Enabled: false}

	p, err := NewWalletProviderProvider(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewWalletProviderProvider: %v", err)
	}
	defer func() { _ = p.Close() }()

	router := gin.New()
	p.RegisterRoutes(router)

	if !hasRoute(router.Routes(), http.MethodGet, "/.well-known/jwks.json") {
		t.Error("expected GET /.well-known/jwks.json to be registered in standalone wallet-provider mode")
	}
}

// Unlike BackendProvider (see TestBackendProvider_RegisterRoutes_NoJWKSWithoutSigningKey),
// there's no "standalone wallet-provider without a signing key" case to test
// here: NewWalletProviderProvider itself refuses to construct without a
// supported signing key (see its "wallet-provider signing keys not
// configured or not supported" error), so the no-op path in
// RegisterWalletProviderJWKSRoute is unreachable through this provider and
// is already covered directly at the service level (see
// TestRegisterWalletProviderJWKSRoute_NoOpWhenNoSigningKey).

// TestAuthProvider_WIARoutes_NotRegisteredWhenServiceNilDespiteEnabled is a
// regression test for a review finding: in co-hosted (AuthProvider) mode,
// WIA routes were registered purely based on cfg.WalletProvider.WIA.Enabled,
// even when no wallet-provider signing key is configured and
// services.WIA is therefore nil. That left dead routes that could only ever
// return 503 WIA_NOT_SUPPORTED. RegisterRoutes must also require the WIA
// service to have actually initialized.
func TestAuthProvider_WIARoutes_NotRegisteredWhenServiceNilDespiteEnabled(t *testing.T) {
	logger := zap.NewNop()
	cfg := minimalTestConfig()
	cfg.WalletProvider.WIA.Enabled = true // no PrivateKeyPath/CertificatePath set, so WIA can't initialize
	store := newTestMemoryBackend(t)

	provider := NewAuthProvider(cfg, store, logger, nil)
	defer func() { _ = provider.Close() }()
	if provider.services.WIA != nil {
		t.Fatal("expected services.WIA to be nil without wallet-provider signing keys configured")
	}

	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/wallet-provider/wia/challenge", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (route should not be registered when services.WIA is nil)", w.Code, http.StatusNotFound)
	}
}

// TestAuthProvider_WIARoutes_RegisteredWhenServiceAvailable is the positive
// counterpart: once a wallet-provider signing key is configured and WIA is
// enabled, the routes must still be registered (not accidentally gated out).
func TestAuthProvider_WIARoutes_RegisteredWhenServiceAvailable(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := writeTestECKeyAndCert(t, dir, "wallet-provider")

	logger := zap.NewNop()
	cfg := minimalTestConfig()
	cfg.WalletProvider.WIA.Enabled = true
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.WIA.RateLimit = config.AuthRateLimitConfig{Enabled: false}
	store := newTestMemoryBackend(t)

	provider := NewAuthProvider(cfg, store, logger, nil)
	defer func() { _ = provider.Close() }()
	if provider.services.WIA == nil {
		t.Fatal("expected services.WIA to be initialized with wallet-provider signing keys configured")
	}

	router := gin.New()
	provider.RegisterRoutes(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/wallet-provider/wia/challenge", nil)
	router.ServeHTTP(w, req)

	if w.Code == http.StatusNotFound {
		t.Fatal("expected /wallet-provider/wia/challenge to be registered when services.WIA is available")
	}
}

func TestWIACallerIdentifier(t *testing.T) {
	newCtx := func(setup func(*gin.Context)) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		if setup != nil {
			setup(c)
		}
		return c
	}

	t.Run("prefers user_id", func(t *testing.T) {
		c := newCtx(func(c *gin.Context) {
			c.Set("user_id", "user-123")
			c.Set("tenant_id", "acme")
		})
		if got := wiaCallerIdentifier(c); got != "user-123" {
			t.Errorf("wiaCallerIdentifier() = %q, want user-123", got)
		}
	})

	t.Run("falls back to tenant_id", func(t *testing.T) {
		c := newCtx(func(c *gin.Context) {
			c.Set("tenant_id", "acme")
		})
		if got := wiaCallerIdentifier(c); got != "acme" {
			t.Errorf("wiaCallerIdentifier() = %q, want acme", got)
		}
	})

	t.Run("falls back to empty (anonymous bucket)", func(t *testing.T) {
		c := newCtx(nil)
		if got := wiaCallerIdentifier(c); got != "" {
			t.Errorf("wiaCallerIdentifier() = %q, want empty string", got)
		}
	})
}

// TestWIARateLimiter_TripsAfterMaxAttempts is a regression test for the missing
// per-caller rate limit on the WIA challenge endpoint: without it, a single
// caller could exhaust the shared in-memory challenge capacity and deny
// service to every other tenant/user. This exercises the exact identifier
// extractor + AuthRateLimiter wiring used by AuthProvider/WalletProviderProvider,
// without needing a full JWT-authenticated HTTP round trip.
func TestWIARateLimiter_TripsAfterMaxAttempts(t *testing.T) {
	cfg := config.AuthRateLimitConfig{Enabled: true, MaxAttempts: 3, WindowSeconds: 60, LockoutSeconds: 60}
	rl := middleware.NewAuthRateLimiter(cfg, zap.NewNop())

	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", "user-abc") })
	router.POST("/wia/challenge", middleware.AuthRateLimitMiddlewareWithIdentifier(rl, wiaCallerIdentifier), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	var lastCode int
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/wia/challenge", nil)
		router.ServeHTTP(w, req)
		lastCode = w.Code
	}

	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after exceeding max_attempts, status = %d, want %d", lastCode, http.StatusTooManyRequests)
	}

	// A different caller must not be affected by the first caller's lockout.
	router2 := gin.New()
	router2.Use(func(c *gin.Context) { c.Set("user_id", "user-xyz") })
	router2.POST("/wia/challenge", middleware.AuthRateLimitMiddlewareWithIdentifier(rl, wiaCallerIdentifier), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/wia/challenge", nil)
	router2.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("different caller: status = %d, want %d (must not share the exhausted caller's lockout)", w.Code, http.StatusOK)
	}
}
