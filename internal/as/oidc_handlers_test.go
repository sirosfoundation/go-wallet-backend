package as

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"go.uber.org/zap"
)

// mockStore implements storage.Store for OIDC tests.
type mockStore struct {
	tenants    *mockTenantStore
	challenges *mockChallengeStore
}

func (m *mockStore) Users() storage.UserStore                 { return nil }
func (m *mockStore) Tenants() storage.TenantStore             { return m.tenants }
func (m *mockStore) UserTenants() storage.UserTenantStore     { return nil }
func (m *mockStore) Credentials() storage.CredentialStore     { return nil }
func (m *mockStore) Presentations() storage.PresentationStore { return nil }
func (m *mockStore) Challenges() storage.ChallengeStore       { return m.challenges }
func (m *mockStore) Issuers() storage.IssuerStore             { return nil }
func (m *mockStore) Verifiers() storage.VerifierStore         { return nil }
func (m *mockStore) Invites() storage.InviteStore             { return nil }
func (m *mockStore) Close() error                             { return nil }
func (m *mockStore) Ping(_ context.Context) error             { return nil }

// mockTenantStore
type mockTenantStore struct {
	tenants map[domain.TenantID]*domain.Tenant
}

func (m *mockTenantStore) Create(_ context.Context, t *domain.Tenant) error { return nil }
func (m *mockTenantStore) GetByID(_ context.Context, id domain.TenantID) (*domain.Tenant, error) {
	t, ok := m.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant not found")
	}
	return t, nil
}
func (m *mockTenantStore) GetAll(_ context.Context) ([]*domain.Tenant, error)        { return nil, nil }
func (m *mockTenantStore) GetAllEnabled(_ context.Context) ([]*domain.Tenant, error) { return nil, nil }
func (m *mockTenantStore) Update(_ context.Context, _ *domain.Tenant) error          { return nil }
func (m *mockTenantStore) Delete(_ context.Context, _ domain.TenantID) error         { return nil }

// mockChallengeStore
type mockChallengeStore struct {
	challenges map[string]*domain.WebauthnChallenge
}

func (m *mockChallengeStore) Create(_ context.Context, c *domain.WebauthnChallenge) error {
	if m.challenges == nil {
		m.challenges = make(map[string]*domain.WebauthnChallenge)
	}
	m.challenges[c.ID] = c
	return nil
}
func (m *mockChallengeStore) GetByID(_ context.Context, id string) (*domain.WebauthnChallenge, error) {
	c, ok := m.challenges[id]
	if !ok {
		return nil, fmt.Errorf("challenge not found")
	}
	return c, nil
}
func (m *mockChallengeStore) Delete(_ context.Context, id string) error {
	delete(m.challenges, id)
	return nil
}
func (m *mockChallengeStore) DeleteExpired(_ context.Context) error            { return nil }
func (m *mockChallengeStore) DeleteByUserID(_ context.Context, _ string) error { return nil }

func setupOIDCHandlers(store *mockStore) (*gin.Engine, *MemorySessionStore) {
	gin.SetMode(gin.TestMode)
	sessions := NewMemorySessionStore()
	cfg := &config.ASConfig{
		ExternalURL:   "https://auth.example.com",
		DefaultMaxTAC: "rwl",
		SessionTTL:    24 * time.Hour,
	}
	logger := zap.NewNop()

	h := NewOIDCHandlers(store, sessions, cfg, logger)

	router := gin.New()
	router.GET("/auth/oidc/login", h.Login)
	router.GET("/auth/oidc/callback", h.Callback)

	return router, sessions
}

func TestOIDCLogin_MissingTenantHeader(t *testing.T) {
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}},
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCLogin_TenantNotFound(t *testing.T) {
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}},
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	req.Header.Set("X-Tenant-ID", "nonexistent")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCLogin_NoOIDCProvider(t *testing.T) {
	store := &mockStore{
		tenants: &mockTenantStore{
			tenants: map[domain.TenantID]*domain.Tenant{
				"t1": {
					ID:       "t1",
					OIDCGate: domain.OIDCGateConfig{Mode: domain.OIDCGateModeNone},
				},
			},
		},
		challenges: &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}},
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCCallback_ErrorParam(t *testing.T) {
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}},
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?error=access_denied&error_description=user+cancelled", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCCallback_MissingStateOrCode(t *testing.T) {
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}},
	}
	router, _ := setupOIDCHandlers(store)

	// Missing both state and code.
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	// Has state but no code.
	req = httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=abc", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing code, got %d", w.Code)
	}
}

func TestOIDCCallback_InvalidState(t *testing.T) {
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}},
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=invalid&code=authcode", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCCallback_ExpiredState(t *testing.T) {
	challengeStore := &mockChallengeStore{
		challenges: map[string]*domain.WebauthnChallenge{
			"expired-state": {
				ID:        "expired-state",
				TenantID:  "t1",
				Challenge: "expired-state",
				Action:    oidcChallengeAction,
				ExpiresAt: time.Now().Add(-time.Hour), // expired
			},
		},
	}
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=expired-state&code=authcode", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCCallback_WrongAction(t *testing.T) {
	challengeStore := &mockChallengeStore{
		challenges: map[string]*domain.WebauthnChallenge{
			"wrong-action": {
				ID:        "wrong-action",
				TenantID:  "t1",
				Challenge: "wrong-action",
				Action:    "login", // wrong action, should be oidc_login
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	}
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=wrong-action&code=authcode", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCCallback_TenantLookupFails(t *testing.T) {
	challengeStore := &mockChallengeStore{
		challenges: map[string]*domain.WebauthnChallenge{
			"valid-state": {
				ID:        "valid-state",
				TenantID:  "unknown-tenant",
				Challenge: "valid-state",
				Action:    oidcChallengeAction,
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	}
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=authcode", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCCallback_TenantNoOIDCConfig(t *testing.T) {
	challengeStore := &mockChallengeStore{
		challenges: map[string]*domain.WebauthnChallenge{
			"valid-state": {
				ID:        "valid-state",
				TenantID:  "t1",
				Challenge: "valid-state",
				Action:    oidcChallengeAction,
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	}
	store := &mockStore{
		tenants: &mockTenantStore{
			tenants: map[domain.TenantID]*domain.Tenant{
				"t1": {
					ID:       "t1",
					OIDCGate: domain.OIDCGateConfig{Mode: domain.OIDCGateModeNone},
				},
			},
		},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=authcode", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCCallback_DiscoveryFails(t *testing.T) {
	challengeStore := &mockChallengeStore{
		challenges: map[string]*domain.WebauthnChallenge{
			"valid-state": {
				ID:        "valid-state",
				TenantID:  "t1",
				Challenge: "valid-state",
				Action:    oidcChallengeAction,
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	}
	store := &mockStore{
		tenants: &mockTenantStore{
			tenants: map[domain.TenantID]*domain.Tenant{
				"t1": {
					ID: "t1",
					OIDCGate: domain.OIDCGateConfig{
						Mode: domain.OIDCGateModeLogin,
						LoginOP: &domain.OIDCProviderConfig{
							Issuer:   "https://127.0.0.1:1/nonexistent",
							ClientID: "test-client",
						},
					},
				},
			},
		},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=authcode", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCLogin_DiscoveryFails(t *testing.T) {
	challengeStore := &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}}
	store := &mockStore{
		tenants: &mockTenantStore{
			tenants: map[domain.TenantID]*domain.Tenant{
				"t1": {
					ID: "t1",
					OIDCGate: domain.OIDCGateConfig{
						Mode: domain.OIDCGateModeLogin,
						LoginOP: &domain.OIDCProviderConfig{
							Issuer:   "https://127.0.0.1:1/nonexistent", // unreachable
							ClientID: "test-client",
						},
					},
				},
			},
		},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should get 502 because OIDC discovery fails.
	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	// Verify state was stored before discovery (challenge should exist).
	if len(challengeStore.challenges) == 0 {
		t.Error("expected state challenge to be stored")
	}
}

func TestGenerateOIDCState(t *testing.T) {
	state1, err := generateOIDCState()
	if err != nil {
		t.Fatalf("generateOIDCState: %v", err)
	}
	if len(state1) == 0 {
		t.Error("expected non-empty state")
	}

	state2, err := generateOIDCState()
	if err != nil {
		t.Fatalf("generateOIDCState: %v", err)
	}
	if state1 == state2 {
		t.Error("expected unique states")
	}
}

func TestNewOIDCHandlers(t *testing.T) {
	store := &mockStore{
		tenants:    &mockTenantStore{},
		challenges: &mockChallengeStore{},
	}
	sessions := NewMemorySessionStore()
	cfg := &config.ASConfig{ExternalURL: "https://example.com"}
	logger := zap.NewNop()

	h := NewOIDCHandlers(store, sessions, cfg, logger)
	if h == nil {
		t.Fatal("expected non-nil OIDCHandlers")
	}
}
