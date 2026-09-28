package as

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// mockStore implements storage.Store for OIDC tests.
type mockStore struct {
	tenants    *mockTenantStore
	challenges *mockChallengeStore
}

func (m *mockStore) Users() storage.UserStore                     { return nil }
func (m *mockStore) Tenants() storage.TenantStore                 { return m.tenants }
func (m *mockStore) UserTenants() storage.UserTenantStore         { return nil }
func (m *mockStore) Credentials() storage.CredentialStore         { return nil }
func (m *mockStore) Presentations() storage.PresentationStore     { return nil }
func (m *mockStore) Challenges() storage.ChallengeStore           { return m.challenges }
func (m *mockStore) Issuers() storage.IssuerStore                 { return nil }
func (m *mockStore) Verifiers() storage.VerifierStore             { return nil }
func (m *mockStore) Invites() storage.InviteStore                 { return nil }
func (m *mockStore) WalletInstances() storage.WalletInstanceStore { return nil }
func (m *mockStore) KeyAttestations() storage.KeyAttestationStore { return nil }
func (m *mockStore) Close() error                                 { return nil }
func (m *mockStore) Ping(_ context.Context) error                 { return nil }

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
func (m *mockChallengeStore) ConsumeByID(_ context.Context, id string) (*domain.WebauthnChallenge, error) {
	c, ok := m.challenges[id]
	if !ok {
		return nil, fmt.Errorf("challenge not found")
	}
	delete(m.challenges, id)
	return c, nil
}
func (m *mockChallengeStore) Delete(_ context.Context, id string) error {
	delete(m.challenges, id)
	return nil
}
func (m *mockChallengeStore) DeleteExpired(_ context.Context) error            { return nil }
func (m *mockChallengeStore) DeleteByUserID(_ context.Context, _ string) error { return nil }

// testStateSecret is the HMAC key used to sign the OIDC state-binding
// cookie in tests (must be >=32 bytes, matching pkg/config.Config.Validate's
// requirement for the real JWT secret it's derived from in production).
var testStateSecret = []byte("test-oidc-state-secret-32-bytes!!")

// withOIDCStateCookie attaches a valid state-binding cookie to req, as if
// the browser had completed a prior /auth/oidc/login for this state. Tests
// that construct a callback request directly (bypassing Login) need this to
// get past the state-cookie check added for go-wallet-backend#385.
func withOIDCStateCookie(req *http.Request, state string) *http.Request {
	req.AddCookie(&http.Cookie{
		Name:  oidcStateCookieName(false),
		Value: signOIDCState(testStateSecret, state),
	})
	return req
}

func setupOIDCHandlers(store *mockStore) (*gin.Engine, *MemorySessionStore) {
	gin.SetMode(gin.TestMode)
	sessions := NewMemorySessionStore()
	cfg := &config.ASConfig{
		ExternalURL:   "https://auth.example.com",
		DefaultMaxTAC: "rwl",
		SessionTTL:    24 * time.Hour,
	}
	logger := zap.NewNop()

	h := NewOIDCHandlers(store, sessions, cfg, testStateSecret, logger)

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
					Enabled:  true,
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

	req := withOIDCStateCookie(httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=authcode", nil), "valid-state")
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
					Enabled:  true,
					OIDCGate: domain.OIDCGateConfig{Mode: domain.OIDCGateModeNone},
				},
			},
		},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := withOIDCStateCookie(httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=authcode", nil), "valid-state")
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
					ID:      "t1",
					Enabled: true,
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

	req := withOIDCStateCookie(httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=authcode", nil), "valid-state")
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
					ID:      "t1",
					Enabled: true,
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

	h := NewOIDCHandlers(store, sessions, cfg, testStateSecret, logger)
	if h == nil {
		t.Fatal("expected non-nil OIDCHandlers")
	}
}

// newMockOIDCServer creates a test server that serves OIDC discovery and token endpoints.
func newMockOIDCServer(t *testing.T, tokenHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]interface{}{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	if tokenHandler != nil {
		mux.HandleFunc("/token", tokenHandler)
	}
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOIDCLogin_HappyPath_Redirect(t *testing.T) {
	// Start mock OIDC provider with discovery.
	oidcSrv := newMockOIDCServer(t, nil)

	challengeStore := &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}}
	store := &mockStore{
		tenants: &mockTenantStore{
			tenants: map[domain.TenantID]*domain.Tenant{
				"t1": {
					ID:      "t1",
					Enabled: true,
					OIDCGate: domain.OIDCGateConfig{
						Mode: domain.OIDCGateModeLogin,
						LoginOP: &domain.OIDCProviderConfig{
							Issuer:   oidcSrv.URL,
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

	// Should redirect (302) to the authorization endpoint.
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	if !strings.HasPrefix(location, oidcSrv.URL+"/authorize") {
		t.Errorf("expected redirect to authorize endpoint, got: %s", location)
	}
	if !strings.Contains(location, "client_id=test-client") {
		t.Error("expected client_id in redirect URL")
	}
	if !strings.Contains(location, "response_type=code") {
		t.Error("expected response_type=code in redirect URL")
	}
	if !strings.Contains(location, "nonce=") {
		t.Error("expected nonce in redirect URL")
	}
	if !strings.Contains(location, "code_challenge=") {
		t.Error("expected PKCE code_challenge in redirect URL (go-wallet-backend#373)")
	}
	if !strings.Contains(location, "code_challenge_method=S256") {
		t.Error("expected PKCE code_challenge_method=S256 in redirect URL (go-wallet-backend#373)")
	}
	// State should have been stored.
	if len(challengeStore.challenges) == 0 {
		t.Error("expected challenge to be stored")
	}
	var stored *domain.WebauthnChallenge
	for _, ch := range challengeStore.challenges {
		stored = ch
	}
	if stored == nil || stored.CodeVerifier == "" {
		t.Error("expected code_verifier to be stored alongside the state challenge")
	}

	// A signed state-binding cookie must be set (go-wallet-backend#385).
	cookies := w.Result().Cookies()
	var stateCookie *http.Cookie
	for _, ck := range cookies {
		if ck.Name == oidcStateCookieName(false) {
			stateCookie = ck
		}
	}
	if stateCookie == nil {
		t.Fatal("expected state-binding cookie to be set")
	}
	if stateCookie.Value == "" {
		t.Error("expected non-empty state-binding cookie value")
	}
	if !stateCookie.HttpOnly {
		t.Error("expected state-binding cookie to be HttpOnly")
	}
	if stateCookie.SameSite != http.SameSiteLaxMode {
		t.Error("expected state-binding cookie SameSite=Lax (must survive the IdP's cross-site redirect)")
	}
}

// TestOIDCLogin_DiscoveryIssuerMismatch covers go-wallet-backend#373 (M-1) at
// the AS integration level: a discovery document whose issuer doesn't match
// the tenant's configured issuer must be rejected before its
// authorization_endpoint is used to build the redirect.
func TestOIDCLogin_DiscoveryIssuerMismatch(t *testing.T) {
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]string{
			"issuer":                 "https://attacker.example.com",
			"authorization_endpoint": "https://attacker.example.com/authorize",
			"token_endpoint":         "https://attacker.example.com/token",
			"jwks_uri":               "https://attacker.example.com/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	challengeStore := &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}}
	store := &mockStore{
		tenants: &mockTenantStore{
			tenants: map[domain.TenantID]*domain.Tenant{
				"t1": {
					ID:      "t1",
					Enabled: true,
					OIDCGate: domain.OIDCGateConfig{
						Mode: domain.OIDCGateModeLogin,
						LoginOP: &domain.OIDCProviderConfig{
							Issuer:   srv.URL,
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

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 (issuer mismatch should be treated as discovery failure), got %d: %s", w.Code, w.Body.String())
	}
}

// TestOIDCLogin_DisabledTenant covers go-wallet-backend#385 (T-4): a
// disabled tenant must not be able to start an OIDC login.
func TestOIDCLogin_DisabledTenant(t *testing.T) {
	store := &mockStore{
		tenants: &mockTenantStore{
			tenants: map[domain.TenantID]*domain.Tenant{
				"t1": {
					ID:      "t1",
					Enabled: false,
					OIDCGate: domain.OIDCGateConfig{
						Mode: domain.OIDCGateModeLogin,
						LoginOP: &domain.OIDCProviderConfig{
							Issuer:   "https://idp.example.com",
							ClientID: "test-client",
						},
					},
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

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for disabled tenant, got %d: %s", w.Code, w.Body.String())
	}
}

// TestOIDCCallback_StateCookieMismatch covers go-wallet-backend#385 (T-4):
// a callback whose state cookie doesn't match (or is missing) must be
// rejected, even though the state itself is a valid, unexpired challenge.
// This is the login-CSRF / cross-browser state injection scenario: an
// attacker completes their own login, then hands the resulting callback URL
// to a victim whose browser never received the matching cookie.
func TestOIDCCallback_StateCookieMismatch(t *testing.T) {
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
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	t.Run("no cookie at all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=authcode", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("cookie signed for a different state", func(t *testing.T) {
		challengeStore.challenges["valid-state-2"] = &domain.WebauthnChallenge{
			ID:        "valid-state-2",
			TenantID:  "t1",
			Challenge: "valid-state-2",
			Action:    oidcChallengeAction,
			ExpiresAt: time.Now().Add(time.Hour),
		}
		req := withOIDCStateCookie(
			httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state-2&code=authcode", nil),
			"some-other-state", // cookie signed for a state that isn't the one in the query
		)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// TestOIDCCallback_DisabledTenant covers go-wallet-backend#385 (T-4): a
// disabled tenant must not be able to complete an OIDC login, even with an
// otherwise-valid state/cookie/code.
func TestOIDCCallback_DisabledTenant(t *testing.T) {
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
					ID:      "t1",
					Enabled: false,
					OIDCGate: domain.OIDCGateConfig{
						Mode: domain.OIDCGateModeLogin,
						LoginOP: &domain.OIDCProviderConfig{
							Issuer:   "https://idp.example.com",
							ClientID: "test-client",
						},
					},
				},
			},
		},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := withOIDCStateCookie(
		httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=authcode", nil),
		"valid-state",
	)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for disabled tenant, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Full-flow helpers for admin-claim gating tests (go-wallet-backend#376) ---
// These stand up a real RSA-signed ID token and a discovery/JWKS/token
// server, so the AS's Validator actually verifies a signature end to end,
// rather than mocking it away.

// testIDTokenServer serves discovery + JWKS with a fixed key, and a /token
// endpoint whose id_token is whatever's currently in *idToken (set by the
// test after the server URL - and therefore the token's `iss` - is known).
// It also records the last code_verifier it received, for PKCE assertions.
type testIDTokenServer struct {
	*httptest.Server
	idToken          *string
	lastCodeVerifier string
}

func newTestIDTokenServer(t *testing.T, jwkJSON string) *testIDTokenServer {
	t.Helper()
	var idToken string
	result := &testIDTokenServer{idToken: &idToken}

	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, jwkJSON)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			result.lastCodeVerifier = r.Form.Get("code_verifier")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-123",
			"token_type":   "Bearer",
			"id_token":     *result.idToken,
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	result.Server = srv
	return result
}

func generateTestRSAKeyAndJWK(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	jwk := fmt.Sprintf(`{"kty":"RSA","kid":"test-kid","use":"sig","alg":"RS256","n":"%s","e":"%s"}`, n, e)
	return key, jwk
}

func signTestIDToken(t *testing.T, key *rsa.PrivateKey, issuer, audience, subject, nonce string, extraClaims map[string]interface{}) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range extraClaims {
		claims[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-kid"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return signed
}

// runOIDCLoginAndCallback drives a full Login -> (sign ID token with the
// real nonce/issuer) -> Callback round trip against router, returning the
// callback response. tokenServer.idToken is populated just before the
// callback request is made.
func runOIDCLoginAndCallback(t *testing.T, router *gin.Engine, tokenServer *testIDTokenServer, key *rsa.PrivateKey, clientID, subject string, extraIDTokenClaims map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()

	loginReq := httptest.NewRequest(http.MethodGet, "/auth/oidc/login", nil)
	loginReq.Header.Set("X-Tenant-ID", "t1")
	loginW := httptest.NewRecorder()
	router.ServeHTTP(loginW, loginReq)
	if loginW.Code != http.StatusFound {
		t.Fatalf("login: expected 302, got %d: %s", loginW.Code, loginW.Body.String())
	}

	loc, err := url.Parse(loginW.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("expected state and nonce in redirect, got: %s", loc)
	}

	var stateCookie *http.Cookie
	for _, ck := range loginW.Result().Cookies() {
		if ck.Name == oidcStateCookieName(false) {
			stateCookie = ck
		}
	}
	if stateCookie == nil {
		t.Fatal("expected state-binding cookie from login response")
	}

	*tokenServer.idToken = signTestIDToken(t, key, tokenServer.URL, clientID, subject, nonce, extraIDTokenClaims)

	cbReq := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state="+url.QueryEscape(state)+"&code=test-code", nil)
	cbReq.AddCookie(stateCookie)
	cbW := httptest.NewRecorder()
	router.ServeHTTP(cbW, cbReq)
	return cbW
}

// TestOIDCCallback_AdminClaim_RequiresTenantOptIn covers go-wallet-backend#376
// (M-4): an ID token asserting an "admin" groups claim must NOT elevate the
// session's MaxTAC unless the tenant has explicitly set
// oidc_gate.trust_admin_claim. Also verifies the full flow's PKCE
// code_verifier reaches the token endpoint (go-wallet-backend#373).
func TestOIDCCallback_AdminClaim_RequiresTenantOptIn(t *testing.T) {
	key, jwk := generateTestRSAKeyAndJWK(t)
	tokenServer := newTestIDTokenServer(t, jwk)

	challengeStore := &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}}
	tenant := &domain.Tenant{
		ID:      "t1",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{
				Issuer:   tokenServer.URL,
				ClientID: "test-client",
			},
			// TrustAdminClaim intentionally left false (the default).
		},
	}
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{"t1": tenant}},
		challenges: challengeStore,
	}
	router, sessions := setupOIDCHandlers(store)

	cbW := runOIDCLoginAndCallback(t, router, tokenServer, key, "test-client", "user-1",
		map[string]interface{}{"groups": []interface{}{"users", "admin"}})

	if cbW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", cbW.Code, cbW.Body.String())
	}
	if tokenServer.lastCodeVerifier == "" {
		t.Error("expected code_verifier to reach the token endpoint (go-wallet-backend#373)")
	}

	session := getSessionFromCookie(t, sessions, cbW)
	if session.MaxTAC == TAC("rwlidka") {
		t.Errorf("expected admin claim to be IGNORED without tenant opt-in, got MaxTAC=%s", session.MaxTAC)
	}
}

// TestOIDCCallback_AdminClaim_TenantOptedIn is the positive counterpart: with
// oidc_gate.trust_admin_claim=true, the same admin groups claim DOES elevate
// the session's MaxTAC.
func TestOIDCCallback_AdminClaim_TenantOptedIn(t *testing.T) {
	key, jwk := generateTestRSAKeyAndJWK(t)
	tokenServer := newTestIDTokenServer(t, jwk)

	challengeStore := &mockChallengeStore{challenges: map[string]*domain.WebauthnChallenge{}}
	tenant := &domain.Tenant{
		ID:      "t1",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{
				Issuer:   tokenServer.URL,
				ClientID: "test-client",
			},
			TrustAdminClaim: true,
		},
	}
	store := &mockStore{
		tenants:    &mockTenantStore{tenants: map[domain.TenantID]*domain.Tenant{"t1": tenant}},
		challenges: challengeStore,
	}
	router, sessions := setupOIDCHandlers(store)

	cbW := runOIDCLoginAndCallback(t, router, tokenServer, key, "test-client", "user-1",
		map[string]interface{}{"groups": []interface{}{"users", "admin"}})

	if cbW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", cbW.Code, cbW.Body.String())
	}

	session := getSessionFromCookie(t, sessions, cbW)
	if session.MaxTAC != TAC("rwlidka") {
		t.Errorf("expected admin claim to elevate MaxTAC with tenant opt-in, got %s", session.MaxTAC)
	}
}

// getSessionFromCookie extracts the session JTI from the AS session cookie
// set on a callback response and loads it from the store.
func getSessionFromCookie(t *testing.T, sessions *MemorySessionStore, w *httptest.ResponseRecorder) *Session {
	t.Helper()
	var jti string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookieSecure || ck.Name == sessionCookieInsecure {
			jti = ck.Value
		}
	}
	if jti == "" {
		t.Fatal("expected AS session cookie in callback response")
	}
	session, err := sessions.Get(context.Background(), jti)
	if err != nil {
		t.Fatalf("Get session: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to exist")
	}
	return session
}

func TestOIDCCallback_TokenExchangeFails(t *testing.T) {
	// Token endpoint returns an error.
	oidcSrv := newMockOIDCServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	})

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
					ID:      "t1",
					Enabled: true,
					OIDCGate: domain.OIDCGateConfig{
						Mode: domain.OIDCGateModeLogin,
						LoginOP: &domain.OIDCProviderConfig{
							Issuer:   oidcSrv.URL,
							ClientID: "test-client",
						},
					},
				},
			},
		},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := withOIDCStateCookie(httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=bad-code", nil), "valid-state")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOIDCCallback_TokenExchangeSuccess_IDTokenValidationFails(t *testing.T) {
	// Token endpoint returns an ID token that won't validate (bad JWT).
	oidcSrv := newMockOIDCServer(t, func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"id_token":     "not.a.valid.jwt",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

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
					ID:      "t1",
					Enabled: true,
					OIDCGate: domain.OIDCGateConfig{
						Mode: domain.OIDCGateModeLogin,
						LoginOP: &domain.OIDCProviderConfig{
							Issuer:   oidcSrv.URL,
							ClientID: "test-client",
						},
					},
				},
			},
		},
		challenges: challengeStore,
	}
	router, _ := setupOIDCHandlers(store)

	req := withOIDCStateCookie(httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?state=valid-state&code=auth-code", nil), "valid-state")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fail with 401 because the ID token can't be validated.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}
