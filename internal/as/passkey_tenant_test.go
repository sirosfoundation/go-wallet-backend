package as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// setupPasskeyTenantTest wires the real /auth/passkey/* routes (tenant-header
// middleware, OIDC gate middleware, and PasskeyHandlers backed by the real
// service.WebAuthnService) against an in-memory store, the same way
// ASModule.RegisterRoutes wires them in production. This exercises the fix
// for issue #374: passkey tenant selection must come from the validated
// X-Tenant-ID header, never from the request body.
func setupPasskeyTenantTest(t *testing.T) (*gin.Engine, *memory.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	store := memory.NewStore()
	logger := zap.NewNop()

	webauthnCfg := &config.Config{
		Server: config.ServerConfig{
			RPName:   "Test App",
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		JWT: config.JWTConfig{
			Secret: "test-jwt-secret-that-is-long-enough-32",
			Issuer: "test-issuer",
		},
	}
	webauthnSvc, err := service.NewWebAuthnService(store, webauthnCfg, logger)
	if err != nil {
		t.Fatalf("failed to create webauthn service: %v", err)
	}

	asCfg := &config.ASConfig{
		DefaultMaxTAC:   "rwl",
		SessionTTL:      24 * time.Hour,
		InsecureCookies: true,
	}

	m := &ASModule{
		PasskeyHandler: NewPasskeyHandlers(webauthnSvc, NewMemorySessionStore(), asCfg, logger),
		Sessions:       NewMemorySessionStore(),
		Logger:         logger,
		Config:         asCfg,
		store:          store,
		validatorCache: middleware.NewValidatorCache(nil, logger),
	}

	router := gin.New()
	authGroup := router.Group("/auth")
	m.RegisterRoutes(authGroup)

	return router, store
}

func mustCreateTenant(t *testing.T, store *memory.Store, tenant *domain.Tenant) {
	t.Helper()
	if err := store.Tenants().Create(context.Background(), tenant); err != nil {
		t.Fatalf("failed to create tenant %s: %v", tenant.ID, err)
	}
}

// (a) A request with header tenant A and body tenant B must operate against
// tenant A, not B. tenant-b requires an invite (and none is supplied); if the
// body's tenantId were still trusted, this request would be rejected with
// invite_required. Since it must operate against tenant-a (no invite
// required), it succeeds, and the stored challenge is scoped to tenant-a.
func TestPasskeyRegisterBegin_HeaderTenantWinsOverBody(t *testing.T) {
	router, store := setupPasskeyTenantTest(t)

	mustCreateTenant(t, store, &domain.Tenant{ID: "tenant-a", Name: "Tenant A", Enabled: true})
	mustCreateTenant(t, store, &domain.Tenant{ID: "tenant-b", Name: "Tenant B", Enabled: true, RequireInvite: true})

	body := strings.NewReader(`{"tenantId":"tenant-b"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Token-Mode", "session")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (tenant-a has no invite requirement), got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		ChallengeID string `json:"challengeId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	challenge, err := store.Challenges().GetByID(context.Background(), resp.ChallengeID)
	if err != nil {
		t.Fatalf("failed to look up stored challenge: %v", err)
	}
	if challenge.TenantID != "tenant-a" {
		t.Errorf("challenge scoped to tenant %q, want tenant-a (body's tenant-b must be ignored)", challenge.TenantID)
	}
}

// Regression test for a Copilot review finding on this PR: RegisterFinish
// must reject a request whose X-Tenant-ID header disagrees with the tenant
// BeginRegistration actually recorded on the challenge. Without this, a
// caller could begin under tenant A and finish the same challenge under
// header tenant B, letting bind_identity enforcement run against the wrong
// tenant's policy/IdP while the registration itself is still written under
// A regardless. The mismatch must be caught before any credential parsing,
// so a bogus/empty credential body is enough to prove it - the request
// never gets that far.
func TestPasskeyRegisterFinish_RejectsHeaderChallengeTenantMismatch(t *testing.T) {
	router, store := setupPasskeyTenantTest(t)

	mustCreateTenant(t, store, &domain.Tenant{ID: "tenant-a", Name: "Tenant A", Enabled: true})
	mustCreateTenant(t, store, &domain.Tenant{ID: "tenant-b", Name: "Tenant B", Enabled: true})

	beginUnderTenantA := func(t *testing.T) string {
		t.Helper()
		beginReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", strings.NewReader(`{}`))
		beginReq.Header.Set("Content-Type", "application/json")
		beginReq.Header.Set("X-Tenant-ID", "tenant-a")
		beginReq.Header.Set("X-Token-Mode", "session")
		beginW := httptest.NewRecorder()
		router.ServeHTTP(beginW, beginReq)
		if beginW.Code != http.StatusOK {
			t.Fatalf("begin: expected 200, got %d: %s", beginW.Code, beginW.Body.String())
		}
		var beginResp struct {
			ChallengeID string `json:"challengeId"`
		}
		if err := json.Unmarshal(beginW.Body.Bytes(), &beginResp); err != nil {
			t.Fatalf("failed to decode begin response: %v", err)
		}
		return beginResp.ChallengeID
	}

	t.Run("mismatched header tenant is rejected before touching the challenge's one-time use", func(t *testing.T) {
		challengeID := beginUnderTenantA(t)

		// Finish under a DIFFERENT header tenant than the one used to begin.
		finishBody := `{"challengeId":"` + challengeID + `","credential":{}}`
		finishReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/finish", strings.NewReader(finishBody))
		finishReq.Header.Set("Content-Type", "application/json")
		finishReq.Header.Set("X-Tenant-ID", "tenant-b")
		finishReq.Header.Set("X-Token-Mode", "session")
		finishW := httptest.NewRecorder()
		router.ServeHTTP(finishW, finishReq)

		if finishW.Code != http.StatusForbidden {
			t.Fatalf("expected 403 tenant mismatch, got %d: %s", finishW.Code, finishW.Body.String())
		}
		if !strings.Contains(finishW.Body.String(), "tenant mismatch") {
			t.Errorf("expected tenant mismatch error, got: %s", finishW.Body.String())
		}

		// The challenge itself must survive a mismatched attempt (fixing a
		// second Copilot finding on this PR): the one-time challenge is only
		// consumed once the tenant check passes, so a caller who merely knows
		// a valid challenge ID can't burn it by submitting the wrong tenant,
		// denying the legitimate caller the ability to ever finish it.
		if _, err := store.Challenges().GetByID(context.Background(), challengeID); err != nil {
			t.Errorf("challenge should survive a mismatched-tenant attempt (not be consumed), but lookup failed: %v", err)
		}
	})

	t.Run("matching header tenant is not rejected as a mismatch", func(t *testing.T) {
		challengeID := beginUnderTenantA(t)

		// Finish under the SAME header tenant used to begin. This must clear
		// the tenant-mismatch check and fail later, on the bogus credential,
		// not be rejected as a tenant mismatch.
		finishBody := `{"challengeId":"` + challengeID + `","credential":{}}`
		finishReq := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/finish", strings.NewReader(finishBody))
		finishReq.Header.Set("Content-Type", "application/json")
		finishReq.Header.Set("X-Tenant-ID", "tenant-a")
		finishReq.Header.Set("X-Token-Mode", "session")
		finishW := httptest.NewRecorder()
		router.ServeHTTP(finishW, finishReq)

		if finishW.Code == http.StatusForbidden && strings.Contains(finishW.Body.String(), "tenant mismatch") {
			t.Errorf("matching header tenant must not be rejected as a tenant mismatch, got: %s", finishW.Body.String())
		}
	})
}

// (b) An invite-required tenant cannot be bypassed by omitting the body's
// tenantId (which used to skip tenant lookup - and therefore the invite
// check - entirely, defaulting to the "default" tenant) or by supplying a
// mismatched body tenantId that doesn't require an invite.
func TestPasskeyRegisterBegin_InviteRequiredCannotBeBypassedByBody(t *testing.T) {
	router, store := setupPasskeyTenantTest(t)

	mustCreateTenant(t, store, &domain.Tenant{ID: "invite-tenant", Name: "Invite Tenant", Enabled: true, RequireInvite: true})
	mustCreateTenant(t, store, &domain.Tenant{ID: "tenant-a", Name: "Tenant A", Enabled: true})

	cases := []struct {
		name string
		body string
	}{
		{"omitted body tenantId", `{}`},
		{"empty body tenantId", `{"tenantId":""}`},
		{"mismatched body tenantId naming a non-invite tenant", `{"tenantId":"tenant-a"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Tenant-ID", "invite-tenant")
			req.Header.Set("X-Token-Mode", "session")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403 invite_required, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "invite_required") {
				t.Errorf("expected invite_required error, got: %s", w.Body.String())
			}
		})
	}
}

// (c) A tenant configured with oidc_gate for registration/login now gates
// the AS passkey routes, matching the /user/* routes. Without an
// Authorization header, the gate rejects the request before it ever reaches
// the handler/service layer.
func TestPasskeyRoutes_OIDCGateApplies(t *testing.T) {
	router, store := setupPasskeyTenantTest(t)

	mustCreateTenant(t, store, &domain.Tenant{
		ID:      "gated-registration",
		Name:    "Gated Registration Tenant",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeRegistration,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "client-1",
			},
		},
	})
	mustCreateTenant(t, store, &domain.Tenant{
		ID:      "gated-login",
		Name:    "Gated Login Tenant",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "client-1",
			},
		},
	})
	mustCreateTenant(t, store, &domain.Tenant{ID: "ungated", Name: "Ungated Tenant", Enabled: true})

	t.Run("registration gate blocks without Authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", "gated-registration")
		req.Header.Set("X-Token-Mode", "session")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 oidc_gate_required, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "oidc_gate_required") {
			t.Errorf("expected oidc_gate_required error, got: %s", w.Body.String())
		}
	})

	t.Run("login gate blocks without Authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", nil)
		req.Header.Set("X-Tenant-ID", "gated-login")
		req.Header.Set("X-Token-Mode", "session")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 oidc_gate_required, got %d: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "oidc_gate_required") {
			t.Errorf("expected oidc_gate_required error, got: %s", w.Body.String())
		}
	})

	t.Run("registration gate does not apply to the login group", func(t *testing.T) {
		// gated-registration only gates registration, not login: login/begin
		// must proceed without an Authorization header.
		req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", nil)
		req.Header.Set("X-Tenant-ID", "gated-registration")
		req.Header.Set("X-Token-Mode", "session")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 (login is not gated for this tenant), got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("ungated tenant proceeds without Authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", "ungated")
		req.Header.Set("X-Token-Mode", "session")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// Unknown tenants in the header are rejected outright (404), regardless of
// what the body claims - the header is validated, the body never is.
func TestPasskeyRegisterBegin_UnknownHeaderTenantRejected(t *testing.T) {
	router, _ := setupPasskeyTenantTest(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "does-not-exist")
	req.Header.Set("X-Token-Mode", "session")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 tenant not found, got %d: %s", w.Code, w.Body.String())
	}
}

// TestNewASModule_WiresPasskeyTenantPerimeter exercises the actual
// production wiring path (NewASModule, not a hand-built ASModule struct
// literal), proving the constructor itself sets up the store and
// validatorCache fields RegisterRoutes needs for the tenant-header and
// OIDC-gate middleware on /auth/passkey/* - the perimeter this PR adds.
func TestNewASModule_WiresPasskeyTenantPerimeter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Write a temp ECDSA signing key for the AS's KeyManager.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "ec.pem")
	f, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	f.Close()

	store := memory.NewStore()
	mustCreateTenant(t, store, &domain.Tenant{ID: "tenant-a", Name: "Tenant A", Enabled: true})

	webauthnSvc, err := service.NewWebAuthnService(store, &config.Config{
		Server: config.ServerConfig{RPName: "Test App", RPID: "localhost", RPOrigin: "http://localhost:8080"},
		JWT:    config.JWTConfig{Secret: "test-jwt-secret-that-is-long-enough-32", Issuer: "test-issuer"},
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("failed to create webauthn service: %v", err)
	}

	asCfg := &config.ASConfig{
		SigningKeyPath:  keyPath,
		Issuer:          "https://auth.example.com",
		DefaultMaxTAC:   "rwl",
		SessionTTL:      24 * time.Hour,
		InsecureCookies: true,
	}
	jwtCfg := &config.JWTConfig{Issuer: "test-issuer"}

	m, err := NewASModule(context.Background(), asCfg, jwtCfg, webauthnSvc, store, nil, http.DefaultClient, zap.NewNop())
	if err != nil {
		t.Fatalf("NewASModule: %v", err)
	}

	router := gin.New()
	authGroup := router.Group("/auth")
	m.RegisterRoutes(authGroup)

	// The tenant-header middleware NewASModule wired up must reject an
	// unknown tenant, and the passkey handlers it constructed must serve a
	// known one - end to end, through the constructor this test targets.
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "does-not-exist")
	req.Header.Set("X-Token-Mode", "session")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown tenant, got %d: %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Token-Mode", "session")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for known tenant, got %d: %s", w.Code, w.Body.String())
	}
}

// Requests without X-Token-Mode: session (the removed legacy flow) must get
// 410 BEFORE the OIDC gate can answer with an OIDC error; session-mode
// requests still reach the gate.
func TestPasskeyRoutes_SessionModeRequired410BeforeOIDCGate(t *testing.T) {
	router, store := setupPasskeyTenantTest(t)
	mustCreateTenant(t, store, &domain.Tenant{
		ID: "gated", Name: "Gated", Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode:           domain.OIDCGateModeBoth,
			RegistrationOP: &domain.OIDCProviderConfig{Issuer: "https://idp.example.com", ClientID: "c"},
			LoginOP:        &domain.OIDCProviderConfig{Issuer: "https://idp.example.com", ClientID: "c"},
		},
	})
	for _, path := range []string{"/auth/passkey/register/begin", "/auth/passkey/register/finish", "/auth/passkey/login/begin", "/auth/passkey/login/finish"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "gated")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "legacy_tokens_disabled") {
			t.Errorf("%s without X-Token-Mode: expected 410 legacy_tokens_disabled before the OIDC gate, got %d: %s", path, w.Code, w.Body.String())
		}

		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "gated")
		req.Header.Set("X-Token-Mode", "session")
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "oidc_gate_required") {
			t.Errorf("%s session-mode: expected the OIDC gate answer, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}
