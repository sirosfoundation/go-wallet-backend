package as

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
	"github.com/sirosfoundation/go-wallet-backend/pkg/oidc"
)

// capturingWebAuthn is a WebAuthnProvider test double that records the
// request it was called with, so tests can assert what the handler actually
// passed down to the service layer (e.g. the resolved OIDCGateBinding).
type capturingWebAuthn struct {
	mockWebAuthn
	lastFinishRegReq   *service.FinishRegistrationRequest
	lastFinishLoginReq *service.FinishLoginRequest
}

func (m *capturingWebAuthn) FinishRegistration(ctx context.Context, req *service.FinishRegistrationRequest) (*service.FinishRegistrationResponse, error) {
	m.lastFinishRegReq = req
	return m.mockWebAuthn.FinishRegistration(ctx, req)
}

func (m *capturingWebAuthn) FinishLogin(ctx context.Context, req *service.FinishLoginRequest) (*service.FinishLoginResponse, error) {
	m.lastFinishLoginReq = req
	return m.mockWebAuthn.FinishLogin(ctx, req)
}

// contextInjector builds middleware that sets the gin context keys
// TenantHeaderMiddleware and OIDCGateMiddleware would normally set, so
// handler-level tests can exercise the bind_identity / OIDC-gate branches
// directly without standing up the full middleware + storage stack (that
// integration path is covered separately in passkey_tenant_test.go).
func contextInjector(tenant *domain.Tenant, oidcResult *oidc.ValidationResult) gin.HandlerFunc {
	return func(c *gin.Context) {
		if tenant != nil {
			c.Set("tenant", tenant)
		}
		if oidcResult != nil {
			c.Set(middleware.OIDCGateContextKey, oidcResult)
		}
		c.Next()
	}
}

func newTestPasskeyHandlers(webauthn WebAuthnProvider) (*PasskeyHandlers, *MemorySessionStore) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	cfg := &config.ASConfig{
		DefaultMaxTAC:   "rwl",
		SessionTTL:      24 * time.Hour,
		InsecureCookies: true,
	}
	return NewPasskeyHandlers(webauthn, store, nil, cfg, zap.NewNop()), store
}

func gatedTenant(bindIdentity bool, regOP *domain.OIDCProviderConfig) *domain.Tenant {
	return &domain.Tenant{
		ID:      "gated",
		Name:    "Gated",
		Enabled: true,
		OIDCGate: domain.OIDCGateConfig{
			Mode:           domain.OIDCGateModeRegistration,
			BindIdentity:   bindIdentity,
			RegistrationOP: regOP,
		},
	}
}

func TestPasskeyRegisterFinish_BindIdentity_MissingOIDCResult(t *testing.T) {
	mock := &capturingWebAuthn{}
	h, _ := newTestPasskeyHandlers(mock)

	router := gin.New()
	router.Use(contextInjector(gatedTenant(true, &domain.OIDCProviderConfig{Issuer: "https://idp.example.com"}), nil))
	router.POST("/finish", h.RegisterFinish)

	body, _ := json.Marshal(service.FinishRegistrationRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasskeyRegisterFinish_BindIdentity_Misconfigured(t *testing.T) {
	mock := &capturingWebAuthn{}
	h, _ := newTestPasskeyHandlers(mock)

	router := gin.New()
	router.Use(contextInjector(
		gatedTenant(true, nil), // BindIdentity enabled, but no RegistrationOP configured.
		&oidc.ValidationResult{Issuer: "https://idp.example.com", Subject: "user-1", Claims: nil},
	))
	router.POST("/finish", h.RegisterFinish)

	body, _ := json.Marshal(service.FinishRegistrationRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasskeyRegisterFinish_BindIdentity_IssuerMismatch(t *testing.T) {
	mock := &capturingWebAuthn{}
	h, _ := newTestPasskeyHandlers(mock)

	router := gin.New()
	router.Use(contextInjector(
		gatedTenant(true, &domain.OIDCProviderConfig{Issuer: "https://expected-idp.example.com"}),
		&oidc.ValidationResult{Issuer: "https://attacker-idp.example.com", Subject: "user-1"},
	))
	router.POST("/finish", h.RegisterFinish)

	body, _ := json.Marshal(service.FinishRegistrationRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 oidc_issuer_mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasskeyRegisterFinish_BindIdentity_Success(t *testing.T) {
	mock := &capturingWebAuthn{
		mockWebAuthn: mockWebAuthn{
			finishRegResp: &service.FinishRegistrationResponse{UUID: "user-1", TenantID: "gated"},
		},
	}
	h, _ := newTestPasskeyHandlers(mock)

	router := gin.New()
	router.Use(contextInjector(
		gatedTenant(true, &domain.OIDCProviderConfig{Issuer: "https://idp.example.com"}),
		&oidc.ValidationResult{
			Issuer:  "https://idp.example.com",
			Subject: "user-1",
			Claims:  map[string]interface{}{"email": "user@example.com"},
		},
	))
	router.POST("/finish", h.RegisterFinish)

	body, _ := json.Marshal(service.FinishRegistrationRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.lastFinishRegReq.OIDCGateBinding == nil {
		t.Fatal("expected OIDCGateBinding to be populated on the request passed to FinishRegistration")
	}
	if mock.lastFinishRegReq.OIDCGateBinding.Email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %q", mock.lastFinishRegReq.OIDCGateBinding.Email)
	}
	if mock.lastFinishRegReq.OIDCGateBinding.BindingType != "registration" {
		t.Errorf("expected binding type registration, got %q", mock.lastFinishRegReq.OIDCGateBinding.BindingType)
	}
}

func TestPasskeyRegisterFinish_ErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"challenge not found", service.ErrChallengeNotFound, http.StatusNotFound},
		{"challenge expired", service.ErrChallengeExpired, http.StatusGone},
		{"verification failed", service.ErrVerificationFailed, http.StatusBadRequest},
		{"aaguid blacklisted", service.ErrAAGUIDBlacklisted, http.StatusForbidden},
		{"invalid invite", service.ErrInvalidInvite, http.StatusForbidden},
		{"unmapped error", fmt.Errorf("boom"), http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &capturingWebAuthn{mockWebAuthn: mockWebAuthn{finishRegErr: tc.err}}
			h, _ := newTestPasskeyHandlers(mock)

			router := gin.New()
			router.POST("/finish", h.RegisterFinish)

			body, _ := json.Marshal(service.FinishRegistrationRequest{ChallengeID: "c1"})
			req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("expected %d, got %d: %s", tc.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestPasskeyLoginFinish_OIDCGateBindingPopulated(t *testing.T) {
	mock := &capturingWebAuthn{
		mockWebAuthn: mockWebAuthn{
			finishLoginResp: &service.FinishLoginResponse{UUID: "user-1", TenantID: "tenant-1"},
		},
	}
	h, _ := newTestPasskeyHandlers(mock)

	router := gin.New()
	router.Use(contextInjector(nil, &oidc.ValidationResult{
		Issuer:  "https://idp.example.com",
		Subject: "user-1",
		Claims:  map[string]interface{}{"email": "user@example.com"},
	}))
	router.POST("/finish", h.LoginFinish)

	body, _ := json.Marshal(service.FinishLoginRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.lastFinishLoginReq.OIDCGateBinding == nil {
		t.Fatal("expected OIDCGateBinding to be populated on the request passed to FinishLogin")
	}
	if mock.lastFinishLoginReq.OIDCGateBinding.Email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %q", mock.lastFinishLoginReq.OIDCGateBinding.Email)
	}
}

// TestPasskeyLoginFinish_OIDCGateBinding_AudiencePopulatedFromTenant covers a
// Copilot review finding: LoginFinish must record which audience the token
// was actually validated against (the header tenant's LoginOP), so
// FinishLogin can compare it against the credential's real tenant's own
// audience - issuer alone isn't enough proof when tenants share an IdP.
func TestPasskeyLoginFinish_OIDCGateBinding_AudiencePopulatedFromTenant(t *testing.T) {
	mock := &capturingWebAuthn{
		mockWebAuthn: mockWebAuthn{
			finishLoginResp: &service.FinishLoginResponse{UUID: "user-1", TenantID: "tenant-1"},
		},
	}
	h, _ := newTestPasskeyHandlers(mock)

	headerTenant := &domain.Tenant{
		ID: "header-tenant",
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "header-tenant-client",
			},
		},
	}

	router := gin.New()
	router.Use(contextInjector(headerTenant, &oidc.ValidationResult{
		Issuer:  "https://idp.example.com",
		Subject: "user-1",
	}))
	router.POST("/finish", h.LoginFinish)

	body, _ := json.Marshal(service.FinishLoginRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.lastFinishLoginReq.OIDCGateBinding == nil {
		t.Fatal("expected OIDCGateBinding to be populated")
	}
	if mock.lastFinishLoginReq.OIDCGateBinding.Audience != "header-tenant-client" {
		t.Errorf("expected audience %q (header tenant's LoginOP client ID), got %q",
			"header-tenant-client", mock.lastFinishLoginReq.OIDCGateBinding.Audience)
	}
}

// TestPasskeyLoginFinish_OIDCGateBinding_ClaimsPopulated covers a third
// Copilot review finding: LoginFinish must also record the token's full
// validated claims, so FinishLogin can re-check them against the
// credential's real tenant's own RequiredClaims - issuer/audience matching
// alone isn't enough when two tenants share both but require different
// claims.
func TestPasskeyLoginFinish_OIDCGateBinding_ClaimsPopulated(t *testing.T) {
	mock := &capturingWebAuthn{
		mockWebAuthn: mockWebAuthn{
			finishLoginResp: &service.FinishLoginResponse{UUID: "user-1", TenantID: "tenant-1"},
		},
	}
	h, _ := newTestPasskeyHandlers(mock)

	router := gin.New()
	router.Use(contextInjector(nil, &oidc.ValidationResult{
		Issuer:  "https://idp.example.com",
		Subject: "user-1",
		Claims:  map[string]interface{}{"role": "admin", "email": "user@example.com"},
	}))
	router.POST("/finish", h.LoginFinish)

	body, _ := json.Marshal(service.FinishLoginRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if mock.lastFinishLoginReq.OIDCGateBinding == nil {
		t.Fatal("expected OIDCGateBinding to be populated")
	}
	if role, _ := mock.lastFinishLoginReq.OIDCGateBinding.Claims["role"].(string); role != "admin" {
		t.Errorf("expected claims to carry role=admin, got %v", mock.lastFinishLoginReq.OIDCGateBinding.Claims)
	}
}

func TestPasskeyLoginFinish_ErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"challenge not found", service.ErrChallengeNotFound, http.StatusNotFound},
		{"challenge expired", service.ErrChallengeExpired, http.StatusGone},
		{"user not found", service.ErrUserNotFound, http.StatusNotFound},
		{"credential not found", service.ErrCredentialNotFound, http.StatusNotFound},
		{"verification failed", service.ErrVerificationFailed, http.StatusUnauthorized},
		{"oidc gate required", service.ErrOIDCGateRequired, http.StatusUnauthorized},
		{"tenant access denied", service.ErrTenantAccessDenied, http.StatusForbidden},
		{"identity not bound", service.ErrIdentityNotBound, http.StatusForbidden},
		{"identity binding mismatch", service.ErrIdentityBindingMismatch, http.StatusForbidden},
		{"unmapped error", fmt.Errorf("boom"), http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &capturingWebAuthn{mockWebAuthn: mockWebAuthn{finishLoginErr: tc.err}}
			h, _ := newTestPasskeyHandlers(mock)

			router := gin.New()
			router.POST("/finish", h.LoginFinish)

			body, _ := json.Marshal(service.FinishLoginRequest{ChallengeID: "c1"})
			req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("expected %d, got %d: %s", tc.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

func TestPasskeyRegisterBegin_ErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"tenant not found", service.ErrTenantNotFound, http.StatusNotFound},
		{"invite required", service.ErrInviteRequired, http.StatusForbidden},
		{"invalid invite", service.ErrInvalidInvite, http.StatusForbidden},
		{"unmapped error", fmt.Errorf("boom"), http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &capturingWebAuthn{mockWebAuthn: mockWebAuthn{beginRegErr: tc.err}}
			h, _ := newTestPasskeyHandlers(mock)

			router := gin.New()
			router.POST("/begin", h.RegisterBegin)

			req := httptest.NewRequest(http.MethodPost, "/begin", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("expected %d, got %d: %s", tc.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// SID-AUTH-06: the registration auto-login session inherits the token's iat, so
// a cut-off between mint and store refuses it.
func TestPasskeyRegisterFinish_SessionInheritsTokenIssuedAt(t *testing.T) {
	iat := time.Now().Add(-10 * time.Second).Truncate(time.Second)
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"iat":%d}`, iat.Unix())))
	tok := hdr + "." + pl + ".sig"

	mock := &capturingWebAuthn{mockWebAuthn: mockWebAuthn{
		finishRegResp: &service.FinishRegistrationResponse{UUID: "user-1", TenantID: "t", Token: tok},
	}}
	h, store := newTestPasskeyHandlers(mock)
	router := gin.New()
	router.POST("/finish", h.RegisterFinish)
	body, _ := json.Marshal(service.FinishRegistrationRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var jti string
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookieInsecure {
			jti = ck.Value
		}
	}
	sess, err := store.Get(context.Background(), jti)
	if err != nil {
		t.Fatalf("session not stored: %v", err)
	}
	if !sess.AuthenticatedAt.Equal(iat) {
		t.Fatalf("AuthenticatedAt = %v, want the registration token iat %v", sess.AuthenticatedAt, iat)
	}

	// A cut-off between the token mint and the session store refuses it.
	users := memory.NewStore().Users()
	uid := domain.NewUserID()
	if err := users.Create(context.Background(), &domain.User{UUID: uid}); err != nil {
		t.Fatal(err)
	}
	if err := users.InvalidateAuthBefore(context.Background(), uid, iat.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tokengate.New(users).Check(context.Background(), uid.String(), sess.authInstant()); !errors.Is(err, tokengate.ErrRevoked) {
		t.Fatalf("session must be refused after a cut-off past the token iat, got %v", err)
	}
}
