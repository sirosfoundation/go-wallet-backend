package as

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// mockWebAuthn implements WebAuthnProvider for testing.
type mockWebAuthn struct {
	beginLoginResp  *service.BeginLoginResponse
	beginLoginErr   error
	finishLoginResp *service.FinishLoginResponse
	finishLoginErr  error
	beginRegResp    *service.BeginRegistrationResponse
	beginRegErr     error
	finishRegResp   *service.FinishRegistrationResponse
	finishRegErr    error
}

func (m *mockWebAuthn) BeginLogin(_ context.Context) (*service.BeginLoginResponse, error) {
	return m.beginLoginResp, m.beginLoginErr
}
func (m *mockWebAuthn) FinishLogin(_ context.Context, _ *service.FinishLoginRequest) (*service.FinishLoginResponse, error) {
	return m.finishLoginResp, m.finishLoginErr
}
func (m *mockWebAuthn) BeginRegistration(_ context.Context, _ *service.BeginRegistrationRequest) (*service.BeginRegistrationResponse, error) {
	return m.beginRegResp, m.beginRegErr
}
func (m *mockWebAuthn) FinishRegistration(_ context.Context, _ *service.FinishRegistrationRequest) (*service.FinishRegistrationResponse, error) {
	return m.finishRegResp, m.finishRegErr
}

func setupPasskeyHandlers(mock *mockWebAuthn) (*gin.Engine, *MemorySessionStore) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	cfg := &config.ASConfig{
		DefaultMaxTAC:   "rwl",
		SessionTTL:      24 * time.Hour,
		InsecureCookies: true,
	}
	logger := zap.NewNop()

	h := NewPasskeyHandlers(mock, store, nil, cfg, logger)

	router := gin.New()
	router.POST("/auth/passkey/login/begin", h.LoginBegin)
	router.POST("/auth/passkey/login/finish", h.LoginFinish)
	router.POST("/auth/passkey/register/begin", h.RegisterBegin)
	router.POST("/auth/passkey/register/finish", h.RegisterFinish)

	return router, store
}

func TestPasskeyLoginBegin_Success(t *testing.T) {
	mock := &mockWebAuthn{
		beginLoginResp: &service.BeginLoginResponse{
			ChallengeID: "challenge-123",
		},
	}
	router, _ := setupPasskeyHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasskeyLoginBegin_Error(t *testing.T) {
	mock := &mockWebAuthn{
		beginLoginErr: fmt.Errorf("webauthn unavailable"),
	}
	router, _ := setupPasskeyHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/begin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestPasskeyLoginFinish_Success(t *testing.T) {
	mock := &mockWebAuthn{
		finishLoginResp: &service.FinishLoginResponse{
			UUID:              "user-123",
			DisplayName:       "Test User",
			TenantID:          "tenant-1",
			TenantDisplayName: "Tenant One",
		},
	}
	router, store := setupPasskeyHandlers(mock)

	body, _ := json.Marshal(service.FinishLoginRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Token-Mode", "session")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify session was created.
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["uuid"] != "user-123" {
		t.Errorf("expected uuid user-123, got %v", resp["uuid"])
	}
	if resp["tenantDisplayName"] != "Tenant One" {
		t.Errorf("expected tenantDisplayName 'Tenant One', got %v", resp["tenantDisplayName"])
	}

	// Verify cookie was set.
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieInsecure {
			found = true
			// Verify session exists in store.
			sess, _ := store.Get(context.Background(), c.Value)
			if sess == nil {
				t.Error("session not found in store")
			} else {
				if sess.UserID != "user-123" {
					t.Errorf("session user_id = %s, want user-123", sess.UserID)
				}
				if sess.TenantID != "tenant-1" {
					t.Errorf("session tenant_id = %s, want tenant-1", sess.TenantID)
				}
				if sess.ACR != "urn:siros:acr:passkey" {
					t.Errorf("session acr = %s, want urn:siros:acr:passkey", sess.ACR)
				}
				if sess.MaxTAC != TAC("rwl") {
					t.Errorf("session max_tac = %s, want rwl", sess.MaxTAC)
				}
			}
		}
	}
	if !found {
		t.Error("session cookie not set")
	}
}

func TestPasskeyLoginFinish_AuthError(t *testing.T) {
	mock := &mockWebAuthn{
		finishLoginErr: fmt.Errorf("credential invalid"),
	}
	router, _ := setupPasskeyHandlers(mock)

	body, _ := json.Marshal(service.FinishLoginRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestPasskeyLoginFinish_BadRequest(t *testing.T) {
	mock := &mockWebAuthn{}
	router, _ := setupPasskeyHandlers(mock)

	// Invalid JSON body.
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestPasskeyLoginFinish_LegacyMode(t *testing.T) {
	mock := &mockWebAuthn{
		finishLoginResp: &service.FinishLoginResponse{
			UUID:        "user-legacy",
			DisplayName: "Legacy User",
			TenantID:    "tenant-1",
			Token:       "legacy-token-value",
		},
	}
	router, _ := setupPasskeyHandlers(mock)

	body, _ := json.Marshal(service.FinishLoginRequest{ChallengeID: "c2"})
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No X-Token-Mode header → legacy mode.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Legacy mode returns the full response including appToken.
	var resp map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["appToken"] != "legacy-token-value" {
		t.Errorf("expected appToken in legacy response, got %v", resp["appToken"])
	}
}

func TestPasskeyRegisterBegin_Success(t *testing.T) {
	mock := &mockWebAuthn{
		beginRegResp: &service.BeginRegistrationResponse{
			ChallengeID: "reg-challenge-1",
		},
	}
	router, _ := setupPasskeyHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasskeyRegisterBegin_Error(t *testing.T) {
	mock := &mockWebAuthn{
		beginRegErr: fmt.Errorf("service error"),
	}
	router, _ := setupPasskeyHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/begin", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestPasskeyRegisterFinish_Success(t *testing.T) {
	mock := &mockWebAuthn{
		finishRegResp: &service.FinishRegistrationResponse{
			UUID:              "new-user-1",
			DisplayName:       "New User",
			TenantID:          "tenant-reg",
			TenantDisplayName: "Tenant Reg",
		},
	}
	router, store := setupPasskeyHandlers(mock)

	body, _ := json.Marshal(service.FinishRegistrationRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Token-Mode", "session")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify session was created (auto-login).
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == sessionCookieInsecure {
			sess, _ := store.Get(context.Background(), c.Value)
			if sess == nil {
				t.Error("session not found after registration")
			} else if sess.UserID != "new-user-1" {
				t.Errorf("session user_id = %s, want new-user-1", sess.UserID)
			}
		}
	}
}

func TestPasskeyRegisterFinish_Error(t *testing.T) {
	mock := &mockWebAuthn{
		finishRegErr: fmt.Errorf("registration failed: duplicate credential"),
	}
	router, _ := setupPasskeyHandlers(mock)

	body, _ := json.Marshal(service.FinishRegistrationRequest{ChallengeID: "c1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestPasskeyRegisterFinish_BadRequest(t *testing.T) {
	mock := &mockWebAuthn{}
	router, _ := setupPasskeyHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/auth/passkey/register/finish", bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
