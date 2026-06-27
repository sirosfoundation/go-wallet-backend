package as

import (
	"bytes"
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
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func setupTokenEndpoint(t *testing.T) (*gin.Engine, *MemorySessionStore, *TokenIssuer) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// Generate signing key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ec.pem")
	f, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	f.Close()

	km, err := NewKeyManager(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewTokenIssuer(km, "test-issuer", func(aud string) time.Duration {
		return 2 * time.Minute
	})

	store := NewMemorySessionStore()
	logger := zap.NewNop()

	router := gin.New()
	group := router.Group("/auth")
	RegisterTokenEndpoint(group, store, issuer, AllowAllPolicy{}, func(aud string) time.Duration { return 2 * time.Minute }, logger)

	return router, store, issuer
}

func TestTokenEndpoint_Success(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC("rwl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "backend-api", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-1"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access_token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("expected Bearer, got %s", resp.TokenType)
	}
	if resp.ExpiresIn != 120 {
		t.Errorf("expected expires_in 120, got %d", resp.ExpiresIn)
	}
}

func TestTokenEndpoint_NoSession(t *testing.T) {
	router, _, _ := setupTokenEndpoint(t)

	body, _ := json.Marshal(TokenRequest{Audience: "api"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestTokenEndpoint_TACExceedsSession(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-2",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	// Request write permission when session only allows read+list.
	body, _ := json.Marshal(TokenRequest{Audience: "api", TAC: "w"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-2"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestTokenEndpoint_PolicyDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Generate signing key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ec.pem")
	f, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	f.Close()

	km, err := NewKeyManager(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	issuer := NewTokenIssuer(km, "test-issuer", func(aud string) time.Duration {
		return 2 * time.Minute
	})

	store := NewMemorySessionStore()
	logger := zap.NewNop()

	// Use a deny-all policy.
	denyAll := &denyAllPolicy{}

	router := gin.New()
	group := router.Group("/auth")
	RegisterTokenEndpoint(group, store, issuer, denyAll, func(aud string) time.Duration { return 2 * time.Minute }, logger)

	sess := &Session{
		JTI:       "sess-deny",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rwl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "api", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-deny"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestTokenEndpoint_DefaultsTenantAndTAC(t *testing.T) {
	router, store, issuer := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-defaults",
		UserID:    "user-1",
		TenantID:  "tenant-default",
		MaxTAC:    TAC("rl"),
		ACR:       "urn:siros:acr:passkey",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	// No tenant_id or tac in request — should use session defaults.
	body, _ := json.Marshal(TokenRequest{Audience: "api"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-defaults"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)

	// Verify the issued token has session defaults.
	claims, err := issuer.ParseAndVerify(resp.AccessToken, []string{"api"})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.TenantID != "tenant-default" {
		t.Errorf("expected tenant_id tenant-default, got %s", claims.TenantID)
	}
	if claims.TAC != TAC("rl") {
		t.Errorf("expected tac rl, got %s", claims.TAC)
	}
}

// denyAllPolicy denies every request.
type denyAllPolicy struct{}

func (denyAllPolicy) Evaluate(_ string) (bool, error) { return false, nil }
func (denyAllPolicy) RuleCount() int                  { return 0 }

func TestTokenEndpoint_EmptyMaxTAC(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	// Session with empty MaxTAC — should deny all token requests.
	sess := &Session{
		JTI:       "sess-no-perms",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC(""),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "api", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-no-perms"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for empty MaxTAC, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_InvalidTAC(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-invalid-tac",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rwlx"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	// Request with invalid character 'x' — should fail validation.
	body, _ := json.Marshal(TokenRequest{Audience: "api", TAC: "x"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-invalid-tac"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid TAC, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_EmptyAudience(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-no-aud",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess-no-aud"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty audience, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Delegation tests ---

func TestTokenEndpoint_Delegation_Success(t *testing.T) {
	router, _, issuer := setupTokenEndpoint(t)

	// Issue a parent token with 'k' (delegate) permission.
	parentToken, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}

	// Request a delegation token with downscoped TAC.
	body, _ := json.Marshal(TokenRequest{Audience: "downstream-api", TAC: "rl"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+parentToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)

	// Verify the delegated token is properly downscoped.
	claims, err := issuer.ParseAndVerify(resp.AccessToken, []string{"downstream-api"})
	if err != nil {
		t.Fatalf("parse delegated token: %v", err)
	}
	if claims.TenantID != "tenant-1" {
		t.Errorf("expected tenant_id tenant-1, got %s", claims.TenantID)
	}
	if claims.TAC != TAC("rl") {
		t.Errorf("expected tac rl, got %s", claims.TAC)
	}
	if claims.Subject != "user-1" {
		t.Errorf("expected subject user-1, got %s", claims.Subject)
	}
}

func TestTokenEndpoint_Delegation_DefaultTACStripsK(t *testing.T) {
	router, _, issuer := setupTokenEndpoint(t)

	parentToken, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}

	// Request with no TAC — should default to parent's TAC minus 'k'.
	body, _ := json.Marshal(TokenRequest{Audience: "api"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+parentToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)

	claims, err := issuer.ParseAndVerify(resp.AccessToken, []string{"api"})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.TAC.Has(TACDelegate) {
		t.Error("default delegated token should not have 'k' permission")
	}
	if claims.TAC != TAC("rwl") {
		t.Errorf("expected tac rwl, got %s", claims.TAC)
	}
}

func TestTokenEndpoint_Delegation_NoKPermission(t *testing.T) {
	router, _, issuer := setupTokenEndpoint(t)

	// Parent token without 'k' — delegation should be denied.
	parentToken, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwl"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(TokenRequest{Audience: "api", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+parentToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_Delegation_TACExceedsParent(t *testing.T) {
	router, _, issuer := setupTokenEndpoint(t)

	// Parent has rwlk, request asks for 'i' which parent doesn't have.
	parentToken, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(TokenRequest{Audience: "api", TAC: "ri"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+parentToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_Delegation_CrossTenantDenied(t *testing.T) {
	router, _, issuer := setupTokenEndpoint(t)

	parentToken, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}

	// Try to delegate to a different tenant.
	body, _ := json.Marshal(TokenRequest{Audience: "api", TenantID: "tenant-2", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+parentToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-tenant delegation, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_Delegation_ReDelegation(t *testing.T) {
	router, _, issuer := setupTokenEndpoint(t)

	// Parent has 'k' — explicitly request 'k' in delegated token (re-delegation).
	parentToken, err := issuer.Issue("user-1", "api", "tenant-1", TAC("rwlk"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(TokenRequest{Audience: "api", TAC: "rk"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+parentToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for re-delegation, got %d: %s", w.Code, w.Body.String())
	}

	var resp TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)

	claims, err := issuer.ParseAndVerify(resp.AccessToken, []string{"api"})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !claims.TAC.Has(TACDelegate) {
		t.Error("re-delegated token should have 'k' permission")
	}
}
