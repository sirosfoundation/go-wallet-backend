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
	RegisterTokenEndpoint(group, store, issuer, AllowAllPolicy{}, func(aud string) time.Duration { return 2 * time.Minute }, true, logger)

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
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-1"})

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
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-2"})

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
	RegisterTokenEndpoint(group, store, issuer, denyAll, func(aud string) time.Duration { return 2 * time.Minute }, true, logger)

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
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-deny"})

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
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-defaults"})

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
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-no-perms"})

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
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-invalid-tac"})

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
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-no-aud"})

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

func TestTokenEndpoint_CrossTenantDenied(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-tenant",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rwl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	// Try to request a token for a different tenant.
	body, _ := json.Marshal(TokenRequest{Audience: "api", TenantID: "tenant-other", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-tenant"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-tenant session token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_CrossTenantAllowedForWildcard(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	// Cross-tenant session (admin) can issue tokens for any tenant.
	sess := &Session{
		JTI:       "sess-admin",
		UserID:    "admin-1",
		TenantID:  "*",
		MaxTAC:    TAC("rwlida"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "api", TenantID: "any-tenant", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-admin"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for wildcard session, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_AnonymousPriorityOverSession(t *testing.T) {
	router, store, issuer := setupTokenEndpoint(t)

	// Create a session so a session cookie is present. ACR is required -
	// handleAnonymousTokenRequest still requires a real, already-
	// authenticated session; "anonymous" only omits "sub" from the token.
	sess := &Session{
		JTI:       "sess-anon-priority",
		UserID:    "user-123",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rw"),
		ACR:       "urn:siros:acr:passkey",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	// Request with Anonymous=true AND a valid session cookie.
	// Anonymous flag must take priority.
	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-anon-priority"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for anonymous with session cookie, got %d: %s", w.Code, w.Body.String())
	}

	// Parse the issued token and verify it has no subject (anonymous).
	var resp TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	claims, err := issuer.ParseAndVerify(resp.AccessToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "" {
		t.Errorf("expected empty subject for anonymous token, got %q", claims.Subject)
	}
}

// TestTokenEndpoint_AnonymousDefaultsToSessionTenant is a regression test
// for a design change: an anonymous request without an explicit tenant_id
// used to always get "default", regardless of who was asking - because the
// old implementation had no session to fall back to. Now that
// handleAnonymousTokenRequest requires a real session (see
// TestTokenEndpoint_Anonymous_NoSessionDenied), it defaults to that
// session's own tenant instead, exactly like handleSessionTokenRequest -
// the "default" tenant is not given any special treatment.
func TestTokenEndpoint_AnonymousDefaultsToSessionTenant(t *testing.T) {
	router, store, issuer := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-anon-tenant",
		UserID:    "user-1",
		TenantID:  "tenant-acme",
		MaxTAC:    TAC("rwl"),
		ACR:       "urn:siros:acr:passkey",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	// Anonymous request without explicit tenant_id should get the session's
	// own tenant - not "default".
	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-anon-tenant"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	claims, err := issuer.ParseAndVerify(resp.AccessToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if claims.TenantID != "tenant-acme" {
		t.Errorf("expected tenant_id %q (the session's own tenant), got %q", "tenant-acme", claims.TenantID)
	}
	if claims.Subject != "" {
		t.Errorf("expected empty subject (identity-free), got %q", claims.Subject)
	}
}

// TestTokenEndpoint_Anonymous_NoSessionDenied is a regression test for the
// core design fix: "anonymous" means the issued token omits the caller's
// identity, not that no authentication is required at all. A caller with no
// session must be rejected before SPOCP is even consulted.
func TestTokenEndpoint_Anonymous_NoSessionDenied(t *testing.T) {
	router, _, _ := setupTokenEndpoint(t)

	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No session cookie.

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for anonymous request with no session, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTokenEndpoint_Anonymous_NoACRDenied covers a session that somehow has
// no ACR - should be unreachable via any real login flow, but
// handleAnonymousTokenRequest must fail closed rather than mint a token
// with no authentication context behind it at all.
func TestTokenEndpoint_Anonymous_NoACRDenied(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-anon-no-acr",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rwl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		// ACR deliberately left empty.
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-anon-no-acr"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a session with no ACR, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTokenEndpoint_Anonymous_CrossTenantDenied mirrors
// TestTokenEndpoint_CrossTenantDenied for the anonymous path: tenant scoping
// is enforced identically, in code, regardless of whether the issued token
// carries the caller's identity.
func TestTokenEndpoint_Anonymous_CrossTenantDenied(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-anon-cross-tenant",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rwl"),
		ACR:       "urn:siros:acr:passkey",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true, TenantID: "tenant-other", TAC: "r"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-anon-cross-tenant"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for cross-tenant anonymous token, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTokenEndpoint_Anonymous_WriteTACDenied is a regression test: an
// anonymous token must be read-only regardless of what the caller's own
// session MaxTAC would otherwise permit - the point of this path is a
// narrowly-scoped, identity-free token, not "everything my session can do,
// minus my name".
func TestTokenEndpoint_Anonymous_WriteTACDenied(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-anon-write",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("rwlidka"), // full permissions
		ACR:       "urn:siros:acr:passkey",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true, TAC: "w"})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-anon-write"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for anonymous request with tac=w, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTokenEndpoint_Anonymous_InvalidSessionDenied covers a session cookie
// that doesn't resolve to a real session (expired/never existed) - distinct
// from TestTokenEndpoint_Anonymous_NoSessionDenied, which covers no cookie
// at all.
func TestTokenEndpoint_Anonymous_InvalidSessionDenied(t *testing.T) {
	router, _, _ := setupTokenEndpoint(t)

	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-does-not-exist"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a session cookie that doesn't resolve, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTokenEndpoint_Anonymous_EmptyMaxTACDenied covers a session with no
// granted permissions at all - mirrors the equivalent check on the
// authenticated path.
func TestTokenEndpoint_Anonymous_EmptyMaxTACDenied(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-anon-empty-maxtac",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC(""),
		ACR:       "urn:siros:acr:passkey",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-anon-empty-maxtac"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for a session with no granted permissions, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTokenEndpoint_Anonymous_ExceedsSessionMaxTACDenied is distinct from
// TestTokenEndpoint_Anonymous_WriteTACDenied: that test's requested tac
// ("w") fails the read-only cap before session.MaxTAC is even consulted.
// This one requests a tac that passes the read-only cap ("r", the default)
// but still exceeds what this specific session's own MaxTAC ("l" only, no
// "r") permits - a session with only list access can't be used to mint even
// a read-only-scoped anonymous token.
func TestTokenEndpoint_Anonymous_ExceedsSessionMaxTACDenied(t *testing.T) {
	router, store, _ := setupTokenEndpoint(t)

	sess := &Session{
		JTI:       "sess-anon-list-only",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		MaxTAC:    TAC("l"),
		ACR:       "urn:siros:acr:passkey",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	body, _ := json.Marshal(TokenRequest{Audience: "api", Anonymous: true})
	req := httptest.NewRequest(http.MethodPost, "/auth/token", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-anon-list-only"})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for a session whose MaxTAC (l) doesn't include the default anonymous tac (r), got %d: %s", w.Code, w.Body.String())
	}
}
