package as

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupSessionAuth(t *testing.T) (*TokenIssuer, *MemorySessionStore) {
	t.Helper()

	// Write a temp ECDSA key for the KeyManager.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ec.pem")
	f, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	_ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	f.Close()

	km, err := NewKeyManager(keyPath)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	tokenIssuer := NewTokenIssuer(km, "test-issuer", func(aud string) time.Duration {
		return 5 * time.Minute
	})

	store := NewMemorySessionStore()

	return tokenIssuer, store
}

func TestSessionAuth_NewStyleClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, store := setupSessionAuth(t)
	logger := zap.NewNop()

	// Create a session.
	sess := &Session{
		JTI:       "session-id-123",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC("rw"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Issue an access token.
	accessToken, err := tokenIssuer.Issue("user-1", "test-audience", "tenant-1", TAC("r"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	router := gin.New()
	router.Use(SessionAuthMiddleware(store, tokenIssuer, []string{"test-audience"}, true, logger))
	router.GET("/test", func(c *gin.Context) {
		ac := GetAuthContext(c)
		if ac == nil {
			t.Error("expected AuthContext")
			c.Status(http.StatusInternalServerError)
			return
		}
		if ac.UserID != "user-1" {
			t.Errorf("expected user-1, got %s", ac.UserID)
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "session-id-123"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestSessionAuth_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, store := setupSessionAuth(t)
	logger := zap.NewNop()

	router := gin.New()
	router.Use(SessionAuthMiddleware(store, tokenIssuer, []string{"aud"}, true, logger))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestSessionAuth_SessionButNoAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, store := setupSessionAuth(t)
	logger := zap.NewNop()

	// Create session.
	sess := &Session{
		JTI:       "session-no-at",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	router := gin.New()
	router.Use(SessionAuthMiddleware(store, tokenIssuer, []string{"aud"}, true, logger))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "session-no-at"})
	// No Authorization header.
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// A bearer access token without the session cookie that minted it is not
// enough: there is no cookie-less (HMAC or otherwise) bearer path any more.
func TestSessionAuth_BearerWithoutSessionCookieRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, store := setupSessionAuth(t)
	logger := zap.NewNop()

	token, err := tokenIssuer.Issue("user-1", "aud", "tenant-1", TAC("r"), "urn:siros:acr:passkey")
	require.NoError(t, err)

	router := gin.New()
	router.Use(SessionAuthMiddleware(store, tokenIssuer, []string{"aud"}, true, logger))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestSessionAuth_SessionTokenMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, store := setupSessionAuth(t)
	logger := zap.NewNop()

	// Create a session for user-1.
	sess := &Session{
		JTI:       "session-user1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC("rw"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Issue a valid access token for a DIFFERENT user.
	accessToken, err := tokenIssuer.Issue("user-2", "test-audience", "tenant-1", TAC("r"), "urn:siros:acr:passkey")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	router := gin.New()
	router.Use(SessionAuthMiddleware(store, tokenIssuer, []string{"test-audience"}, true, logger))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "session-user1"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for session/token user mismatch, got %d", w.Code)
	}
}

func TestSessionAuth_TenantMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, store := setupSessionAuth(t)
	logger := zap.NewNop()

	sess := &Session{
		JTI:       "session-tenant1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC("rwl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Create(context.Background(), sess))

	// Issue token for same user but different tenant.
	accessToken, err := tokenIssuer.Issue("user-1", "test-audience", "tenant-2", TAC("r"), "urn:siros:acr:passkey")
	require.NoError(t, err)

	router := gin.New()
	router.Use(SessionAuthMiddleware(store, tokenIssuer, []string{"test-audience"}, true, logger))
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "session-tenant1"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "tenant does not match")
}

func TestSessionAuth_CrossTenantSession_AllowsNarrowedToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, store := setupSessionAuth(t)
	logger := zap.NewNop()

	// Session with cross-tenant scope.
	sess := &Session{
		JTI:       "session-cross",
		UserID:    "admin-1",
		TenantID:  "*",
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC("rwlka"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Create(context.Background(), sess))

	// Token narrowed to specific tenant — should be allowed.
	accessToken, err := tokenIssuer.Issue("admin-1", "test-audience", "tenant-3", TAC("r"), "urn:siros:acr:passkey")
	require.NoError(t, err)

	router := gin.New()
	router.Use(SessionAuthMiddleware(store, tokenIssuer, []string{"test-audience"}, true, logger))
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "session-cross"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSessionAuth_TACExceedsSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, store := setupSessionAuth(t)
	logger := zap.NewNop()

	// Session with limited TAC.
	sess := &Session{
		JTI:       "session-limited",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC("rl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Create(context.Background(), sess))

	// Token with write permission exceeding session's MaxTAC.
	accessToken, err := tokenIssuer.Issue("user-1", "test-audience", "tenant-1", TAC("rw"), "urn:siros:acr:passkey")
	require.NoError(t, err)

	router := gin.New()
	router.Use(SessionAuthMiddleware(store, tokenIssuer, []string{"test-audience"}, true, logger))
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "session-limited"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "exceeds session permissions")
}
