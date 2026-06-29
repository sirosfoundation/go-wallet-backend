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
	"go.uber.org/zap"
)

func setupUnifiedAuth(t *testing.T) (*TokenIssuer, *LegacyTokenIssuer, *MemorySessionStore) {
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

	// Legacy issuer.
	secret := []byte("test-secret-32-bytes-long-value!")
	legacyIssuer := NewLegacyTokenIssuer(secret, "test-issuer", 24*time.Hour)

	store := NewMemorySessionStore()

	return tokenIssuer, legacyIssuer, store
}

func TestUnifiedAuth_NewStyleClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, _, store := setupUnifiedAuth(t)
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
	router.Use(UnifiedAuthMiddleware(store, tokenIssuer, nil, []string{"test-audience"}, logger))
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
		if ac.Mode != ClientModeSession {
			t.Errorf("expected ClientModeSession, got %s", ac.Mode)
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "session-id-123"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestUnifiedAuth_LegacyClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	_, legacyIssuer, store := setupUnifiedAuth(t)
	logger := zap.NewNop()

	// Issue a legacy token.
	token, err := legacyIssuer.Issue("user-2", "did:example:2", "tenant-2", "rp-1")
	if err != nil {
		t.Fatalf("issue legacy token: %v", err)
	}

	// Need a tokenIssuer for new-style path (won't be hit).
	tokenIssuer, _, _ := setupUnifiedAuth(t)

	router := gin.New()
	router.Use(UnifiedAuthMiddleware(store, tokenIssuer, legacyIssuer, []string{"rp-1"}, logger))
	router.GET("/test", func(c *gin.Context) {
		ac := GetAuthContext(c)
		if ac == nil {
			t.Error("expected AuthContext")
			c.Status(http.StatusInternalServerError)
			return
		}
		if ac.UserID != "user-2" {
			t.Errorf("expected user-2, got %s", ac.UserID)
		}
		if ac.Mode != ClientModeLegacy {
			t.Errorf("expected ClientModeLegacy, got %s", ac.Mode)
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestUnifiedAuth_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, legacyIssuer, store := setupUnifiedAuth(t)
	logger := zap.NewNop()

	router := gin.New()
	router.Use(UnifiedAuthMiddleware(store, tokenIssuer, legacyIssuer, []string{"aud"}, logger))
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

func TestUnifiedAuth_SessionButNoAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, _, store := setupUnifiedAuth(t)
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
	router.Use(UnifiedAuthMiddleware(store, tokenIssuer, nil, []string{"aud"}, logger))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "session-no-at"})
	// No Authorization header.
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestUnifiedAuth_LegacyDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, legacyIssuer, store := setupUnifiedAuth(t)
	logger := zap.NewNop()

	// Issue a legacy token but pass nil as legacyIssuer.
	token, _ := legacyIssuer.Issue("user-1", "", "tenant-1", "rp-1")

	router := gin.New()
	router.Use(UnifiedAuthMiddleware(store, tokenIssuer, nil, []string{"aud"}, logger))
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

func TestUnifiedAuth_SessionTokenMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tokenIssuer, _, store := setupUnifiedAuth(t)
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
	router.Use(UnifiedAuthMiddleware(store, tokenIssuer, nil, []string{"test-audience"}, logger))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "session-user1"})
	req.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for session/token user mismatch, got %d", w.Code)
	}
}
