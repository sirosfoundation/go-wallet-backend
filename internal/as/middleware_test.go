package as

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupMiddlewareTest(t *testing.T) (*MemorySessionStore, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	r := gin.New()
	r.Use(SessionMiddleware(store, logger))
	r.GET("/protected", RequireSession(), func(c *gin.Context) {
		session := GetSession(c)
		c.JSON(http.StatusOK, gin.H{
			"user_id":     session.UserID,
			"tenant_id":   session.TenantID,
			"client_mode": string(GetClientMode(c)),
		})
	})
	r.GET("/optional", func(c *gin.Context) {
		mode := GetClientMode(c)
		c.JSON(http.StatusOK, gin.H{"client_mode": string(mode)})
	})

	return store, r
}

func TestMiddleware_NoSession_LegacyMode(t *testing.T) {
	_, r := setupMiddlewareTest(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/optional", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "legacy")
}

func TestMiddleware_NoSession_ProtectedEndpoint(t *testing.T) {
	_, r := setupMiddlewareTest(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddleware_ValidSession(t *testing.T) {
	store, r := setupMiddlewareTest(t)

	session := &Session{
		JTI:       "valid-session-id",
		UserID:    "user-42",
		TenantID:  "tenant-1",
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC("rwl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	require.NoError(t, store.Create(context.Background(), session))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "valid-session-id"})
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "user-42")
	assert.Contains(t, w.Body.String(), "session")
}

func TestMiddleware_ExpiredSession(t *testing.T) {
	store, r := setupMiddlewareTest(t)

	session := &Session{
		JTI:       "expired-session",
		UserID:    "user-42",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	require.NoError(t, store.Create(context.Background(), session))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "expired-session"})
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "session expired")
}

func TestMiddleware_RevokedSession(t *testing.T) {
	store, r := setupMiddlewareTest(t)

	session := &Session{
		JTI:       "revoked-session",
		UserID:    "user-42",
		ExpiresAt: time.Now().Add(time.Hour),
		Revoked:   true,
	}
	require.NoError(t, store.Create(context.Background(), session))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "revoked-session"})
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMiddleware_UnknownSession(t *testing.T) {
	_, r := setupMiddlewareTest(t)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "does-not-exist"})
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "session not found")
}

func TestCookie_SetAndGet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/set", func(c *gin.Context) {
		SetSessionCookie(c, "test-jti", CookieOptions{
			Secure: true,
			Path:   "/",
			MaxAge: 3600,
		})
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/set", nil)
	r.ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, SessionCookieName, cookies[0].Name)
	assert.Equal(t, "test-jti", cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
	assert.True(t, cookies[0].Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	assert.Equal(t, "/", cookies[0].Path)
	assert.Equal(t, 3600, cookies[0].MaxAge)
}

func TestCookie_Clear(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/clear", func(c *gin.Context) {
		ClearSessionCookie(c, DefaultCookieOptions())
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/clear", nil)
	r.ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, SessionCookieName, cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

func TestGetClientMode_Default(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	assert.Equal(t, ClientModeLegacy, GetClientMode(c))
}
