package as

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestLogoutHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	// Create a session.
	sess := &Session{
		JTI:       "sess-logout",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	_ = store.Create(context.Background(), sess)

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "sess-logout"})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}

	// Session should be revoked.
	s, _ := store.Get(context.Background(), "sess-logout")
	if s == nil {
		t.Fatal("session should still exist (revoked, not deleted)")
	}
	if !s.Revoked {
		t.Error("expected session to be revoked")
	}

	// Cookie should be cleared (MaxAge=-1).
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieInsecure && c.MaxAge < 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected session cookie to be cleared")
	}
}

func TestLogoutHandler_NoSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLogoutHandler_NonexistentSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := NewMemorySessionStore()
	logger := zap.NewNop()

	router := gin.New()
	router.DELETE("/auth/session", LogoutHandler(store, true, logger))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieInsecure, Value: "nonexistent"})
	router.ServeHTTP(w, req)

	// Should still clear the cookie and return 204 (graceful).
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 even for nonexistent session, got %d", w.Code)
	}
}
