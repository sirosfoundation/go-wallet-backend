package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNoCacheMiddleware_SetsHeaders(t *testing.T) {
	router := gin.New()
	router.Use(NoCacheMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if got := w.Header().Get("Cache-Control"); got != noCacheControlValue {
		t.Errorf("Cache-Control = %q, want %q", got, noCacheControlValue)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want %q", got, "no-cache")
	}
	if got := w.Header().Get("Expires"); got != "0" {
		t.Errorf("Expires = %q, want %q", got, "0")
	}
}

func TestNoCacheMiddleware_AllowsExplicitOverride(t *testing.T) {
	router := gin.New()
	router.Use(NoCacheMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Header("Cache-Control", "private, max-age=60")
		c.Header("Pragma", "custom")
		c.Header("Expires", "60")
		c.Status(http.StatusNoContent)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if got := w.Header().Get("Cache-Control"); got != "private, max-age=60" {
		t.Errorf("Cache-Control = %q, want override", got)
	}
	if got := w.Header().Get("Pragma"); got != "custom" {
		t.Errorf("Pragma = %q, want override", got)
	}
	if got := w.Header().Get("Expires"); got != "60" {
		t.Errorf("Expires = %q, want override", got)
	}
}
