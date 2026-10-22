package as

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDeprecationMiddleware_LegacyClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Simulate that client mode was detected as legacy.
		c.Set(ContextKeyClientMode, ClientModeLegacy)
		c.Next()
	})
	router.Use(DeprecationMiddleware(DeprecationConfig{
		Enabled: true,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if w.Header().Get("Deprecation") != "true" {
		t.Errorf("expected Deprecation: true, got %q", w.Header().Get("Deprecation"))
	}
	if got := w.Header().Get("Sunset"); got != "" {
		t.Errorf("Sunset header must not be sent, got %q", got)
	}
}

func TestDeprecationMiddleware_NewClient(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextKeyClientMode, ClientModeSession)
		c.Next()
	})
	router.Use(DeprecationMiddleware(DeprecationConfig{
		Enabled: true,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if w.Header().Get("Deprecation") != "" {
		t.Error("expected no Deprecation header for new client")
	}
}

func TestDeprecationMiddleware_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ContextKeyClientMode, ClientModeLegacy)
		c.Next()
	})
	router.Use(DeprecationMiddleware(DeprecationConfig{
		Enabled: false,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if w.Header().Get("Deprecation") != "" {
		t.Error("expected no Deprecation header when disabled")
	}
}
