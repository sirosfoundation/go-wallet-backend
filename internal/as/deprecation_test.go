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
		Enabled:    true,
		SunsetDate: "2027-10-01T00:00:00Z",
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
	sunset := w.Header().Get("Sunset")
	if sunset == "" {
		t.Fatal("expected Sunset header")
	}
	// Should be HTTP-date format.
	if sunset != "Fri, 01 Oct 2027 00:00:00 GMT" {
		t.Errorf("unexpected Sunset value: %s", sunset)
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
		Enabled:    true,
		SunsetDate: "2027-10-01T00:00:00Z",
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
