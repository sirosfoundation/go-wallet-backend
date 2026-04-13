package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestPrometheus_RecordsMetrics(t *testing.T) {
	router := gin.New()
	router.Use(Prometheus())
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestPrometheus_SkipPath(t *testing.T) {
	router := gin.New()
	router.Use(Prometheus("/healthz"))
	router.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/api", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Skipped path should still serve normally but not record metrics
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthz", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Non-skipped path should also work
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestPrometheus_UnmatchedPath(t *testing.T) {
	router := gin.New()
	router.Use(Prometheus())
	// No routes registered — any path should be "unmatched"

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	router.ServeHTTP(w, req)

	// Gin returns 404 for unmatched routes
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPrometheus_MultipleStatusCodes(t *testing.T) {
	router := gin.New()
	router.Use(Prometheus())
	router.POST("/items", func(c *gin.Context) {
		c.String(http.StatusCreated, "created")
	})
	router.GET("/fail", func(c *gin.Context) {
		c.String(http.StatusInternalServerError, "err")
	})

	// 201
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/items", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// 500
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/fail", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}
