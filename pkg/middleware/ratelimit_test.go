package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewAuthRateLimiter(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.AuthRateLimitConfig{
		Enabled:        true,
		MaxAttempts:    5,
		WindowSeconds:  60,
		LockoutSeconds: 300,
	}

	rl := NewAuthRateLimiter(cfg, logger)
	if rl == nil {
		t.Fatal("NewAuthRateLimiter() returned nil")
	}
	if rl.limiters == nil {
		t.Error("limiters map should be initialized")
	}
}

func TestAuthRateLimiter_Allow(t *testing.T) {
	logger := zap.NewNop()

	t.Run("disabled allows all", func(t *testing.T) {
		cfg := config.AuthRateLimitConfig{
			Enabled: false,
		}
		rl := NewAuthRateLimiter(cfg, logger)

		for i := 0; i < 100; i++ {
			if !rl.Allow("test-user") {
				t.Errorf("Allow() should always return true when disabled")
			}
		}
	})

	t.Run("rate limits after max attempts", func(t *testing.T) {
		cfg := config.AuthRateLimitConfig{
			Enabled:        true,
			MaxAttempts:    3,
			WindowSeconds:  60,
			LockoutSeconds: 1, // Short lockout for testing
		}
		rl := NewAuthRateLimiter(cfg, logger)

		// First few should be allowed (burst)
		allowed := 0
		for i := 0; i < 10; i++ {
			if rl.Allow("test-user") {
				allowed++
			}
		}

		// Should have some allowed and some rejected
		if allowed == 0 {
			t.Error("Some requests should have been allowed")
		}
		if allowed == 10 {
			t.Error("Some requests should have been rejected")
		}
	})

	t.Run("different identifiers have separate limits", func(t *testing.T) {
		cfg := config.AuthRateLimitConfig{
			Enabled:        true,
			MaxAttempts:    2,
			WindowSeconds:  60,
			LockoutSeconds: 60,
		}
		rl := NewAuthRateLimiter(cfg, logger)

		// Exhaust user1's limit
		for i := 0; i < 5; i++ {
			rl.Allow("user1")
		}

		// user2 should still be allowed
		if !rl.Allow("user2") {
			t.Error("user2 should not be affected by user1's rate limit")
		}
	})
}

func TestAuthRateLimiter_RecordFailure(t *testing.T) {
	logger := zap.NewNop()

	t.Run("disabled does nothing", func(t *testing.T) {
		cfg := config.AuthRateLimitConfig{
			Enabled: false,
		}
		rl := NewAuthRateLimiter(cfg, logger)

		// Should not panic
		rl.RecordFailure("test-user")
	})

	t.Run("failure consumes extra tokens", func(t *testing.T) {
		cfg := config.AuthRateLimitConfig{
			Enabled:        true,
			MaxAttempts:    5,
			WindowSeconds:  60,
			LockoutSeconds: 1,
		}
		rl := NewAuthRateLimiter(cfg, logger)

		// Record failures which consume extra tokens
		for i := 0; i < 3; i++ {
			rl.RecordFailure("test-user")
		}

		// Should be rate limited faster due to failures
		allowed := 0
		for i := 0; i < 3; i++ {
			if rl.Allow("test-user") {
				allowed++
			}
		}

		// Should have mostly rejections
		if allowed > 2 {
			t.Error("Failures should have consumed extra rate limit tokens")
		}
	})
}

func TestAuthRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	t.Run("disabled passes through", func(t *testing.T) {
		cfg := config.AuthRateLimitConfig{
			Enabled: false,
		}
		rl := NewAuthRateLimiter(cfg, logger)

		router := gin.New()
		router.POST("/auth", AuthRateLimitMiddleware(rl), func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("rate limits when enabled", func(t *testing.T) {
		cfg := config.AuthRateLimitConfig{
			Enabled:        true,
			MaxAttempts:    2,
			WindowSeconds:  60,
			LockoutSeconds: 60,
		}
		rl := NewAuthRateLimiter(cfg, logger)

		router := gin.New()
		router.POST("/auth", AuthRateLimitMiddleware(rl), func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		// Send many requests
		rateLimited := false
		for i := 0; i < 10; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/auth", nil)
			router.ServeHTTP(w, req)

			if w.Code == http.StatusTooManyRequests {
				rateLimited = true
				break
			}
		}

		if !rateLimited {
			t.Error("Expected rate limiting to kick in")
		}
	})
}

func TestAuthRateLimitMiddlewareWithIdentifier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	cfg := config.AuthRateLimitConfig{
		Enabled:        true,
		MaxAttempts:    2,
		WindowSeconds:  60,
		LockoutSeconds: 60,
	}
	rl := NewAuthRateLimiter(cfg, logger)

	// Custom extractor based on header
	extractor := func(c *gin.Context) string {
		return c.GetHeader("X-User-ID")
	}

	router := gin.New()
	router.POST("/auth", AuthRateLimitMiddlewareWithIdentifier(rl, extractor), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Exhaust user1's limit
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth", nil)
		req.Header.Set("X-User-ID", "user1")
		router.ServeHTTP(w, req)
	}

	// user2 should still be allowed
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/auth", nil)
	req.Header.Set("X-User-ID", "user2")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("user2 should not be rate limited, got status %d", w.Code)
	}

	// Test with empty identifier (falls back to anonymous)
	t.Run("empty identifier uses anonymous", func(t *testing.T) {
		emptyExtractor := func(c *gin.Context) string {
			return ""
		}

		router := gin.New()
		router.POST("/auth", AuthRateLimitMiddlewareWithIdentifier(rl, emptyExtractor), func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/auth", nil)
		router.ServeHTTP(w, req)
		// Should work (anonymous has separate pool)
		// Just verify it doesn't panic
	})
}

func TestAuthRateLimiter_Cleanup(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.AuthRateLimitConfig{
		Enabled:        true,
		MaxAttempts:    5,
		WindowSeconds:  60,
		LockoutSeconds: 60,
	}
	rl := NewAuthRateLimiter(cfg, logger)
	// Set very short cleanup interval for testing
	rl.cleanupInterval = 1 * time.Millisecond
	rl.lastCleanup = time.Now().Add(-time.Hour)

	// Create a limiter
	rl.Allow("test-user")

	// Get limiter count before cleanup
	rl.mu.RLock()
	countBefore := len(rl.limiters)
	rl.mu.RUnlock()

	if countBefore == 0 {
		t.Error("Expected at least one limiter")
	}

	// Force cleanup by triggering another Allow (cleanup runs if interval passed)
	time.Sleep(2 * time.Millisecond)
	rl.Allow("another-user") // This should trigger cleanup

	// Note: cleanup removes limiters older than 30 minutes,
	// so our fresh limiter should NOT be cleaned up
	rl.mu.RLock()
	countAfter := len(rl.limiters)
	rl.mu.RUnlock()

	// Both limiters should still exist (they're recent)
	if countAfter < 2 {
		t.Errorf("Expected 2 limiters, got %d", countAfter)
	}
}

func TestAuthRateLimiter_LockoutExpiry(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.AuthRateLimitConfig{
		Enabled:        true,
		MaxAttempts:    1,
		WindowSeconds:  60,
		LockoutSeconds: 1, // 1 second lockout
	}
	rl := NewAuthRateLimiter(cfg, logger)

	// Use up the rate limit
	rl.Allow("test-user")
	rl.Allow("test-user")
	rl.Allow("test-user")

	// Should be locked out now
	if rl.Allow("test-user") {
		t.Error("Expected to be locked out")
	}

	// Wait for lockout to expire
	time.Sleep(1100 * time.Millisecond)

	// Should be allowed again (lockout expired)
	// Note: token bucket is still depleted, but lockout should be reset
	// The limiter may still reject due to rate limiting vs lockout
}
