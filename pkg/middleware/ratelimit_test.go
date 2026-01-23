package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func TestRateLimiter_Allow(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name              string
		requestsPerMinute int
		burstSize         int
		requests          int
		wantAllowed       int
	}{
		{
			name:              "allows up to burst size",
			requestsPerMinute: 60,
			burstSize:         5,
			requests:          5,
			wantAllowed:       5,
		},
		{
			name:              "blocks after burst exceeded",
			requestsPerMinute: 60,
			burstSize:         3,
			requests:          5,
			wantAllowed:       3,
		},
		{
			name:              "single request allowed",
			requestsPerMinute: 60,
			burstSize:         10,
			requests:          1,
			wantAllowed:       1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := RateLimitConfig{
				RequestsPerMinute: tt.requestsPerMinute,
				BurstSize:         tt.burstSize,
				CleanupInterval:   time.Minute,
				Enabled:           true,
			}
			rl := NewRateLimiter(cfg, logger)
			defer rl.Stop()

			allowed := 0
			for i := 0; i < tt.requests; i++ {
				if rl.Allow("test-key") {
					allowed++
				}
			}

			if allowed != tt.wantAllowed {
				t.Errorf("Allow() allowed %d requests, want %d", allowed, tt.wantAllowed)
			}
		})
	}
}

func TestRateLimiter_Disabled(t *testing.T) {
	logger := zap.NewNop()

	cfg := RateLimitConfig{
		RequestsPerMinute: 1,
		BurstSize:         1,
		CleanupInterval:   time.Minute,
		Enabled:           false, // Disabled
	}
	rl := NewRateLimiter(cfg, logger)
	defer rl.Stop()

	// All requests should be allowed when disabled
	for i := 0; i < 100; i++ {
		if !rl.Allow("test-key") {
			t.Error("Allow() should always return true when disabled")
		}
	}
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	logger := zap.NewNop()

	cfg := RateLimitConfig{
		RequestsPerMinute: 600, // 10 per second
		BurstSize:         1,
		CleanupInterval:   time.Minute,
		Enabled:           true,
	}
	rl := NewRateLimiter(cfg, logger)
	defer rl.Stop()

	// Use the single token
	if !rl.Allow("test-key") {
		t.Error("First request should be allowed")
	}

	// Should be blocked immediately
	if rl.Allow("test-key") {
		t.Error("Second request should be blocked")
	}

	// Wait for token refill (100ms = 1 token at 10/sec)
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	if !rl.Allow("test-key") {
		t.Error("Request after refill should be allowed")
	}
}

func TestRateLimiter_MultipleKeys(t *testing.T) {
	logger := zap.NewNop()

	cfg := RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         2,
		CleanupInterval:   time.Minute,
		Enabled:           true,
	}
	rl := NewRateLimiter(cfg, logger)
	defer rl.Stop()

	// Each key should have independent limits
	for i := 0; i < 2; i++ {
		if !rl.Allow("key-1") {
			t.Errorf("key-1 request %d should be allowed", i+1)
		}
		if !rl.Allow("key-2") {
			t.Errorf("key-2 request %d should be allowed", i+1)
		}
	}

	// Both should now be blocked
	if rl.Allow("key-1") {
		t.Error("key-1 should be blocked after burst")
	}
	if rl.Allow("key-2") {
		t.Error("key-2 should be blocked after burst")
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	logger := zap.NewNop()

	cfg := RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         100,
		CleanupInterval:   time.Minute,
		Enabled:           true,
	}
	rl := NewRateLimiter(cfg, logger)
	defer rl.Stop()

	var wg sync.WaitGroup
	allowed := int32(0)
	var mu sync.Mutex

	// 100 concurrent requests
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("concurrent-key") {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Should allow exactly burst size
	if allowed != 100 {
		t.Errorf("Concurrent test: allowed %d, want 100", allowed)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	cfg := RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         2,
		CleanupInterval:   time.Minute,
		Enabled:           true,
	}
	rl := NewRateLimiter(cfg, logger)
	defer rl.Stop()

	router := gin.New()
	router.Use(RateLimitMiddleware(rl, logger))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: got status %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Third request: got status %d, want %d", w.Code, http.StatusTooManyRequests)
	}

	// Check Retry-After header
	if w.Header().Get("Retry-After") == "" {
		t.Error("Missing Retry-After header")
	}
}
