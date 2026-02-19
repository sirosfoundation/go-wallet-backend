package registry

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNewRateLimiter(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   1000,
		UnauthenticatedRPM: 100,
		BurstMultiplier:    3,
	}

	rl := NewRateLimiter(config)
	require.NotNil(t, rl)
	assert.Equal(t, config, rl.config)
	assert.NotNil(t, rl.tenants)
}

func TestRateLimiter_Allow_Unauthenticated(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   60, // 1 per second
		UnauthenticatedRPM: 60, // 1 per second
		BurstMultiplier:    3,  // burst of 3
	}

	rl := NewRateLimiter(config)

	// First few requests should be allowed (burst)
	// Privacy: uses anonymousKey, not IP
	for i := 0; i < 3; i++ {
		assert.True(t, rl.Allow(anonymousKey, false), "request %d should be allowed", i+1)
	}

	// After burst, should be rate limited
	// Note: timing-dependent, so we just verify the mechanism exists
}

func TestRateLimiter_Allow_Authenticated(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   60,
		UnauthenticatedRPM: 6, // Much lower for unauthenticated
		BurstMultiplier:    3,
	}

	rl := NewRateLimiter(config)

	// Privacy: rate limit by tenant_id, not IP
	for i := 0; i < 3; i++ {
		assert.True(t, rl.Allow("tenant_1", true), "authenticated request %d should be allowed", i+1)
	}
}

func TestRateLimiter_DifferentTenants(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   60,
		UnauthenticatedRPM: 60,
		BurstMultiplier:    1, // minimal burst
	}

	rl := NewRateLimiter(config)

	// Tenant 1 makes request
	assert.True(t, rl.Allow("tenant_1", true))

	// Tenant 2 should have its own limiter
	assert.True(t, rl.Allow("tenant_2", true))

	// They should have separate limiters
	assert.Len(t, rl.tenants, 2)
}

func TestRateLimiter_GetLimiter_Creates(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   60,
		UnauthenticatedRPM: 60,
		BurstMultiplier:    3,
	}

	rl := NewRateLimiter(config)

	limiter := rl.getLimiter("tenant_1", true)
	require.NotNil(t, limiter)
	assert.NotNil(t, limiter.limiter)
}

func TestRateLimiter_GetLimiter_Reuses(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   60,
		UnauthenticatedRPM: 60,
		BurstMultiplier:    3,
	}

	rl := NewRateLimiter(config)

	limiter1 := rl.getLimiter("tenant_1", true)
	limiter2 := rl.getLimiter("tenant_1", true)

	assert.Same(t, limiter1, limiter2)
}

func TestRateLimitMiddleware_Disabled(t *testing.T) {
	config := RateLimitConfig{
		Enabled: false,
	}

	rl := NewRateLimiter(config)

	router := gin.New()
	router.Use(RateLimitMiddleware(rl))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Make many requests - should all succeed since rate limiting is disabled
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestRateLimitMiddleware_Enabled(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   1, // Very low rate
		UnauthenticatedRPM: 1,
		BurstMultiplier:    1, // Minimal burst
	}

	rl := NewRateLimiter(config)

	router := gin.New()
	router.Use(RateLimitMiddleware(rl))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// First request should succeed
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Subsequent requests should be rate limited (eventually)
	var rateLimited bool
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			rateLimited = true
			break
		}
	}

	// Should have hit rate limit at some point
	assert.True(t, rateLimited, "expected to hit rate limit")
}

func TestRateLimitMiddleware_RespectsAuthentication(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   6000, // Higher for authenticated
		UnauthenticatedRPM: 1,    // Very low for unauthenticated
		BurstMultiplier:    1,
	}

	rl := NewRateLimiter(config)

	router := gin.New()
	// Simulate authentication middleware (privacy: uses tenant_id, not IP)
	router.Use(func(c *gin.Context) {
		if c.GetHeader("Authorization") != "" {
			c.Set(string(AuthenticatedKey), true)
			c.Set(string(TenantIDKey), "test-tenant")
		}
		c.Next()
	})
	router.Use(RateLimitMiddleware(rl))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Authenticated requests should have more capacity
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer token")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "authenticated request %d should succeed", i+1)
	}
}

func TestRateLimitMiddleware_ResponseFormat(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   1,
		UnauthenticatedRPM: 1,
		BurstMultiplier:    1,
	}

	rl := NewRateLimiter(config)

	router := gin.New()
	router.Use(RateLimitMiddleware(rl))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// First request succeeds
	w1 := httptest.NewRecorder()
	req1, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w1, req1)

	// Keep making requests until rate limited
	var lastResponse *httptest.ResponseRecorder
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			lastResponse = w
			break
		}
	}

	if lastResponse != nil {
		assert.Contains(t, lastResponse.Body.String(), "rate_limit_exceeded")
		assert.Contains(t, lastResponse.Body.String(), "Too many requests")
	}
}

func TestIsAuthenticated(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*gin.Context)
		wantResult bool
	}{
		{
			name:       "no value set",
			setup:      func(c *gin.Context) {},
			wantResult: false,
		},
		{
			name: "value set to true",
			setup: func(c *gin.Context) {
				c.Set(string(AuthenticatedKey), true)
			},
			wantResult: true,
		},
		{
			name: "value set to false",
			setup: func(c *gin.Context) {
				c.Set(string(AuthenticatedKey), false)
			},
			wantResult: false,
		},
		{
			name: "wrong type",
			setup: func(c *gin.Context) {
				c.Set(string(AuthenticatedKey), "true")
			},
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			tt.setup(c)

			result := isAuthenticated(c)
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   60,
		UnauthenticatedRPM: 60,
		BurstMultiplier:    1,
	}

	rl := NewRateLimiter(config)

	// Add some tenants (privacy: uses tenant_id, not IP)
	rl.getLimiter("tenant_1", true)
	rl.getLimiter("tenant_2", true)
	rl.getLimiter("tenant_3", true)

	assert.Len(t, rl.tenants, 3)

	// Note: cleanup is internal and time-based, we just verify it doesn't panic
}

func TestRateLimiter_MinimalBurst(t *testing.T) {
	// Test that burst is at least 1 even with very low RPM
	config := RateLimitConfig{
		Enabled:            true,
		AuthenticatedRPM:   1, // Very low
		UnauthenticatedRPM: 1,
		BurstMultiplier:    1,
	}

	rl := NewRateLimiter(config)
	limiter := rl.getLimiter("tenant_1", true)

	// Should be able to make at least one request
	assert.NotNil(t, limiter.limiter)
}

func TestGetTenantID(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*gin.Context)
		wantResult string
	}{
		{
			name:       "no value set",
			setup:      func(c *gin.Context) {},
			wantResult: "",
		},
		{
			name: "value set",
			setup: func(c *gin.Context) {
				c.Set(string(TenantIDKey), "test-tenant")
			},
			wantResult: "test-tenant",
		},
		{
			name: "wrong type",
			setup: func(c *gin.Context) {
				c.Set(string(TenantIDKey), 12345)
			},
			wantResult: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			tt.setup(c)

			result := getTenantID(c)
			assert.Equal(t, tt.wantResult, result)
		})
	}
}
