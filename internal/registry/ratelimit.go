package registry

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// contextKey is used for type-safe context keys
type contextKey string

const (
	// AuthenticatedKey is the context key for authentication status
	AuthenticatedKey contextKey = "authenticated"
	// TenantIDKey is the context key for tenant ID from JWT
	TenantIDKey contextKey = "tenant_id"
	// anonymousKey is used for rate limiting anonymous requests (privacy: no IP tracking)
	anonymousKey = "_anonymous"
)

// RateLimiter manages per-tenant rate limiting (privacy: no IP tracking)
type RateLimiter struct {
	config RateLimitConfig

	mu      sync.RWMutex
	tenants map[string]*tenantLimiter

	// cleanupInterval for removing old limiters
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

// tenantLimiter holds the rate limiter for a single tenant
type tenantLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		config:          config,
		tenants:         make(map[string]*tenantLimiter),
		cleanupInterval: 10 * time.Minute,
		lastCleanup:     time.Now(),
	}
}

// getLimiter returns the rate limiter for a tenant (or anonymous pool)
func (r *RateLimiter) getLimiter(tenantKey string, authenticated bool) *tenantLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Cleanup old limiters periodically (before checking if tenant exists,
	// so cleanup runs even when existing tenants are making requests)
	if time.Since(r.lastCleanup) > r.cleanupInterval {
		r.cleanup()
	}

	limiter, exists := r.tenants[tenantKey]
	if exists {
		limiter.lastSeen = time.Now()
		return limiter
	}

	// Create new limiter - use ceiling to avoid truncation for low RPM values
	var rateLimit rate.Limit
	var burst int

	if authenticated {
		rateLimit = rate.Limit(float64(r.config.AuthenticatedRPM) / 60.0)
		burst = int(math.Ceil(float64(r.config.AuthenticatedRPM) / 60.0 * float64(r.config.BurstMultiplier)))
	} else {
		rateLimit = rate.Limit(float64(r.config.UnauthenticatedRPM) / 60.0)
		burst = int(math.Ceil(float64(r.config.UnauthenticatedRPM) / 60.0 * float64(r.config.BurstMultiplier)))
	}
	if burst < 1 {
		burst = 1
	}

	limiter = &tenantLimiter{
		limiter:  rate.NewLimiter(rateLimit, burst),
		lastSeen: time.Now(),
	}
	r.tenants[tenantKey] = limiter

	return limiter
}

// cleanup removes limiters that haven't been used in a while
func (r *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-30 * time.Minute)
	for key, limiter := range r.tenants {
		if limiter.lastSeen.Before(cutoff) {
			delete(r.tenants, key)
		}
	}
	r.lastCleanup = time.Now()
}

// Allow checks if a request is allowed based on rate limiting
// Uses tenant_id for authenticated requests (privacy: no IP tracking)
func (r *RateLimiter) Allow(tenantKey string, authenticated bool) bool {
	limiter := r.getLimiter(tenantKey, authenticated)
	return limiter.limiter.Allow()
}

// RateLimitMiddleware returns a Gin middleware that applies rate limiting
// Uses tenant_id from JWT for authenticated requests (privacy: no IP tracking)
func RateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.config.Enabled {
			c.Next()
			return
		}

		authenticated := isAuthenticated(c)
		tenantKey := anonymousKey

		// For authenticated requests, use tenant_id from JWT (privacy: no IP tracking)
		if authenticated {
			if tid := getTenantID(c); tid != "" {
				tenantKey = tid
			}
		}

		if !rl.Allow(tenantKey, authenticated) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// isAuthenticated checks if the request is authenticated
func isAuthenticated(c *gin.Context) bool {
	val, exists := c.Get(string(AuthenticatedKey))
	if !exists {
		return false
	}
	authenticated, ok := val.(bool)
	return ok && authenticated
}

// getTenantID extracts tenant_id from context (set by JWT middleware)
func getTenantID(c *gin.Context) string {
	val, exists := c.Get(string(TenantIDKey))
	if !exists {
		return ""
	}
	tid, ok := val.(string)
	if !ok {
		return ""
	}
	return tid
}
