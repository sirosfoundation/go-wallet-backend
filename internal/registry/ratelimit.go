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
)

// RateLimiter manages per-client rate limiting
type RateLimiter struct {
	config RateLimitConfig

	mu      sync.RWMutex
	clients map[string]*clientLimiter

	// cleanupInterval for removing old limiters
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

// clientLimiter holds the rate limiter for a single client
type clientLimiter struct {
	authenticated *rate.Limiter
	anonymous     *rate.Limiter
	lastSeen      time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		config:          config,
		clients:         make(map[string]*clientLimiter),
		cleanupInterval: 10 * time.Minute,
		lastCleanup:     time.Now(),
	}
}

// getLimiter returns the rate limiter for a client
func (r *RateLimiter) getLimiter(clientIP string) *clientLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	limiter, exists := r.clients[clientIP]
	if exists {
		limiter.lastSeen = time.Now()
		return limiter
	}

	// Create new limiter - use ceiling to avoid truncation for low RPM values
	authRate := rate.Limit(float64(r.config.AuthenticatedRPM) / 60.0)
	authBurst := int(math.Ceil(float64(r.config.AuthenticatedRPM) / 60.0 * float64(r.config.BurstMultiplier)))
	if authBurst < 1 {
		authBurst = 1
	}

	anonRate := rate.Limit(float64(r.config.UnauthenticatedRPM) / 60.0)
	anonBurst := int(math.Ceil(float64(r.config.UnauthenticatedRPM) / 60.0 * float64(r.config.BurstMultiplier)))
	if anonBurst < 1 {
		anonBurst = 1
	}

	limiter = &clientLimiter{
		authenticated: rate.NewLimiter(authRate, authBurst),
		anonymous:     rate.NewLimiter(anonRate, anonBurst),
		lastSeen:      time.Now(),
	}
	r.clients[clientIP] = limiter

	// Cleanup old limiters periodically
	if time.Since(r.lastCleanup) > r.cleanupInterval {
		r.cleanup()
	}

	return limiter
}

// cleanup removes limiters that haven't been used in a while
func (r *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-30 * time.Minute)
	for ip, limiter := range r.clients {
		if limiter.lastSeen.Before(cutoff) {
			delete(r.clients, ip)
		}
	}
	r.lastCleanup = time.Now()
}

// Allow checks if a request is allowed based on rate limiting
func (r *RateLimiter) Allow(clientIP string, authenticated bool) bool {
	limiter := r.getLimiter(clientIP)

	if authenticated {
		return limiter.authenticated.Allow()
	}
	return limiter.anonymous.Allow()
}

// RateLimitMiddleware returns a Gin middleware that applies rate limiting
func RateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.config.Enabled {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		authenticated := isAuthenticated(c)

		if !rl.Allow(clientIP, authenticated) {
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
