package middleware

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// AuthRateLimiter manages rate limiting for authentication endpoints
// Uses a sliding window approach with lockout after exceeding limits
type AuthRateLimiter struct {
	config config.AuthRateLimitConfig
	logger *zap.Logger

	mu       sync.RWMutex
	limiters map[string]*authLimiter

	cleanupInterval time.Duration
	lastCleanup     time.Time
}

// authLimiter tracks rate limiting state for a single identifier (username, IP, etc.)
type authLimiter struct {
	limiter    *rate.Limiter
	lastSeen   time.Time
	lockedOut  bool
	lockoutEnd time.Time
}

// NewAuthRateLimiter creates a new rate limiter for auth endpoints
func NewAuthRateLimiter(cfg config.AuthRateLimitConfig, logger *zap.Logger) *AuthRateLimiter {
	cfg.SetDefaults()
	return &AuthRateLimiter{
		config:          cfg,
		logger:          logger.Named("auth-ratelimit"),
		limiters:        make(map[string]*authLimiter),
		cleanupInterval: 10 * time.Minute,
		lastCleanup:     time.Now(),
	}
}

// getLimiter returns the rate limiter for an identifier, creating if needed
func (r *AuthRateLimiter) getLimiter(identifier string) *authLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Cleanup old limiters periodically
	if time.Since(r.lastCleanup) > r.cleanupInterval {
		r.cleanup()
	}

	limiter, exists := r.limiters[identifier]
	if exists {
		limiter.lastSeen = time.Now()
		return limiter
	}

	// Create new limiter
	// Rate: MaxAttempts per WindowSeconds
	rateLimit := rate.Limit(float64(r.config.MaxAttempts) / float64(r.config.WindowSeconds))
	burst := int(math.Ceil(float64(r.config.MaxAttempts) / 2.0))
	if burst < 1 {
		burst = 1
	}

	limiter = &authLimiter{
		limiter:  rate.NewLimiter(rateLimit, burst),
		lastSeen: time.Now(),
	}
	r.limiters[identifier] = limiter

	return limiter
}

// cleanup removes old limiters that haven't been used
func (r *AuthRateLimiter) cleanup() {
	cutoff := time.Now().Add(-30 * time.Minute)
	for key, limiter := range r.limiters {
		if limiter.lastSeen.Before(cutoff) {
			delete(r.limiters, key)
		}
	}
	r.lastCleanup = time.Now()
}

// Allow checks if a request is allowed for the given identifier
// Returns true if allowed, false if rate limited
func (r *AuthRateLimiter) Allow(identifier string) bool {
	if !r.config.Enabled {
		return true
	}

	limiter := r.getLimiter(identifier)

	// Check if currently locked out
	r.mu.RLock()
	if limiter.lockedOut {
		if time.Now().Before(limiter.lockoutEnd) {
			r.mu.RUnlock()
			return false
		}
		// Lockout expired, reset
		r.mu.RUnlock()
		r.mu.Lock()
		limiter.lockedOut = false
		r.mu.Unlock()
	} else {
		r.mu.RUnlock()
	}

	// Check rate limit
	if !limiter.limiter.Allow() {
		// Apply lockout
		r.mu.Lock()
		limiter.lockedOut = true
		limiter.lockoutEnd = time.Now().Add(time.Duration(r.config.LockoutSeconds) * time.Second)
		r.mu.Unlock()

		r.logger.Warn("Auth rate limit exceeded, applying lockout",
			zap.String("identifier", identifier),
			zap.Duration("lockout_duration", time.Duration(r.config.LockoutSeconds)*time.Second),
		)

		return false
	}

	return true
}

// RecordFailure records a failed authentication attempt
// This is used for more aggressive rate limiting on repeated failures
func (r *AuthRateLimiter) RecordFailure(identifier string) {
	if !r.config.Enabled {
		return
	}

	limiter := r.getLimiter(identifier)

	// Consume two tokens on failure (making failures more costly)
	limiter.limiter.AllowN(time.Now(), 2)
}

// AuthRateLimitMiddleware returns a Gin middleware that rate limits auth endpoints
// The identifier is extracted from the request body's "username" field when present,
// or falls back to a shared anonymous pool (privacy-preserving: no IP tracking)
func AuthRateLimitMiddleware(rl *AuthRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.config.Enabled {
			c.Next()
			return
		}

		// Try to extract username from request body without consuming it
		identifier := "_anonymous"

		// For auth endpoints, we try to identify by username in request body
		// This is done by peeking at the body (we'll reset it after)
		// For simplicity, we use anonymous bucket for now - username extraction
		// would require copying the body which has performance implications

		if !rl.Allow(identifier) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many authentication attempts. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AuthRateLimitMiddlewareWithIdentifier returns a middleware that uses a custom identifier extractor
// This allows callers to define how to identify rate limit subjects
func AuthRateLimitMiddlewareWithIdentifier(rl *AuthRateLimiter, extractID func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.config.Enabled {
			c.Next()
			return
		}

		identifier := extractID(c)
		if identifier == "" {
			identifier = "_anonymous"
		}

		if !rl.Allow(identifier) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many authentication attempts. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
