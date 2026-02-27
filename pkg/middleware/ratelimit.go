// Package middleware provides HTTP middleware for the wallet backend.
package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RateLimitConfig configures the rate limiter.
type RateLimitConfig struct {
	// RequestsPerMinute is the maximum number of requests per minute per user/IP.
	RequestsPerMinute int
	// BurstSize allows temporary bursts above the rate limit.
	BurstSize int
	// CleanupInterval is how often to clean up expired entries.
	CleanupInterval time.Duration
	// Enabled allows disabling rate limiting entirely.
	Enabled bool
}

// DefaultRateLimitConfig returns sensible defaults for rate limiting.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         10,
		CleanupInterval:   5 * time.Minute,
		Enabled:           true,
	}
}

// rateLimitEntry tracks rate limit state for a single client.
type rateLimitEntry struct {
	tokens    float64
	lastCheck time.Time
}

// RateLimiter implements token bucket rate limiting.
type RateLimiter struct {
	cfg     RateLimitConfig
	clients map[string]*rateLimitEntry
	mu      sync.RWMutex
	logger  *zap.Logger
	stopCh  chan struct{}
}

// NewRateLimiter creates a new rate limiter with the given configuration.
func NewRateLimiter(cfg RateLimitConfig, logger *zap.Logger) *RateLimiter {
	rl := &RateLimiter{
		cfg:     cfg,
		clients: make(map[string]*rateLimitEntry),
		logger:  logger.Named("rate-limiter"),
		stopCh:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Stop stops the rate limiter cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// cleanup periodically removes expired entries.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, entry := range rl.clients {
				// Remove entries that haven't been used in 2x the cleanup interval
				if now.Sub(entry.lastCheck) > 2*rl.cfg.CleanupInterval {
					delete(rl.clients, key)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Allow checks if a request from the given key should be allowed.
// Returns true if allowed, false if rate limited.
func (rl *RateLimiter) Allow(key string) bool {
	if !rl.cfg.Enabled {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, exists := rl.clients[key]

	if !exists {
		// New client, start with full bucket
		rl.clients[key] = &rateLimitEntry{
			tokens:    float64(rl.cfg.BurstSize) - 1, // Use one token for this request
			lastCheck: now,
		}
		return true
	}

	// Calculate tokens to add based on time elapsed
	elapsed := now.Sub(entry.lastCheck)
	tokensPerSecond := float64(rl.cfg.RequestsPerMinute) / 60.0
	tokensToAdd := elapsed.Seconds() * tokensPerSecond

	// Update tokens, capped at burst size
	entry.tokens = min(float64(rl.cfg.BurstSize), entry.tokens+tokensToAdd)
	entry.lastCheck = now

	// Check if we have a token to spend
	if entry.tokens >= 1.0 {
		entry.tokens -= 1.0
		return true
	}

	return false
}

// RateLimitMiddleware returns a Gin middleware that rate limits requests.
// It uses the user ID if authenticated, otherwise falls back to client IP.
func RateLimitMiddleware(rl *RateLimiter, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.cfg.Enabled {
			c.Next()
			return
		}

		// Determine the rate limit key
		// Prefer user ID if authenticated, otherwise use IP
		key := c.GetString("user_id")
		if key == "" {
			key = "ip:" + c.ClientIP()
		} else {
			key = "user:" + key
		}

		if !rl.Allow(key) {
			logger.Warn("Rate limit exceeded",
				zap.String("key", key),
				zap.String("path", c.Request.URL.Path),
			)
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": 60,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ProxyRateLimitMiddleware returns a rate limiter specifically for proxy requests.
// Proxy requests typically need stricter limits due to potential for abuse.
func ProxyRateLimitMiddleware(rl *RateLimiter, logger *zap.Logger) gin.HandlerFunc {
	return RateLimitMiddleware(rl, logger)
}
