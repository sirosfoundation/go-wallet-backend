package middleware

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// OIDCGateRateLimiter rate limits requests to the OIDC gates by client IP and
// by tenant (#65). Build one and share it across the registration and login
// gate groups, so both draw from the same buckets.
type OIDCGateRateLimiter struct {
	perIP         *AuthRateLimiter
	perTenant     *AuthRateLimiter
	retryAfterIP  int
	retryAfterTen int
	logger        *zap.Logger
}

// NewOIDCGateRateLimiter creates the limiter from configuration.
func NewOIDCGateRateLimiter(cfg config.OIDCGateRateLimitConfig, logger *zap.Logger) *OIDCGateRateLimiter {
	cfg.PerIP.SetDefaults()
	cfg.PerTenant.SetDefaults()
	return &OIDCGateRateLimiter{
		perIP:         NewAuthRateLimiter(cfg.PerIP, logger.Named("oidc-gate-ip")),
		perTenant:     NewAuthRateLimiter(cfg.PerTenant, logger.Named("oidc-gate-tenant")),
		retryAfterIP:  cfg.PerIP.LockoutSeconds,
		retryAfterTen: cfg.PerTenant.LockoutSeconds,
		logger:        logger,
	}
}

// Middleware returns the gin middleware. Place it after TenantHeaderMiddleware
// (which sets the tenant) and before OIDCGateMiddleware (whose token
// validation is what it protects). Requests without a bearer token are not
// counted: they are not validated, and an ungated tenant never sends one.
func (l *OIDCGateRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if extractBearer(c) == "" {
			c.Next()
			return
		}

		ip := "ip:" + c.ClientIP()
		tenantKey := "tenant:"
		if tid, ok := GetTenantID(c); ok {
			tenantKey += string(tid)
		}

		// The IP bucket is checked first, so a refused client does not spend
		// from the shared tenant bucket.
		if !l.perIP.Allow(ip) {
			l.reject(c, "ip", l.retryAfterIP)
			return
		}
		if !l.perTenant.Allow(tenantKey) {
			l.reject(c, "tenant", l.retryAfterTen)
			return
		}

		c.Next()

		// A gate that refused the token makes the attempt cost double for
		// that client, so guessing is dearer than valid use.
		if c.IsAborted() && c.Writer.Status() == http.StatusUnauthorized {
			l.perIP.RecordFailure(ip)
		}
	}
}

func (l *OIDCGateRateLimiter) reject(c *gin.Context, bucket string, retryAfter int) {
	l.logger.Warn("OIDC gate rate limit exceeded",
		zap.String("bucket", bucket),
		zap.String("method", c.Request.Method),
		zap.String("path", c.FullPath()),
	)
	c.Header("Retry-After", strconv.Itoa(retryAfter))
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":   "rate_limit_exceeded",
		"message": "Too many authentication attempts. Please try again later.",
	})
	c.Abort()
}
