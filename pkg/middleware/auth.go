package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TokenBlacklistChecker is an interface for checking if a token is
// blacklisted, either individually by jti or in bulk for every token of a user (TokenBlacklist.RevokeUser).
type TokenBlacklistChecker interface {
	IsBlacklisted(ctx context.Context, jti string) bool
	IsUserRevoked(ctx context.Context, userID string) bool
}

// GenerateAdminToken generates a secure random token for admin API authentication
func GenerateAdminToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// AdminAuthMiddleware validates bearer tokens for the admin API
func AdminAuthMiddleware(token string, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logAuthReject(logger, c, "missing_authorization_header")
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			logAuthReject(logger, c, "malformed_authorization_header")
			c.JSON(401, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		providedToken := strings.TrimSpace(parts[1])
		if providedToken == "" {
			logAuthReject(logger, c, "empty_bearer_token")
			c.JSON(401, gin.H{"error": "Token required"})
			c.Abort()
			return
		}

		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
			logAuthReject(logger, c, "invalid_admin_token")
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// logAuthReject records why a request was refused by an authentication
// middleware. Rejections used to be visible only as a JSON body on the
// client, which is unreachable when debugging wrapper apps or platforms
// without client-side request logs (#301). Never pass the token itself.
func logAuthReject(logger *zap.Logger, c *gin.Context, reason string, fields ...zap.Field) {
	base := []zap.Field{
		zap.String("reason", reason),
		zap.String("method", c.Request.Method),
		zap.String("path", c.FullPath()),
		zap.String("client_ip", c.ClientIP()),
	}
	logger.Warn("Authentication rejected", append(base, fields...)...)
}

// Logger returns a gin middleware for logging with optional path exclusions.
// Paths in skipPaths (e.g., "/status") will not be logged.
func Logger(logger *zap.Logger, skipPaths ...string) gin.HandlerFunc {
	skipSet := make(map[string]bool)
	for _, p := range skipPaths {
		skipSet[p] = true
	}

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		c.Next()

		// Skip logging for specified paths
		if skipSet[path] {
			return
		}

		logger.Info("Request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", c.Request.URL.RawQuery),
			zap.Int("status", c.Writer.Status()),
		)
	}
}
