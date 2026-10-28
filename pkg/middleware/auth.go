package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TokenBlacklistChecker is an interface for checking if a token is
// blacklisted, either individually by jti or in bulk for every token of a user (TokenBlacklist.RevokeUser).
type TokenBlacklistChecker interface {
	// IsBlacklisted and IsUserRevoked return an error when the revocation
	// store cannot answer; callers must then refuse the request.
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	IsUserRevoked(ctx context.Context, userID string) (bool, error)
}

// IsAccountDeletion reports whether the request is the account deletion call
// (DELETE /user/session). A user revocation means the deletion has begun, so
// that call stays reachable to a revoked user: a deletion interrupted after
// the revocation was stored (including a write whose acknowledgement was
// lost) can then be completed by retrying, with every other token check
// (signature, jti, family, expiry) still applied.
func IsAccountDeletion(c *gin.Context) bool {
	return c.Request.Method == http.MethodDelete && strings.TrimSuffix(c.FullPath(), "/") == "/user/session"
}

// IsLogout reports whether the request is the session logout call
// (POST /user/session/logout).
//
// Logout is the one call that stays reachable to a token whose own jti is
// already revoked, so that it is an idempotent completion path: a logout whose
// revocation write reported an error may still have been applied (a MongoDB
// write can land before its majority acknowledgement times out), and the jti
// entry is never withdrawn because another request may have completed a
// logout with it. Without this the retry would be rejected as "revoked" and
// the client could not tell a completed logout from a failed one. A revoked
// jti is the only check relaxed:
// signature, expiry, user revocation, tenant and the store-unavailable
// refusal all still apply, and the call only revokes the caller's own
// session, so repeating it is harmless.
func IsLogout(c *gin.Context) bool {
	return c.Request.Method == http.MethodPost && strings.TrimSuffix(c.FullPath(), "/") == "/user/session/logout"
}

type logoutCompletionKey struct{}

// WithLogoutCompletion marks ctx as belonging to a logout call, so a
// revocation checker running inside token validation (which cannot see the
// request) admits a token whose jti is already revoked. See IsLogout.
func WithLogoutCompletion(ctx context.Context) context.Context {
	return context.WithValue(ctx, logoutCompletionKey{}, true)
}

// IsLogoutCompletion reports whether ctx was marked by WithLogoutCompletion.
func IsLogoutCompletion(ctx context.Context) bool {
	v, _ := ctx.Value(logoutCompletionKey{}).(bool)
	return v
}

// RefuseRevocationUnavailable aborts the request with 503 because the
// revocation store could not say whether the token is revoked. Only the
// error is logged, never token content.
func RefuseRevocationUnavailable(c *gin.Context, logger *zap.Logger, err error) {
	logger.Error("Revocation check failed; refusing request",
		zap.Error(err),
		zap.String("method", c.Request.Method),
		zap.String("path", c.FullPath()),
	)
	c.JSON(503, gin.H{"error": "Token revocation check unavailable"})
	c.Abort()
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
