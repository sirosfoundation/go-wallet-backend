package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// TokenBlacklistChecker is an interface for checking if a token is
// blacklisted, either individually by jti (e.g. an explicit logout) or in
// bulk for every token belonging to a user (e.g. an account deletion, which
// has no way to enumerate every jti it ever issued - see
// TokenBlacklist.RevokeUser). Shared by both the legacy HMAC path
// (AuthMiddlewareWithBlacklist) and the go-tokenauth path
// (TokenAuthMiddleware), so a revocation is honored regardless of which
// authenticated the request.
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

// AuthMiddleware validates JWT tokens, validates tenant, and sets user/tenant context.
// The JWT tenant_id claim is authoritative for authenticated requests.
// If X-Tenant-ID header is provided and differs from JWT, a warning is logged but JWT wins.
func AuthMiddleware(cfg *config.Config, store storage.Store, logger *zap.Logger) gin.HandlerFunc {
	return AuthMiddlewareWithBlacklist(cfg, store, nil, logger)
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

// AuthMiddlewareWithBlacklist is like AuthMiddleware but also checks for blacklisted tokens.
func AuthMiddlewareWithBlacklist(cfg *config.Config, store storage.Store, blacklist TokenBlacklistChecker, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// This path only understands HMAC tokens: with as.legacy.enabled=false
		// nothing can validate here (fail closed).
		if !cfg.LegacyEnabled() {
			logAuthReject(logger, c, "legacy_tokens_disabled")
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logAuthReject(logger, c, "missing_authorization_header")
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			logAuthReject(logger, c, "malformed_authorization_header")
			c.JSON(401, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := strings.TrimSpace(parts[1])
		if tokenString == "" {
			logAuthReject(logger, c, "empty_bearer_token")
			c.JSON(401, gin.H{"error": "Token required"})
			c.Abort()
			return
		}

		// Legacy HMAC tokens are all minted with iss = jwt.issuer; pin it so a
		// token signed with the shared secret but carrying a missing or
		// different issuer is refused. An empty jwt.issuer would disable the
		// check (golang-jwt treats "" as "no expectation"), so fail closed.
		if cfg.JWT.Issuer == "" {
			logAuthReject(logger, c, "jwt_issuer_not_configured")
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Parse and validate the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(cfg.JWT.Secret), nil
		}, jwt.WithIssuer(cfg.JWT.Issuer))

		if err != nil || !token.Valid {
			logAuthReject(logger, c, "invalid_token", zap.Error(err))
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			logAuthReject(logger, c, "invalid_token_claims")
			c.JSON(401, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Get user_id from claims
		userID, ok := claims["user_id"].(string)
		if !ok {
			logAuthReject(logger, c, "missing_user_id_claim")
			c.JSON(401, gin.H{"error": "Invalid user ID in token"})
			c.Abort()
			return
		}

		// Check if the token is blacklisted (if a checker is configured) -
		// either individually by jti (explicit logout) or in bulk for every
		// token belonging to this user (account deletion - see
		// TokenBlacklist.RevokeUser). Without this second check, deleting a
		// user would only invalidate the one token used to request the
		// deletion, leaving any other still-valid token for that user usable
		// until it naturally expires (#383).
		if blacklist != nil {
			jti, _ := claims["jti"].(string)
			if jti != "" && blacklist.IsBlacklisted(c.Request.Context(), jti) {
				logger.Warn("Blacklisted token used",
					zap.String("jti", jti),
				)
				c.JSON(401, gin.H{"error": "Token has been revoked"})
				c.Abort()
				return
			}

			if blacklist.IsUserRevoked(c.Request.Context(), userID) {
				logger.Warn("Token for revoked user used",
					zap.String("user_id", userID),
				)
				c.JSON(401, gin.H{"error": "Token has been revoked"})
				c.Abort()
				return
			}
		}

		// Get did from claims
		did, _ := claims["did"].(string)

		// Get tenant_id from claims (required for security boundary)
		// This is the authoritative source for tenant on authenticated requests
		tenantID, _ := claims["tenant_id"].(string)
		if tenantID == "" {
			// For backward compatibility with older tokens, default to "default"
			tenantID = "default"
		}

		// Validate tenant exists and is enabled
		tenant, err := store.Tenants().GetByID(c.Request.Context(), domain.TenantID(tenantID))
		if err != nil {
			if err == storage.ErrNotFound {
				logger.Warn("JWT contains invalid tenant_id",
					zap.String("tenant_id", tenantID),
				)
				c.JSON(401, gin.H{"error": "Invalid tenant in token"})
			} else {
				logger.Error("Failed to lookup tenant from JWT",
					zap.String("tenant_id", tenantID),
					zap.Error(err),
				)
				c.JSON(500, gin.H{"error": "Internal server error"})
			}
			c.Abort()
			return
		}

		if !tenant.Enabled {
			logger.Warn("JWT tenant is disabled",
				zap.String("tenant_id", tenantID),
			)
			c.JSON(403, gin.H{"error": "Tenant is disabled"})
			c.Abort()
			return
		}

		// Check if X-Tenant-ID header was provided and log if it mismatches JWT
		headerTenantID := c.GetHeader("X-Tenant-ID")
		if headerTenantID != "" && headerTenantID != tenantID {
			logger.Warn("X-Tenant-ID header mismatches JWT tenant_id - using JWT (authoritative)",
				zap.String("header_tenant_id", headerTenantID),
				zap.String("jwt_tenant_id", tenantID),
			)
		}

		// user_id/did are only set when non-empty — see the matching comment
		// in TokenAuthMiddleware for why (an always-true c.Set makes the
		// common `val, exists := c.Get(...)` idiom unable to tell "no
		// identity" apart from "identity is the empty string").
		if userID != "" {
			c.Set("user_id", userID)
		}
		if did != "" {
			c.Set("did", did)
		}
		c.Set("token", tokenString)
		c.Set("tenant_id", tenantID)   // Set tenant from JWT for security
		c.Set("tenant", tenant)        // Set full tenant object for handlers
		c.Set("tenant_from_jwt", true) // Flag to indicate this came from JWT (authoritative)

		c.Next()
	}
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
