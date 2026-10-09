package middleware

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// TokenBlacklistChecker is an interface for checking if a token is
// blacklisted, either individually by jti (e.g. an explicit logout), in
// bulk for every token belonging to a user (e.g. an account deletion, which
// has no way to enumerate every jti it ever issued - see
// TokenBlacklist.RevokeUser), or in bulk for every token in a refresh-token
// family/session (e.g. logging out a session that had a still-valid
// refresh token issued alongside it - see TokenBlacklist.RevokeFamily,
// #402). Shared by both the legacy HMAC path (AuthMiddlewareWithBlacklist)
// and the go-tokenauth path (TokenAuthMiddleware), so a revocation is
// honored regardless of which authenticated the request.
type TokenBlacklistChecker interface {
	IsBlacklisted(ctx context.Context, jti string) bool
	IsUserRevoked(ctx context.Context, userID string) bool
	IsFamilyRevoked(ctx context.Context, sid string) bool
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
	gate := tokengate.New(store.Users())
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

		// Parse and validate the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(cfg.JWT.Secret), nil
		})

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

			// Refresh-token family revocation (#402): rejects an access
			// token whose "sid" claim (see
			// WebAuthnService.generateToken/generateRefreshToken) ties it to
			// a session Logout has since revoked in bulk
			// (TokenBlacklist.RevokeFamily) - even though this specific
			// access token's own jti was never individually blacklisted. A
			// no-op for a token with no sid claim at all (minted before
			// #402, or never paired with a refresh token in the first
			// place - e.g. FinishRegistration).
			if sid, _ := claims["sid"].(string); sid != "" && blacklist.IsFamilyRevoked(c.Request.Context(), sid) {
				logger.Warn("Token for revoked refresh-token family used",
					zap.String("sid", sid),
				)
				c.JSON(401, gin.H{"error": "Token has been revoked"})
				c.Abort()
				return
			}
		}

		// SID-AUTH-06: refuse tokens issued before the wallet was revoked.
		if !checkTokenGate(c, gate, userID, tokengate.IssuedAtFromClaims(claims), logger) {
			return
		}
		// Carried to writes that judge it against the record they load (tokengate.RefuseLoaded).
		c.Request = c.Request.WithContext(tokengate.WithSubject(c.Request.Context(), userID, tokengate.IssuedAtFromClaims(claims)))

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

// checkTokenGate applies the SID-AUTH-06 token cut-off and writes the
// response on refusal. It returns false when the request was aborted.
func checkTokenGate(c *gin.Context, gate *tokengate.Gate, userID string, issuedAt time.Time, logger *zap.Logger) bool {
	err := gate.Check(c.Request.Context(), userID, issuedAt)
	switch {
	case err == nil:
		return true
	case errors.Is(err, tokengate.ErrRevoked):
		logger.Warn("Token issued before authorization cut-off", zap.String("user_id", userID))
		c.JSON(401, gin.H{"error": "Token has been revoked"})
	default:
		logger.Error("Failed to check token authorization cut-off", zap.String("user_id", userID), zap.Error(err))
		c.JSON(500, gin.H{"error": "Internal server error"})
	}
	c.Abort()
	return false
}
