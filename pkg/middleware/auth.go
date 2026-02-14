package middleware

import (
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
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(401, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		providedToken := strings.TrimSpace(parts[1])
		if providedToken == "" {
			c.JSON(401, gin.H{"error": "Token required"})
			c.Abort()
			return
		}

		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) != 1 {
			logger.Warn("Invalid admin token attempt", zap.String("ip", c.ClientIP()))
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AuthMiddleware validates JWT tokens and sets user context.
// It validates the tenant from the JWT exists and is enabled.
// The JWT tenant_id claim is authoritative; X-Tenant-ID header is logged if mismatched.
func AuthMiddleware(cfg *config.Config, store storage.Store, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(401, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := strings.TrimSpace(parts[1])
		if tokenString == "" {
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
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Get user_id from claims
		userID, ok := claims["user_id"].(string)
		if !ok {
			c.JSON(401, gin.H{"error": "Invalid user ID in token"})
			c.Abort()
			return
		}

		// Get did from claims
		did, _ := claims["did"].(string)

		// Get tenant_id from claims (defaults to "default" for backward compatibility)
		tenantID, _ := claims["tenant_id"].(string)
		if tenantID == "" {
			tenantID = "default"
		}

		// Validate tenant exists and is enabled
		tenant, err := store.Tenants().GetByID(c.Request.Context(), domain.TenantID(tenantID))
		if err != nil {
			if err == storage.ErrNotFound {
				logger.Warn("JWT contains invalid tenant_id",
					zap.String("tenant_id", tenantID),
					zap.String("user_id", userID))
				c.JSON(401, gin.H{"error": "Invalid tenant in token"})
			} else {
				logger.Error("Failed to lookup tenant from JWT", zap.Error(err))
				c.JSON(500, gin.H{"error": "Failed to validate tenant"})
			}
			c.Abort()
			return
		}

		if !tenant.Enabled {
			logger.Warn("JWT tenant is disabled",
				zap.String("tenant_id", tenantID),
				zap.String("user_id", userID))
			c.JSON(403, gin.H{"error": "Tenant is disabled"})
			c.Abort()
			return
		}

		// Check X-Tenant-ID header against JWT tenant_id (JWT is authoritative)
		headerTenantID := c.GetHeader("X-Tenant-ID")
		if headerTenantID != "" && headerTenantID != tenantID {
			logger.Warn("X-Tenant-ID header does not match JWT tenant_id",
				zap.String("header_tenant", headerTenantID),
				zap.String("jwt_tenant", tenantID),
				zap.String("user_id", userID),
				zap.String("path", c.Request.URL.Path))
			// JWT is authoritative - continue with JWT tenant but log the mismatch
		}

		c.Set("user_id", userID)
		c.Set("did", did)
		c.Set("tenant_id", tenantID)
		c.Set("tenant", tenant)
		c.Set("token", tokenString)

		c.Next()
	}
}

// Logger returns a gin middleware for logging
func Logger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := c.Request.Context()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		logger.Info("Request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.Int("status", c.Writer.Status()),
			zap.String("ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		)

		_ = start // Use the variable
	}
}
