// Package middleware provides HTTP middleware for the wallet backend.
//
// TokenAuthMiddleware bridges go-tokenauth validation to the context keys
// that existing handlers expect (user_id, did, tenant_id, tenant).
package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// TokenAuthMiddleware validates Bearer tokens using a go-tokenauth validator
// and populates the Gin context with the same keys that legacy AuthMiddleware
// sets, so existing handlers work unchanged.
//
// Context keys set on success:
//
//	"user_id"        (string)           — from claims.Result.UserID
//	"did"            (string)           — from claims.Result.DID
//	"tenant_id"      (string)           — from claims.Result.TenantID
//	"tenant"         (*domain.Tenant)   — looked up from the tenant store
//	"tenant_from_jwt" (bool)           — always true
//	"token"          (string)           — raw Bearer token
//	"tokenauth_result" (*claims.Result) — full validation result
func TokenAuthMiddleware(v *validator.Validator, tenants storage.TenantStore, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract Bearer token
		rawToken := extractBearer(c)
		if rawToken == "" {
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Validate via go-tokenauth (auto-detects new-style vs legacy HMAC)
		result, err := v.Validate(c.Request.Context(), rawToken)
		if err != nil {
			logger.Debug("Token validation failed", zap.Error(err))
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Tenant validation: look up and check enabled
		tenantID := result.TenantID
		if tenantID == "" {
			tenantID = "default"
		}

		tenant, err := tenants.GetByID(c.Request.Context(), domain.TenantID(tenantID))
		if err != nil {
			if err == storage.ErrNotFound {
				logger.Warn("Token contains invalid tenant_id",
					zap.String("tenant_id", tenantID),
					zap.String("mode", string(result.Mode)),
				)
				c.JSON(401, gin.H{"error": "Invalid tenant in token"})
			} else {
				logger.Error("Failed to lookup tenant from token",
					zap.String("tenant_id", tenantID),
					zap.Error(err),
				)
				c.JSON(500, gin.H{"error": "Internal server error"})
			}
			c.Abort()
			return
		}

		if !tenant.Enabled {
			logger.Warn("Token tenant is disabled",
				zap.String("tenant_id", tenantID),
				zap.String("mode", string(result.Mode)),
			)
			c.JSON(403, gin.H{"error": "Tenant is disabled"})
			c.Abort()
			return
		}

		// Log header mismatch (JWT is authoritative)
		if h := c.GetHeader("X-Tenant-ID"); h != "" && h != tenantID {
			logger.Warn("X-Tenant-ID header mismatches token tenant_id — using token (authoritative)",
				zap.String("header_tenant_id", h),
				zap.String("token_tenant_id", tenantID),
			)
		}

		// Populate context keys for existing handlers
		c.Set("user_id", result.UserID)
		c.Set("did", result.DID)
		c.Set("token", rawToken)
		c.Set("tenant_id", tenantID)
		c.Set("tenant", tenant)
		c.Set("tenant_from_jwt", true)
		c.Set("tokenauth_result", result)

		c.Next()
	}
}

// MustHaveTAC returns middleware that requires the token to contain all
// the specified TAC permission characters (e.g. "rw" for read+write).
// Must be placed after TokenAuthMiddleware in the middleware chain.
func MustHaveTAC(required string) gin.HandlerFunc {
	return func(c *gin.Context) {
		v, exists := c.Get("tokenauth_result")
		if !exists {
			c.JSON(401, gin.H{"error": "Not authenticated"})
			c.Abort()
			return
		}
		result, ok := v.(*claims.Result)
		if !ok || result == nil {
			c.JSON(401, gin.H{"error": "Not authenticated"})
			c.Abort()
			return
		}

		if !result.TAC.HasAll(required) {
			c.JSON(403, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// extractBearer extracts the token from the Authorization: Bearer header.
func extractBearer(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
