package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// TenantHeaderMiddleware extracts the tenant from X-Tenant-ID header and validates it.
// This is used for unauthenticated requests where tenant context is needed (e.g., login begin).
// For authenticated requests, the JWT tenant_id claim is authoritative (set by AuthMiddleware).
func TenantHeaderMiddleware(store storage.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr := c.GetHeader("X-Tenant-ID")
		if tenantIDStr == "" {
			// Default to "default" tenant for backwards compatibility with single-tenant deployments
			tenantIDStr = "default"
		}

		tenantID := domain.TenantID(tenantIDStr)

		// Validate tenant exists
		tenant, err := store.Tenants().GetByID(c.Request.Context(), tenantID)
		if err != nil {
			if err == storage.ErrNotFound {
				c.JSON(404, gin.H{"error": "tenant not found"})
			} else {
				c.JSON(500, gin.H{"error": "failed to lookup tenant"})
			}
			c.Abort()
			return
		}

		// Validate tenant is enabled
		if !tenant.Enabled {
			c.JSON(403, gin.H{"error": "tenant is disabled"})
			c.Abort()
			return
		}

		// Set tenant context (can be overridden by AuthMiddleware if JWT has tenant_id)
		c.Set("tenant_id", tenantID)
		c.Set("tenant", tenant)
		c.Next()
	}
}

// TenantMembershipMiddleware verifies the user is a member of the current tenant
// Must be used after AuthMiddleware (which sets tenant from JWT)
func TenantMembershipMiddleware(store storage.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from auth context
		userIDStr, exists := c.Get("user_id")
		if !exists {
			c.JSON(401, gin.H{"error": "user not authenticated"})
			c.Abort()
			return
		}

		// Get tenant ID from context (could be string from JWT or domain.TenantID from path)
		tenantID, ok := GetTenantID(c)
		if !ok {
			c.JSON(500, gin.H{"error": "tenant context missing"})
			c.Abort()
			return
		}

		userIDString, ok := userIDStr.(string)
		if !ok {
			c.JSON(500, gin.H{"error": "invalid user_id type in context"})
			c.Abort()
			return
		}
		userID := domain.UserIDFromString(userIDString)

		// Check membership
		isMember, err := store.UserTenants().IsMember(c.Request.Context(), userID, tenantID)
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to check tenant membership"})
			c.Abort()
			return
		}

		if !isMember {
			c.JSON(403, gin.H{"error": "not a member of this tenant"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// GetTenantID extracts tenant ID from gin context
// Handles both string (from JWT via AuthMiddleware) and domain.TenantID (from header via TenantHeaderMiddleware)
func GetTenantID(c *gin.Context) (domain.TenantID, bool) {
	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		return "", false
	}

	// Handle string type (from JWT via AuthMiddleware)
	if tidStr, ok := tenantIDVal.(string); ok {
		return domain.TenantID(tidStr), true
	}

	// Handle domain.TenantID type (from header via TenantHeaderMiddleware)
	if tid, ok := tenantIDVal.(domain.TenantID); ok {
		return tid, true
	}

	return "", false
}

// GetTenant extracts tenant from gin context
func GetTenant(c *gin.Context) (*domain.Tenant, bool) {
	tenant, exists := c.Get("tenant")
	if !exists {
		return nil, false
	}
	t, ok := tenant.(*domain.Tenant)
	if !ok {
		return nil, false
	}
	return t, true
}
