package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// TenantPathMiddleware extracts the tenant from URL path parameter and validates it
func TenantPathMiddleware(store storage.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr := c.Param("tenantID")
		if tenantIDStr == "" {
			c.JSON(400, gin.H{"error": "tenant ID required in path"})
			c.Abort()
			return
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

		// Set tenant context
		c.Set("tenant_id", tenantID)
		c.Set("tenant", tenant)
		c.Next()
	}
}

// TenantMembershipMiddleware verifies the user is a member of the current tenant
// Must be used after AuthMiddleware and TenantPathMiddleware
func TenantMembershipMiddleware(store storage.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from auth context
		userIDStr, exists := c.Get("user_id")
		if !exists {
			c.JSON(401, gin.H{"error": "user not authenticated"})
			c.Abort()
			return
		}

		// Get tenant ID from tenant context
		tenantIDVal, exists := c.Get("tenant_id")
		if !exists {
			c.JSON(500, gin.H{"error": "tenant context missing"})
			c.Abort()
			return
		}

		userID := domain.UserIDFromString(userIDStr.(string))
		tenantID := tenantIDVal.(domain.TenantID)

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
func GetTenantID(c *gin.Context) (domain.TenantID, bool) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		return "", false
	}
	return tenantID.(domain.TenantID), true
}

// GetTenant extracts tenant from gin context
func GetTenant(c *gin.Context) (*domain.Tenant, bool) {
	tenant, exists := c.Get("tenant")
	if !exists {
		return nil, false
	}
	return tenant.(*domain.Tenant), true
}
