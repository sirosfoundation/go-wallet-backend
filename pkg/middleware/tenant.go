package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// TenantPathMiddleware extracts the tenant from URL path parameter and validates it.
// For authenticated requests (where AuthMiddleware has already run), the tenant_id from
// the JWT is authoritative and will NOT be overwritten by the path tenant.
// The path tenant is only used for:
// 1. Unauthenticated endpoints (login, registration) where tenant comes from path
// 2. Routing purposes (load balancer/CDN) - we still validate the tenant exists
func TenantPathMiddleware(store storage.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantIDStr := c.Param("tenantID")
		if tenantIDStr == "" {
			c.JSON(400, gin.H{"error": "tenant ID required in path"})
			c.Abort()
			return
		}

		pathTenantID := domain.TenantID(tenantIDStr)

		// Always validate that the path tenant exists (for routing validation)
		tenant, err := store.Tenants().GetByID(c.Request.Context(), pathTenantID)
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

		// Check if tenant was already set by AuthMiddleware (from JWT)
		// If so, the JWT tenant_id is authoritative for security boundary
		if _, exists := c.Get("tenant_from_jwt"); exists {
			// tenant_id already set from JWT - don't override (security boundary)
			// Store the path tenant separately for reference if needed
			c.Set("path_tenant_id", pathTenantID)
			c.Set("path_tenant", tenant)
		} else {
			// No JWT auth yet (unauthenticated endpoint) - use path tenant
			c.Set("tenant_id", pathTenantID)
			c.Set("tenant", tenant)
		}

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
// Handles both string (from JWT) and domain.TenantID (from path) types
func GetTenantID(c *gin.Context) (domain.TenantID, bool) {
	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		return "", false
	}

	// Handle string type (from JWT via AuthMiddleware)
	if tidStr, ok := tenantIDVal.(string); ok {
		return domain.TenantID(tidStr), true
	}

	// Handle domain.TenantID type (from path via TenantPathMiddleware)
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
