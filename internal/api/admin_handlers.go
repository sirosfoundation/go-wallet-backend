package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// AdminHandlers contains handlers for internal admin API endpoints
type AdminHandlers struct {
	store  storage.Store
	logger *zap.Logger
}

// NewAdminHandlers creates a new AdminHandlers instance
func NewAdminHandlers(store storage.Store, logger *zap.Logger) *AdminHandlers {
	return &AdminHandlers{
		store:  store,
		logger: logger,
	}
}

// TenantRequest represents the request body for creating/updating a tenant
type TenantRequest struct {
	ID          string `json:"id" binding:"required"`
	Name        string `json:"name" binding:"required"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     *bool  `json:"enabled,omitempty"`
}

// TenantResponse represents a tenant in API responses
type TenantResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func tenantToResponse(t *domain.Tenant) *TenantResponse {
	return &TenantResponse{
		ID:          string(t.ID),
		Name:        t.Name,
		DisplayName: t.DisplayName,
		Enabled:     t.Enabled,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}

// ListTenants returns all tenants
// GET /admin/tenants
func (h *AdminHandlers) ListTenants(c *gin.Context) {
	tenants, err := h.store.Tenants().GetAll(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to list tenants", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tenants"})
		return
	}

	response := make([]*TenantResponse, len(tenants))
	for i, t := range tenants {
		response[i] = tenantToResponse(t)
	}

	c.JSON(http.StatusOK, gin.H{"tenants": response})
}

// GetTenant returns a specific tenant
// GET /admin/tenants/:id
func (h *AdminHandlers) GetTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	tenant, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	c.JSON(http.StatusOK, tenantToResponse(tenant))
}

// CreateTenant creates a new tenant
// POST /admin/tenants
func (h *AdminHandlers) CreateTenant(c *gin.Context) {
	var req TenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := domain.TenantID(req.ID)
	if err := domain.ValidateTenantID(tenantID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if tenant already exists
	existing, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err == nil && existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Tenant already exists"})
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	tenant := &domain.Tenant{
		ID:          tenantID,
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Enabled:     enabled,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.store.Tenants().Create(c.Request.Context(), tenant); err != nil {
		h.logger.Error("Failed to create tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	h.logger.Info("Tenant created", zap.String("tenant_id", string(tenantID)))
	c.JSON(http.StatusCreated, tenantToResponse(tenant))
}

// UpdateTenant updates an existing tenant
// PUT /admin/tenants/:id
func (h *AdminHandlers) UpdateTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	var req TenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing tenant
	tenant, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	// Update fields
	tenant.Name = req.Name
	tenant.DisplayName = req.DisplayName
	if req.Enabled != nil {
		tenant.Enabled = *req.Enabled
	}
	tenant.UpdatedAt = time.Now()

	if err := h.store.Tenants().Update(c.Request.Context(), tenant); err != nil {
		h.logger.Error("Failed to update tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant"})
		return
	}

	h.logger.Info("Tenant updated", zap.String("tenant_id", string(tenantID)))
	c.JSON(http.StatusOK, tenantToResponse(tenant))
}

// DeleteTenant deletes a tenant
// DELETE /admin/tenants/:id
func (h *AdminHandlers) DeleteTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Prevent deleting the default tenant
	if tenantID == domain.DefaultTenantID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete the default tenant"})
		return
	}

	// Check if tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	if err := h.store.Tenants().Delete(c.Request.Context(), tenantID); err != nil {
		h.logger.Error("Failed to delete tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tenant"})
		return
	}

	h.logger.Info("Tenant deleted", zap.String("tenant_id", string(tenantID)))
	c.JSON(http.StatusOK, gin.H{"message": "Tenant deleted"})
}

// AddUserToTenant adds a user to a tenant
// POST /admin/tenants/:id/users
func (h *AdminHandlers) AddUserToTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	var req struct {
		UserID string `json:"user_id" binding:"required"`
		Role   string `json:"role,omitempty"` // user, admin
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	userID := domain.UserIDFromString(req.UserID)
	role := req.Role
	if role == "" {
		role = domain.TenantRoleUser
	}

	membership := &domain.UserTenantMembership{
		UserID:    userID,
		TenantID:  tenantID,
		Role:      role,
		CreatedAt: time.Now(),
	}

	if err := h.store.UserTenants().AddMembership(c.Request.Context(), membership); err != nil {
		h.logger.Error("Failed to add user to tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user to tenant"})
		return
	}

	h.logger.Info("User added to tenant",
		zap.String("tenant_id", string(tenantID)),
		zap.String("user_id", req.UserID),
		zap.String("role", role),
	)
	c.JSON(http.StatusOK, gin.H{"message": "User added to tenant"})
}

// RemoveUserFromTenant removes a user from a tenant
// DELETE /admin/tenants/:id/users/:user_id
func (h *AdminHandlers) RemoveUserFromTenant(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	userID := domain.UserIDFromString(c.Param("user_id"))

	if err := h.store.UserTenants().RemoveMembership(c.Request.Context(), userID, tenantID); err != nil {
		h.logger.Error("Failed to remove user from tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove user from tenant"})
		return
	}

	h.logger.Info("User removed from tenant",
		zap.String("tenant_id", string(tenantID)),
		zap.String("user_id", userID.String()),
	)
	c.JSON(http.StatusOK, gin.H{"message": "User removed from tenant"})
}

// GetTenantUsers returns all users in a tenant
// GET /admin/tenants/:id/users
func (h *AdminHandlers) GetTenantUsers(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Verify tenant exists
	_, err := h.store.Tenants().GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	userIDs, err := h.store.UserTenants().GetTenantUsers(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get tenant users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant users"})
		return
	}

	// Convert to strings
	users := make([]string, len(userIDs))
	for i, id := range userIDs {
		users[i] = id.String()
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// AdminStatus returns the admin server status
// GET /admin/status
func (h *AdminHandlers) AdminStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "wallet-backend-admin",
	})
}
