package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// CreateInviteRequest represents the request body for creating an invite
type CreateInviteRequest struct {
	ExpiresIn int              `json:"expires_in"` // seconds until expiry (default: 7 days)
	Metadata  *json.RawMessage `json:"metadata,omitempty"`
}

// InviteResponse represents an invite in API responses
type InviteResponse struct {
	ID        string           `json:"id"`
	TenantID  string           `json:"tenant_id"`
	Code      string           `json:"code,omitempty"` // only returned on create
	Status    string           `json:"status"`
	Metadata  *json.RawMessage `json:"metadata,omitempty"`
	UsedBy    *string          `json:"used_by,omitempty"`
	ExpiresAt time.Time        `json:"expires_at"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

func inviteToResponse(inv *domain.Invite, includeCode bool) *InviteResponse {
	resp := &InviteResponse{
		ID:        inv.ID,
		TenantID:  string(inv.TenantID),
		Status:    string(inv.Status),
		ExpiresAt: inv.ExpiresAt,
		CreatedAt: inv.CreatedAt,
		UpdatedAt: inv.UpdatedAt,
	}
	if includeCode {
		resp.Code = inv.Code
	}
	if len(inv.Metadata) > 0 {
		raw := inv.Metadata
		resp.Metadata = &raw
	}
	if inv.UsedBy != nil {
		s := inv.UsedBy.String()
		resp.UsedBy = &s
	}
	return resp
}

// CreateInvite creates a new invite code for a tenant
// POST /admin/tenants/:id/invites
func (h *AdminHandlers) CreateInvite(c *gin.Context) {
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

	var req CreateInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body (all fields are optional)
		req = CreateInviteRequest{}
	}

	// Default expiry: 7 days
	expiresIn := 7 * 24 * 3600
	if req.ExpiresIn > 0 {
		expiresIn = req.ExpiresIn
	}

	code, err := domain.GenerateInviteCode()
	if err != nil {
		h.logger.Error("Failed to generate invite code", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate invite code"})
		return
	}

	now := time.Now()
	invite := &domain.Invite{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		Code:      code,
		Status:    domain.InviteStatusActive,
		ExpiresAt: now.Add(time.Duration(expiresIn) * time.Second),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if req.Metadata != nil {
		invite.Metadata = *req.Metadata
	}

	if err := h.store.Invites().Create(c.Request.Context(), invite); err != nil {
		h.logger.Error("Failed to create invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create invite"})
		return
	}

	h.logger.Info("Invite created",
		zap.String("tenant_id", string(tenantID)),
		zap.String("invite_id", invite.ID))
	c.JSON(http.StatusCreated, inviteToResponse(invite, true))
}

// ListInvites returns all invites for a tenant
// GET /admin/tenants/:id/invites
func (h *AdminHandlers) ListInvites(c *gin.Context) {
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

	invites, err := h.store.Invites().GetAllByTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list invites", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list invites"})
		return
	}

	response := make([]*InviteResponse, len(invites))
	for i, inv := range invites {
		response[i] = inviteToResponse(inv, false)
	}

	c.JSON(http.StatusOK, gin.H{"invites": response})
}

// GetInvite returns a specific invite
// GET /admin/tenants/:id/invites/:invite_id
func (h *AdminHandlers) GetInvite(c *gin.Context) {
	invite, err := h.store.Invites().GetByID(c.Request.Context(), c.Param("invite_id"))
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Invite not found"})
			return
		}
		h.logger.Error("Failed to get invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get invite"})
		return
	}

	// Verify invite belongs to the tenant
	tenantID := domain.TenantID(c.Param("id"))
	if invite.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Invite not found"})
		return
	}

	c.JSON(http.StatusOK, inviteToResponse(invite, false))
}

// UpdateInviteRequest represents action-based invite updates
type UpdateInviteRequest struct {
	Action    string `json:"action" binding:"required"` // "renew" or "revoke"
	ExpiresIn int    `json:"expires_in,omitempty"`      // seconds (for renew)
}

// UpdateInvite updates an invite (renew or revoke)
// PUT /admin/tenants/:id/invites/:invite_id
func (h *AdminHandlers) UpdateInvite(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	inviteID := c.Param("invite_id")

	var req UpdateInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	invite, err := h.store.Invites().GetByID(c.Request.Context(), inviteID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Invite not found"})
			return
		}
		h.logger.Error("Failed to get invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get invite"})
		return
	}

	if invite.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Invite not found"})
		return
	}

	switch req.Action {
	case "renew":
		if invite.Status == domain.InviteStatusCompleted {
			c.JSON(http.StatusConflict, gin.H{"error": "Cannot renew a completed invite"})
			return
		}
		// Renew: set status back to active and extend expiry
		invite.Status = domain.InviteStatusActive
		expiresIn := 7 * 24 * 3600 // default 7 days
		if req.ExpiresIn > 0 {
			expiresIn = req.ExpiresIn
		}
		invite.ExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	case "revoke":
		if invite.Status == domain.InviteStatusCompleted {
			c.JSON(http.StatusConflict, gin.H{"error": "Cannot revoke a completed invite"})
			return
		}
		invite.Status = domain.InviteStatusRevoked

	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action, must be 'renew' or 'revoke'"})
		return
	}

	if err := h.store.Invites().Update(c.Request.Context(), invite); err != nil {
		h.logger.Error("Failed to update invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update invite"})
		return
	}

	h.logger.Info("Invite updated",
		zap.String("tenant_id", string(tenantID)),
		zap.String("invite_id", inviteID),
		zap.String("action", req.Action))
	c.JSON(http.StatusOK, inviteToResponse(invite, false))
}

// DeleteInvite hard-deletes an invite
// DELETE /admin/tenants/:id/invites/:invite_id
func (h *AdminHandlers) DeleteInvite(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	inviteID := c.Param("invite_id")

	// Verify invite belongs to tenant
	invite, err := h.store.Invites().GetByID(c.Request.Context(), inviteID)
	if err != nil {
		if err == storage.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Invite not found"})
			return
		}
		h.logger.Error("Failed to get invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get invite"})
		return
	}

	if invite.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Invite not found"})
		return
	}

	if err := h.store.Invites().Delete(c.Request.Context(), tenantID, inviteID); err != nil {
		h.logger.Error("Failed to delete invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete invite"})
		return
	}

	h.logger.Info("Invite deleted",
		zap.String("tenant_id", string(tenantID)),
		zap.String("invite_id", inviteID))
	c.JSON(http.StatusOK, gin.H{"message": "Invite deleted"})
}
