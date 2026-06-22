package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-siros-set/set"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// ListWalletInstances returns all wallet instances for a tenant.
func (h *AdminHandlers) ListWalletInstances(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	instances, err := h.store.WalletInstances().GetAllByTenant(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("failed to list wallet instances", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list wallet instances"})
		return
	}
	if instances == nil {
		instances = []*domain.WalletInstance{}
	}
	c.JSON(http.StatusOK, instances)
}

// GetWalletInstance returns a specific wallet instance.
func (h *AdminHandlers) GetWalletInstance(c *gin.Context) {
	instanceID := c.Param("instance_id")

	instance, err := h.store.WalletInstances().GetByID(c.Request.Context(), instanceID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
			return
		}
		h.logger.Error("failed to get wallet instance", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get wallet instance"})
		return
	}
	c.JSON(http.StatusOK, instance)
}

type updateInstanceStatusRequest struct {
	Status string `json:"status" binding:"required,oneof=active suspended revoked"`
	Reason string `json:"reason"`
}

// UpdateWalletInstanceStatus changes the lifecycle state of a wallet instance.
func (h *AdminHandlers) UpdateWalletInstanceStatus(c *gin.Context) {
	instanceID := c.Param("instance_id")

	var req updateInstanceStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: status must be active, suspended, or revoked"})
		return
	}

	status := domain.InstanceStatus(req.Status)

	if err := h.store.WalletInstances().UpdateStatus(c.Request.Context(), instanceID, status, req.Reason); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
			return
		}
		h.logger.Error("failed to update wallet instance status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update wallet instance"})
		return
	}

	// Emit audit event
	if h.audit != nil {
		h.emitInstanceAuditEvent(c, instanceID, status, req.Reason)
	}

	c.JSON(http.StatusOK, gin.H{"id": instanceID, "status": req.Status})
}

// DeleteWalletInstance hard-deletes a wallet instance.
func (h *AdminHandlers) DeleteWalletInstance(c *gin.Context) {
	instanceID := c.Param("instance_id")

	if err := h.store.WalletInstances().Delete(c.Request.Context(), instanceID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
			return
		}
		h.logger.Error("failed to delete wallet instance", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete wallet instance"})
		return
	}

	h.emitAudit(set.EventWIDeactivated, instanceID, map[string]any{"action": "deleted"})
	c.Status(http.StatusNoContent)
}

// ListWalletInstancesByUser returns all wallet instances for a specific user in a tenant.
func (h *AdminHandlers) ListWalletInstancesByUser(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	userID := domain.UserIDFromString(c.Param("user_id"))

	instances, err := h.store.WalletInstances().GetByUser(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("failed to list wallet instances by user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list wallet instances"})
		return
	}
	if instances == nil {
		instances = []*domain.WalletInstance{}
	}
	c.JSON(http.StatusOK, instances)
}

func (h *AdminHandlers) emitInstanceAuditEvent(_ *gin.Context, instanceID string, status domain.InstanceStatus, reason string) {
	var event set.EventURI
	switch status {
	case domain.InstanceStatusRevoked:
		event = set.EventWIRevoked
	case domain.InstanceStatusSuspended:
		event = set.EventWISuspended
	case domain.InstanceStatusActive:
		event = set.EventWICreated // re-activation
	default:
		event = set.EventWIDeactivated
	}
	h.audit.EmitWithSubject(event, instanceID, map[string]any{
		"status": string(status),
		"reason": reason,
	})
}
