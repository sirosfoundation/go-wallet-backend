package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// Self-service wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#195):
// a user can see their own wallet instances and suspend, reactivate or revoke
// them; revoking all deactivates the wallet. Provider-side changes go through
// the admin API (admin_instance_handlers.go); both share
// service.WalletLifecycleService, so the cascade is the same.

type updateMyInstanceStatusRequest struct {
	Status string `json:"status" binding:"required,oneof=active suspended revoked"`
	Reason string `json:"reason"`
}

type revokeAllInstancesRequest struct {
	Reason string `json:"reason"`
}

func (h *Handlers) lifecycleActor(c *gin.Context) (service.LifecycleActor, domain.TenantID, bool) {
	uid, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return service.LifecycleActor{}, "", false
	}
	userID := domain.UserIDFromString(uid.(string))
	tenantID, _ := h.getTenantID(c)
	return service.LifecycleActor{Kind: "user", UserID: &userID}, tenantID, true
}

// ListMyWalletInstances handles GET /user/session/instances.
func (h *Handlers) ListMyWalletInstances(c *gin.Context) {
	if h.services.WalletLifecycle == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LIFECYCLE_NOT_SUPPORTED"})
		return
	}
	actor, tenantID, ok := h.lifecycleActor(c)
	if !ok {
		return
	}
	instances, err := h.services.WalletLifecycle.ListForUser(c.Request.Context(), tenantID, *actor.UserID)
	if err != nil {
		h.logger.Error("failed to list wallet instances", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list wallet instances"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"instances": instances})
}

// UpdateMyWalletInstanceStatus handles PUT /user/session/instances/:instance_id/status.
func (h *Handlers) UpdateMyWalletInstanceStatus(c *gin.Context) {
	if h.services.WalletLifecycle == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LIFECYCLE_NOT_SUPPORTED"})
		return
	}
	actor, tenantID, ok := h.lifecycleActor(c)
	if !ok {
		return
	}
	var req updateMyInstanceStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: status must be active, suspended, or revoked"})
		return
	}
	inst, err := h.services.WalletLifecycle.ChangeStatus(c.Request.Context(), actor, tenantID, c.Param("instance_id"), domain.InstanceStatus(req.Status), req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrNotFound), errors.Is(err, service.ErrWalletInstanceNotOwned):
			c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
		case errors.Is(err, domain.ErrInvalidStatusTransition):
			c.JSON(http.StatusConflict, gin.H{"error": "invalid status transition"})
		default:
			h.logger.Error("failed to update wallet instance status", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update wallet instance"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": inst.ID, "status": string(inst.Status)})
}

// RevokeAllMyWalletInstances handles POST /user/session/instances/revoke-all:
// deactivate the wallet. Every instance is revoked and the wallet data erased;
// a new enrollment is required afterwards.
func (h *Handlers) RevokeAllMyWalletInstances(c *gin.Context) {
	if h.services.WalletLifecycle == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LIFECYCLE_NOT_SUPPORTED"})
		return
	}
	actor, tenantID, ok := h.lifecycleActor(c)
	if !ok {
		return
	}
	var req revokeAllInstancesRequest
	_ = c.ShouldBindJSON(&req) // body is optional
	n, err := h.services.WalletLifecycle.RevokeAllForUser(c.Request.Context(), actor, tenantID, *actor.UserID, req.Reason)
	if err != nil {
		h.logger.Error("failed to revoke wallet instances", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke wallet instances"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": n})
}
