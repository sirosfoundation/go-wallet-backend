package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-siros-set/set"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// Error strings shared with the self-service handlers so clients see one vocabulary.
//
// errCodeErasureIncomplete reports a persisted lifecycle change whose cascade
// did not complete; repeating the request resumes the cleanup.
const (
	errCodeErasureIncomplete = "ERASURE_INCOMPLETE"
	// errCodeDeletionIncomplete: account deletion left a wallet instance behind; repeat the request.
	errCodeDeletionIncomplete = "DELETION_INCOMPLETE"
	// errCodeDeletionCleanupPending: the account was deleted but the later sweep failed; do not repeat.
	errCodeDeletionCleanupPending = "DELETION_CLEANUP_PENDING"
	// errCodeDeletionOperatorRequired: deletion stalled after the user's tokens were
	// revoked for good; the user cannot repeat it.
	errCodeDeletionOperatorRequired = "DELETION_OPERATOR_REQUIRED"
	// errCodeLifecycleNotSupported: no lifecycle service behind the operation; nothing happened.
	errCodeLifecycleNotSupported = "LIFECYCLE_NOT_SUPPORTED"
	errMsgErasureIncomplete      = "the status change was recorded but part of the lifecycle cleanup (dropping sessions, cutting off tokens, erasing wallet data) did not complete; repeat the request to finish it"
)

const (
	errMsgInstanceUpdateFailed    = "failed to update wallet instance"
	errMsgInvalidStatusTransition = "invalid status transition"
	// errCodeInstanceRetained refuses hard delete of a non-live user-owned
	// instance: it is the tombstone the login gate and WIA guard read.
	errCodeInstanceRetained = "INSTANCE_RETAINED"
	// errCodeInstanceOwned refuses hard delete of a live user-owned instance,
	// which would skip the lifecycle cascade; revoke it instead.
	errCodeInstanceOwned = "INSTANCE_OWNED"
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
	tenantID := domain.TenantID(c.Param("id"))
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
	// Enforce tenant ownership — prevent cross-tenant access
	if instance.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
		return
	}
	c.JSON(http.StatusOK, instance)
}

type updateInstanceStatusRequest struct {
	// Status is "revoked", the only status change; kept so a future state needs no second URL.
	Status string `json:"status" binding:"required,oneof=revoked"`
	Reason string `json:"reason"`
}

// UpdateWalletInstanceStatus revokes a wallet instance. Terminal, hence a
// provider action.
func (h *AdminHandlers) UpdateWalletInstanceStatus(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	instanceID := c.Param("instance_id")

	var req updateInstanceStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: status must be revoked"})
		return
	}

	// Fetch once: used both to verify tenant ownership and to validate the
	// state transition before persisting.
	instance, err := h.store.WalletInstances().GetByID(c.Request.Context(), instanceID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
			return
		}
		h.logger.Error("failed to get wallet instance", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMsgInstanceUpdateFailed})
		return
	}
	if instance.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
		return
	}

	status := domain.InstanceStatus(req.Status)
	if err := domain.ValidateStatusTransition(instance.Status, status); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": errMsgInvalidStatusTransition, "current": string(instance.Status), "target": string(status)})
		return
	}

	if h.lifecycle != nil {
		// Shared lifecycle service: same rules, audit and cascade as self-service.
		if _, err := h.lifecycle.ChangeStatus(c.Request.Context(), service.LifecycleActor{Kind: "provider"}, tenantID, instanceID, status, req.Reason); err != nil {
			switch {
			case errors.Is(err, service.ErrErasureIncomplete):
				h.logger.Error("wallet instance status changed but cascade incomplete", zap.Error(err))
				c.JSON(http.StatusConflict, gin.H{"error": errCodeErasureIncomplete, "id": instanceID, "status": req.Status, "message": errMsgErasureIncomplete})
			case errors.Is(err, storage.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
			case errors.Is(err, domain.ErrInvalidStatusTransition):
				c.JSON(http.StatusConflict, gin.H{"error": errMsgInvalidStatusTransition})
			default:
				h.logger.Error("failed to update wallet instance status", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": errMsgInstanceUpdateFailed})
			}
			return
		}
		c.JSON(http.StatusOK, gin.H{"id": instanceID, "status": req.Status})
		return
	}

	// No lifecycle service: fail closed, since writing the status directly would
	// skip cut-off, session drop and erasure yet answer 200.
	h.logger.Error("wallet instance revocation refused: no lifecycle service is wired",
		zap.String("instance_id", instanceID), zap.String("tenant_id", string(tenantID)))
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": errCodeLifecycleNotSupported})
}

// DeleteWalletInstance hard-deletes a wallet instance.
func (h *AdminHandlers) DeleteWalletInstance(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))
	instanceID := c.Param("instance_id")

	// Verify tenant ownership before allowing deletion
	instance, err := h.store.WalletInstances().GetByID(c.Request.Context(), instanceID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
			return
		}
		h.logger.Error("failed to get wallet instance for tenant check", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete wallet instance"})
		return
	}
	if instance.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
		return
	}

	// SID-AUTH-06: a revoked instance is the tombstone that keeps the login gate
	// and WIA guard refusing that wallet, owned or not. Only active records are
	// hard-deleted.
	if !instance.Status.IsLive() {
		c.JSON(http.StatusConflict, gin.H{
			"error":   errCodeInstanceRetained,
			"message": "a wallet instance that is no longer live is retained as a lifecycle record and cannot be deleted",
		})
		return
	}

	// A live user-owned instance is not deleted: that would skip the lifecycle
	// (cut-off, session drop) and can leave an empty listing the login gate
	// reads as a first enrollment. Revoke instead.
	if instance.UserID != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":   errCodeInstanceOwned,
			"message": "a wallet instance that belongs to a user cannot be deleted; revoke it instead (PUT .../instances/{instance_id}/status with status \"revoked\")",
		})
		return
	}

	// The condition and binding (owner, generation) travel with the delete: the
	// read above is a snapshot, and a concurrent revocation's tombstone or
	// another user's re-attested thumbprint must not be deleted.
	if err := h.store.WalletInstances().DeleteIfRemovable(c.Request.Context(), instanceID, tenantID, instance.Binding()); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "wallet instance not found"})
			return
		}
		if errors.Is(err, storage.ErrBindingChanged) {
			c.JSON(http.StatusConflict, gin.H{
				"error":   "wallet_instance_changed",
				"message": "the wallet instance was replaced while the request was in flight; nothing was deleted",
			})
			return
		}
		if errors.Is(err, domain.ErrInvalidStatusTransition) {
			c.JSON(http.StatusConflict, gin.H{
				"error":   errCodeInstanceRetained,
				"message": "a wallet instance that is no longer live is retained as a lifecycle record and cannot be deleted",
			})
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
	// Revocation is the only accepted status; anything else is recorded, not dropped.
	event := set.EventWIDeactivated
	if status == domain.InstanceStatusRevoked {
		event = set.EventWIRevoked
	}
	h.audit.EmitWithSubject(event, instanceID, map[string]any{
		"status": string(status),
		"reason": reason,
	})
}

// revokeAllInstancesRequest is the optional body of the admin revoke-all.
type revokeAllInstancesRequest struct {
	Reason string `json:"reason"`
}

// RevokeAllWalletInstancesForUser handles POST
// /admin/tenants/:id/users/:user_id/instances/revoke-all: revokes every instance
// the user has in the tenant (SID-AUTH-06) via the single-revocation cascade.
func (h *AdminHandlers) RevokeAllWalletInstancesForUser(c *gin.Context) {
	if h.lifecycle == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": errCodeLifecycleNotSupported})
		return
	}
	tenantID := domain.TenantID(c.Param("id"))
	userID := domain.UserIDFromString(c.Param("user_id"))

	// The body is optional: absent is fine, malformed is not. Content-Length
	// cannot tell them apart (chunked is -1), so bind and treat only "nothing to
	// read" as absent.
	var req revokeAllInstancesRequest
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	n, err := h.lifecycle.RevokeAllForUser(c.Request.Context(), service.LifecycleActor{Kind: "provider"}, tenantID, userID, req.Reason)
	if err != nil {
		if errors.Is(err, service.ErrErasureIncomplete) {
			h.logger.Error("wallet instances revoked but cascade incomplete", zap.Error(err))
			c.JSON(http.StatusConflict, gin.H{"error": errCodeErasureIncomplete, "revoked": n, "message": errMsgErasureIncomplete})
			return
		}
		h.logger.Error("failed to revoke wallet instances", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke wallet instances"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": n})
}
