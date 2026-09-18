package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-siros-set/set"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// Error strings shared by the admin instance handlers (kept identical to the
// self-service handlers so clients see one vocabulary).
// errCodeErasureIncomplete reports a lifecycle change that was persisted but
// whose cascade (dropping sessions, cutting off tokens, erasing wallet data)
// did not complete. The status change stands; repeating the request resumes
// the cleanup.
const (
	errCodeErasureIncomplete = "ERASURE_INCOMPLETE"
	// errCodeDeletionIncomplete is returned when account deletion left a
	// wallet instance behind. The account still exists; repeat the request.
	errCodeDeletionIncomplete = "DELETION_INCOMPLETE"
	// errCodeLifecycleNotSupported is returned when a lifecycle operation is
	// reached without a lifecycle service behind it. It means the operation
	// did not happen, not that it half happened.
	errCodeLifecycleNotSupported = "LIFECYCLE_NOT_SUPPORTED"
	errMsgErasureIncomplete      = "the status change was recorded but part of the lifecycle cleanup (dropping sessions, cutting off tokens, erasing wallet data) did not complete; repeat the request to finish it"
)

const (
	errMsgInstanceUpdateFailed    = "failed to update wallet instance"
	errMsgInvalidStatusTransition = "invalid status transition"
	// errCodeInstanceRetained refuses the hard delete of a user-owned
	// instance that is not live. The record is the tombstone the login gate
	// and the WIA guard read, so deleting it would make the next attestation
	// on that device look like a first enrollment. It is status-neutral
	// because a legacy suspended record is retained for the same reason a
	// revoked one is.
	errCodeInstanceRetained = "INSTANCE_RETAINED"
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
	// Status is "revoked", the only status change a wallet instance has.
	// The field is kept rather than dropped for a bare revoke endpoint so
	// that a client always says what it means to happen, and so a future
	// state does not need a second URL.
	Status string `json:"status" binding:"required,oneof=revoked"`
	Reason string `json:"reason"`
}

// UpdateWalletInstanceStatus revokes a wallet instance. Revocation is the only
// lifecycle change there is and it cannot be undone, which is why it is a
// provider action: a user who revoked the instance behind their last passkey
// would have no way back without an admin.
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
		// Shared lifecycle service: same transition rules, audit and cascade
		// (session drop, wallet erasure on last revocation) as self-service.
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

	// No lifecycle service: fail closed. Writing the status straight to the
	// store would skip the token cut-off, the session drop and the erasure,
	// and answer 200 for a revocation that left the device's tokens working.
	// For the one operation a wallet instance has, and one that cannot be
	// undone, that is the worst possible half-measure.
	//
	// Both providers wire the service (server.BackendProvider and
	// server.AdminProvider), so this is unreachable in a built server. It is
	// here so that a future one cannot reintroduce a silent partial
	// revocation by forgetting to.
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

	// SID-AUTH-06: a revoked instance of a user is the record that keeps the
	// login gate and the WIA guard refusing that wallet. Deleting it would
	// make the user look never-enrolled and re-open both. Revocation is
	// terminal, so the record stays as a tombstone; only instances without
	// a user (stray attestation records) or non-revoked ones may be removed.
	if !instance.Status.IsLive() && instance.UserID != nil {
		c.JSON(http.StatusConflict, gin.H{
			"error":   errCodeInstanceRetained,
			"message": "a wallet instance that is no longer live is retained as a lifecycle record and cannot be deleted",
		})
		return
	}

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
	// Revocation is the only status this endpoint accepts; anything else
	// reaching here got past the binding, so it is recorded rather than
	// dropped.
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

// RevokeAllWalletInstancesForUser handles
// POST /admin/tenants/:id/users/:user_id/instances/revoke-all: revoke every
// instance the user has in the tenant. SID-AUTH-06 requires a provider to be
// able to act on one instance, several, or all of them; this is the "all"
// case, and revoking the last live one runs the same cascade as a single
// revocation.
func (h *AdminHandlers) RevokeAllWalletInstancesForUser(c *gin.Context) {
	if h.lifecycle == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": errCodeLifecycleNotSupported})
		return
	}
	tenantID := domain.TenantID(c.Param("id"))
	userID := domain.UserIDFromString(c.Param("user_id"))

	var req revokeAllInstancesRequest
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
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
