package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
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

// Error code for a lifecycle change that was persisted but whose cascade
// (session drop, wallet erasure) did not complete. The status is final;
// repeating the same request re-runs the erasure.
const (
	errCodeErasureIncomplete = "ERASURE_INCOMPLETE"
	errMsgErasureIncomplete  = "the status change was recorded but part of the lifecycle cleanup (dropping sessions, cutting off tokens, erasing wallet data) did not complete; repeat the request to finish it"
)

func (h *Handlers) lifecycleActor(c *gin.Context) (service.LifecycleActor, domain.TenantID, bool) {
	uid, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return service.LifecycleActor{}, "", false
	}
	userID := domain.UserIDFromString(uid.(string))
	tenantID, _ := h.getTenantID(c)
	actor := service.LifecycleActor{Kind: "user", UserID: &userID}
	if raw, ok := c.Get("token"); ok {
		if tok, ok := raw.(string); ok {
			actor.TokenJTI = tokengate.JTI(tok)
		}
	}
	return actor, tenantID, true
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
	// The route needs TAC `w` for the reversible changes; `revoked` is
	// terminal and runs the same destructive cascade as revoke-all (wallet
	// data erasure once it is the last instance), so it additionally needs
	// `d`, like revoke-all and credential deletion. Otherwise a write-only
	// token could erase the wallet one instance at a time.
	if req.Status == string(domain.InstanceStatusRevoked) && !tacAllows(c, "d") {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		return
	}
	inst, err := h.services.WalletLifecycle.ChangeStatus(c.Request.Context(), actor, tenantID, c.Param("instance_id"), domain.InstanceStatus(req.Status), req.Reason)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrErasureIncomplete):
			h.logger.Error("wallet instance status changed but cascade incomplete", zap.Error(err))
			c.JSON(http.StatusConflict, gin.H{"error": errCodeErasureIncomplete, "id": inst.ID, "status": string(inst.Status), "message": errMsgErasureIncomplete})
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

// tacAllows reports whether the request's go-tokenauth TAC grants required.
// Like requireTACIfEnforced it is a no-op under legacy AuthMiddleware, which
// never sets tokenauth_result (there is no TAC concept there).
func tacAllows(c *gin.Context, required string) bool {
	v, ok := c.Get("tokenauth_result")
	if !ok {
		return true
	}
	result, ok := v.(*claims.Result)
	if !ok || result == nil {
		return true
	}
	return result.TAC.HasAll(required)
}

// bindOptionalJSON decodes an optional JSON body into dst. An empty body is
// accepted as "no options"; any other decoding failure answers 400 and returns
// false, so that on a destructive endpoint a malformed payload (say a
// truncated reason) cannot silently pass as an unannotated request.
func bindOptionalJSON(c *gin.Context, dst any) bool {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return false
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return true
	}
	if err := json.Unmarshal(body, dst); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return false
	}
	return true
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
	if !bindOptionalJSON(c, &req) {
		return
	}
	n, err := h.services.WalletLifecycle.RevokeAllForUser(c.Request.Context(), actor, tenantID, *actor.UserID, req.Reason)
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
