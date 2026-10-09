package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

// Self-service wallet instance endpoints (SID-AUTH-06, go-wallet-backend#195).
// A user can list their instances, log out everywhere, or delete the account,
// but not revoke an instance: revocation is terminal, and one that took the
// last passkey would lock the user out. It lives on the admin API
// (admin_instance_handlers.go), matching the ARF (Art. 5a(9)(a),
// WURevocation_10, WIAM_06): the Provider performs it after authenticating
// the user.

// ListMyWalletInstances handles GET /user/session/instances.
func (h *Handlers) ListMyWalletInstances(c *gin.Context) {
	if h.services.WalletLifecycle == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LIFECYCLE_NOT_SUPPORTED"})
		return
	}
	uid, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := domain.UserIDFromString(uid.(string))
	tenantID, _ := h.getTenantID(c)

	instances, err := h.services.WalletLifecycle.ListForUser(c.Request.Context(), tenantID, userID)
	if err != nil {
		h.logger.Error("failed to list wallet instances", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list wallet instances"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"instances": instances})
}

// LogoutEverywhere handles POST /user/session/logout-all: drop every session
// and refuse already-issued bearer tokens (SID-AUTH-06), including the
// caller's own. Nothing is erased.
func (h *Handlers) LogoutEverywhere(c *gin.Context) {
	uid, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := domain.UserIDFromString(uid.(string))

	if err := h.services.User.LogoutEverywhere(c.Request.Context(), userID); err != nil {
		if abortIfTokenRevoked(c, err) {
			return
		}
		if errors.Is(err, service.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		h.logger.Error("failed to log the user out everywhere", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to log out"})
		return
	}
	c.Status(http.StatusNoContent)
}

// SID-AUTH-06: tokens issued before a revocation cannot open a new engine session.
