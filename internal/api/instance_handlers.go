package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

// Self-service wallet instance endpoints (SID-AUTH-06,
// go-wallet-backend#195). A user can see their own wallet instances and can
// log out everywhere, and can remove the account outright (DeleteUser). What
// a user cannot do is revoke an instance. Revocation cannot be undone, so a
// user who revoked the instance holding their last passkey would be locked
// out of their own account with no self-service way back; it lives on the
// admin API (admin_instance_handlers.go). This matches where the ARF puts
// it: the User has a right to obtain revocation and a channel to ask for it
// (Art. 5a(9)(a), WURevocation_10, WIAM_06), and the Wallet Provider is the
// party that performs it after authenticating them. The irreversible path a
// user does own is removing the account, which erases the data and the
// passkeys with it.

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
// of the caller, on this device and on any other, and refuse the bearer
// tokens already issued to them (SID-AUTH-06). The caller's own token is
// refused too - that is what "log out everywhere" means - so the client must
// log in again afterwards. Nothing is erased; this is the reversible thing a
// user can safely do to themselves.
func (h *Handlers) LogoutEverywhere(c *gin.Context) {
	uid, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	userID := domain.UserIDFromString(uid.(string))

	if err := h.services.User.LogoutEverywhere(c.Request.Context(), userID); err != nil {
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
