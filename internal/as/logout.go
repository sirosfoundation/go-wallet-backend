package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LogoutHandler handles DELETE /auth/session.
// It revokes the session and clears the session cookie.
func LogoutHandler(store SessionStore, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID := GetSessionCookie(c)
		if sessionID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no session"})
			return
		}

		if err := store.Revoke(c.Request.Context(), sessionID); err != nil {
			logger.Warn("session revocation failed",
				zap.String("session_id", sessionID),
				zap.Error(err),
			)
			// Don't expose internal errors — clear cookie regardless.
		}

		ClearSessionCookie(c, DefaultCookieOptions())
		c.Status(http.StatusNoContent)
	}
}
