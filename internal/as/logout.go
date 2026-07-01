package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LogoutHandler handles DELETE /auth/session.
// It revokes the session and clears the session cookie.
func LogoutHandler(store SessionStore, insecureCookies bool, logger *zap.Logger) gin.HandlerFunc {
	opts := CookieOptions{Insecure: insecureCookies}
	return func(c *gin.Context) {
		sessionID := GetSessionCookie(c, opts)
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

		ClearSessionCookie(c, opts)
		c.Status(http.StatusNoContent)
	}
}
