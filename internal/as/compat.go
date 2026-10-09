package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// TokenModeHeader opts in to session mode; it is mandatory on /auth/passkey/*.
	TokenModeHeader = "X-Token-Mode"

	// TokenModeSessionValue is the header value selecting session mode.
	TokenModeSessionValue = "session"
)

// IsSessionMode reports whether the request carries X-Token-Mode: session.
func IsSessionMode(c *gin.Context) bool {
	return c.GetHeader(TokenModeHeader) == TokenModeSessionValue
}

// sessionModeGate answers 410 legacy_tokens_disabled to a request without X-Token-Mode: session,
// before the OIDC gate, so clients expecting the removed legacy flow get a clear error.
func sessionModeGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if IsSessionMode(c) {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusGone, gin.H{
			"error":   "legacy_tokens_disabled",
			"message": "legacy HMAC session tokens are no longer issued; send X-Token-Mode: session",
		})
	}
}
