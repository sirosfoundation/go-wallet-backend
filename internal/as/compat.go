package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// TokenModeHeader is the header clients send to opt in to session-based
	// authentication (cookie-bound AS session, access tokens from
	// /auth/token). It is mandatory on the /auth/passkey/* endpoints: the
	// legacy all-in-one HMAC token flow that clients got without it was
	// removed.
	TokenModeHeader = "X-Token-Mode"

	// TokenModeSessionValue is the header value selecting session mode.
	TokenModeSessionValue = "session"
)

// IsSessionMode reports whether the request carries X-Token-Mode: session.
func IsSessionMode(c *gin.Context) bool {
	return c.GetHeader(TokenModeHeader) == TokenModeSessionValue
}

// sessionModeGate answers 410 legacy_tokens_disabled to a request without
// X-Token-Mode: session. Such a client expects the removed legacy flow (an
// appToken in the response body); silently handing it a cookie-only session
// would look like a successful login that left it with no usable token. It
// sits before the OIDC gate so those clients get this answer rather than an
// unrelated OIDC error.
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
