package as

import (
	"github.com/gin-gonic/gin"
)

const (
	// TokenModeHeader is the header clients send to indicate they support
	// the new session-based authentication.
	TokenModeHeader = "X-Token-Mode"

	// TokenModeSessionValue is the header value indicating a new-style client.
	TokenModeSessionValue = "session"
)

// DetectClientMode determines whether a request is from a legacy or new-style client.
// New-style clients send X-Token-Mode: session.
func DetectClientMode(c *gin.Context) ClientMode {
	if c.GetHeader(TokenModeHeader) == TokenModeSessionValue {
		return ClientModeSession
	}
	return ClientModeLegacy
}
