package as

import (
	"github.com/gin-gonic/gin"
)

// DeprecationConfig holds configuration for RFC 8594 deprecation headers.
type DeprecationConfig struct {
	// Enabled controls whether deprecation headers are sent.
	Enabled bool
}

// DeprecationMiddleware adds RFC 8594 Deprecation header
// to responses served to legacy clients.
func DeprecationMiddleware(cfg DeprecationConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if !cfg.Enabled {
			return
		}

		// Only add headers for legacy client requests.
		mode := GetClientMode(c)
		if mode != ClientModeLegacy {
			return
		}

		c.Header("Deprecation", "true")
	}
}
