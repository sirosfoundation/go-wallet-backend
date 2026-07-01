package as

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// DeprecationConfig holds configuration for RFC 8594 deprecation headers.
type DeprecationConfig struct {
	// Enabled controls whether deprecation headers are sent.
	Enabled bool

	// SunsetDate is the date after which legacy mode will be removed.
	SunsetDate string
}

// DeprecationMiddleware adds RFC 8594 Deprecation and Sunset headers
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
		if cfg.SunsetDate != "" {
			// Parse and reformat to HTTP-date (RFC 7231).
			if t, err := time.Parse(time.RFC3339, cfg.SunsetDate); err == nil {
				c.Header("Sunset", t.UTC().Format(http.TimeFormat))
			} else {
				// If not RFC3339, pass through as-is.
				c.Header("Sunset", cfg.SunsetDate)
			}
		}
	}
}
