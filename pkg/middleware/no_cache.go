package middleware

import "github.com/gin-gonic/gin"

// NoCacheControlValue is the Cache-Control header value set by NoCacheMiddleware.
const NoCacheControlValue = "no-store, no-cache, must-revalidate"

// NoCacheMiddleware disables caching for sensitive responses such as
// authentication, session, private-data, and credential storage endpoints.
// Handlers can still explicitly override these headers later in the chain.
func NoCacheMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", NoCacheControlValue)
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}
