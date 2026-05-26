package middleware

import "github.com/gin-gonic/gin"

const noCacheControlValue = "no-store, no-cache, must-revalidate"

// NoCacheMiddleware disables caching for sensitive responses such as
// authentication, session, private-data, and credential storage endpoints.
// Handlers can still explicitly override these headers later in the chain.
func NoCacheMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", noCacheControlValue)
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}
