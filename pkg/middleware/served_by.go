package middleware

import "github.com/gin-gonic/gin"

// ServedByMiddleware adds an X-Served-By response header with the given value.
func ServedByMiddleware(value string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Served-By", value)
		c.Next()
	}
}
