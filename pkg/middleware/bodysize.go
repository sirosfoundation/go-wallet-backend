package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxBodySize is the default maximum request body size (1 MB).
const MaxBodySize int64 = 1 << 20

// BodySizeLimitMiddleware rejects requests with a body larger than maxBytes.
// This prevents denial-of-service attacks via oversized JSON payloads.
func BodySizeLimitMiddleware(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
