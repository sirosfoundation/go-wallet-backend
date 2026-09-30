package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// MaxBodySize is the default maximum request body size (10 MB).
//
// The wallet's private-data blob (S.credentials[] in the encrypted
// container) grows without bound as credentials accumulate - nothing prunes
// or compacts it, and mdoc/mDL credentials in particular embed a base64
// portrait photo each. 1 MB was tight enough to be hit by a real device
// after only a few mdoc batch-issuance rounds in the same test account
// (confirmed: POST /user/session/private-data returning 413 well before any
// abnormal number of credentials had accumulated).
const MaxBodySize int64 = 10 << 20

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
