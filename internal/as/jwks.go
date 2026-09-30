package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RegisterJWKSRoute registers the /.well-known/jwks.json endpoint on the given router.
func RegisterJWKSRoute(router gin.IRoutes, km *KeyManager) {
	router.GET("/.well-known/jwks.json", jwksHandler(km))
}

// jwksHandler returns a Gin handler that serves the JWKS.
func jwksHandler(km *KeyManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		jwks := km.JWKS()
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, jwks)
	}
}
