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

// MetadataPath is where the AS serves its (minimal, RFC 8414-shaped) metadata,
// relative to the group the AS is mounted on (normally /auth). Separate
// processes such as the registry discover the issuer and jwks_uri from it.
const MetadataPath = "/.well-known/oauth-authorization-server"

// RegisterMetadataRoute serves {"issuer", "jwks_uri"} at MetadataPath.
func RegisterMetadataRoute(router gin.IRoutes, issuer, jwksURI string) {
	router.GET(MetadataPath, func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, gin.H{"issuer": issuer, "jwks_uri": jwksURI})
	})
}
