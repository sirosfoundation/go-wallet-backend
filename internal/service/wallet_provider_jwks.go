package service

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
)

// RegisterWalletProviderJWKSRoute registers a bare-root /.well-known/jwks.json
// endpoint serving the wallet provider's own signing public key. Distinct
// from the AS module's JWKS (mounted at /auth/.well-known/jwks.json, a
// different key for a different purpose): relying parties that receive an
// iss-based WIA (WalletProvider.WIA.OmitX5C enabled) resolve trust by
// fetching this endpoint at the WIA's iss URL, per the well-known-endpoint
// discovery patterns trust registries use for JWK-identified issuers.
//
// No-ops (never registers the route) when the wallet provider has no
// signing key configured, so environments without WIA enabled see a plain
// 404 rather than a route that always errors.
func RegisterWalletProviderJWKSRoute(router gin.IRoutes, wp *WalletProviderService) {
	if wp == nil {
		return
	}
	pub := wp.PublicKey()
	if pub == nil {
		return
	}
	router.GET("/.well-known/jwks.json", func(c *gin.Context) {
		jwk := jose.JSONWebKey{
			Key:       pub,
			KeyID:     "wallet-provider",
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
}
