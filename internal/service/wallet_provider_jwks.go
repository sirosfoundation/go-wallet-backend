package service

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
)

// RegisterWalletProviderJWKSRoute registers a bare-root /.well-known/jwks.json
// endpoint serving the wallet provider's own signing public key, plus RFC
// 8414 OAuth 2.0 Authorization Server Metadata at
// /.well-known/oauth-authorization-server pointing to it via jwks_uri.
// Distinct from the AS module's JWKS (mounted at /auth/.well-known/jwks.json,
// a different key for a different purpose): relying parties that receive an
// iss-based WIA (WalletProvider.WIA.Mode == config.WIAModeIETF) resolve
// trust by discovering this metadata at the WIA's iss URL - the RFC 8414
// document is what lets standards-compliant JWKS discovery chains (e.g.
// SD-JWT VC §5.3 clients) find the key without any wallet-provider-specific
// knowledge.
//
// No-ops (never registers the routes) when the wallet provider has no
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

	issuer := wp.Issuer()
	if issuer == "" {
		return
	}
	router.GET("/.well-known/oauth-authorization-server", func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, gin.H{
			"issuer":   issuer,
			"jwks_uri": issuer + "/.well-known/jwks.json",
		})
	})
}
