package service

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// RegisterWalletProviderJWKSRoute registers a bare-root /.well-known/jwks.json
// endpoint serving the wallet provider's own signing public key, plus - only
// in "ietf" mode (see below) - RFC 8414 OAuth 2.0 Authorization Server
// Metadata at /.well-known/oauth-authorization-server pointing to it via
// jwks_uri. Distinct from the AS module's JWKS (mounted at
// /auth/.well-known/jwks.json, a different key for a different purpose):
// relying parties that receive an iss-based WIA
// (WalletProvider.WIA.Mode == config.WIAModeIETF) resolve trust by
// discovering this metadata at the WIA's iss URL - the RFC 8414 document is
// what lets standards-compliant JWKS discovery chains (e.g. SD-JWT VC §5.3
// clients) find the key without any wallet-provider-specific knowledge.
//
// The bare JWKS itself is served regardless of mode (harmless key
// publication), but the RFC 8414 metadata is gated on "ietf" mode: in "etsi"
// mode the WIA has no iss (identity is x5c-only), so advertising a
// jwks_uri-based discovery path would be actively misleading.
//
// No-ops (never registers the routes) when the wallet provider has no
// signing key configured, so environments without WIA enabled see a plain
// 404 rather than a route that always errors.
func RegisterWalletProviderJWKSRoute(router gin.IRoutes, wp *WalletProviderService) {
	if wp == nil || wp.cfg == nil {
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

	// The RFC 8414 metadata specifically advertises JWKS-based trust
	// discovery via jwks_uri, which is only meaningful in "ietf" mode - in
	// "etsi" mode the WIA intentionally has no iss (identity is x5c-only per
	// EC TS03 v1.5.2), so publishing this metadata would advertise a
	// discovery path relying parties have no reason to use and that doesn't
	// match how this wallet provider's WIAs actually carry identity.
	if wp.cfg.WalletProvider.WIA.Mode != config.WIAModeIETF {
		return
	}
	issuer := wp.Issuer()
	if issuer == "" {
		return
	}
	router.GET("/.well-known/oauth-authorization-server", func(c *gin.Context) {
		// jwks_uri is built from the issuer with any trailing slash trimmed,
		// to avoid a double slash before "/.well-known/jwks.json" - the
		// issuer claim itself stays byte-identical to the configured value,
		// since relying parties (e.g. vc's JWKSKeyResolver) match it exactly
		// against the WIA's own iss claim, which also uses the untrimmed
		// configured value.
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, gin.H{
			"issuer":   issuer,
			"jwks_uri": strings.TrimSuffix(issuer, "/") + "/.well-known/jwks.json",
		})
	})
}
