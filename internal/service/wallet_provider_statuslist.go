package service

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
)

// emptyStatusListSize is the number of entries in the always-empty status
// list this wallet provider publishes. The value is arbitrary — nothing this
// wallet provider issues ever references a status list index (see
// AttestationConfig's type-level comment) — so a small fixed size is enough
// to make the list well-formed.
const emptyStatusListSize = 1

// RegisterWalletProviderStatusListRoute registers a Token Status List
// endpoint that always serves a validly-shaped, all-VALID (never revoked)
// list, for interop completeness only: this wallet provider does not
// implement WIA/KA revocation-chaining (see AttestationConfig's type-level
// comment in pkg/config) — no WIA or KA this wallet provider issues ever
// references this endpoint's URI or an index within it.
//
// No-op (never registers the route) when the wallet provider has no signing
// key configured, mirroring RegisterWalletProviderJWKSRoute.
func RegisterWalletProviderStatusListRoute(router gin.IRoutes, wp *WalletProviderService) {
	if wp == nil || wp.jwtSigner == nil {
		return
	}

	// emptyStatusListSize is fixed, so the compressed list is the same on
	// every request - compute it once at registration time rather than
	// redoing the DEFLATE work on every call.
	lst, err := statuslist.EmptyCompressedList(emptyStatusListSize)
	if err != nil {
		router.GET("/wallet-provider/status-list", func(c *gin.Context) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "STATUS_LIST_GENERATION_FAILED"})
		})
		return
	}

	router.GET("/wallet-provider/status-list", func(c *gin.Context) {
		now := time.Now()
		claims := jwt.MapClaims{
			"iat": now.Unix(),
			"status_list": map[string]interface{}{
				"bits": 1,
				"lst":  lst,
			},
		}
		// iss/sub are set consistently regardless of x5c/kid below, so a
		// verifier can always identify and locate this wallet provider.
		// Trim BaseURL's trailing slash, if any, so sub doesn't end up with
		// a double slash before the path (unlike the JWKS route's issuer,
		// nothing else needs to match this iss byte-for-byte, so trimming
		// it too keeps both claims consistent with each other).
		if base := strings.TrimSuffix(wp.cfg.Server.BaseURL, "/"); base != "" {
			claims["iss"] = base
			claims["sub"] = base + "/wallet-provider/status-list"
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["typ"] = "statuslist+jwt"
		if len(wp.certChain) > 0 {
			token.Header["x5c"] = wp.certChain
		} else {
			// No x5c: without a kid, a verifier fetching
			// /.well-known/jwks.json (RegisterWalletProviderJWKSRoute, which
			// publishes this same key under KeyID "wallet-provider") would
			// have no way to select this key. Matches the WIA's own ietf-mode
			// kid handling in WIAService.signWIA.
			token.Header["kid"] = "wallet-provider"
		}

		tokenString, err := wp.jwtSigner.SignToken(token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "STATUS_LIST_SIGNING_FAILED"})
			return
		}

		c.Header("Cache-Control", "public, max-age=300")
		c.Data(http.StatusOK, "application/statuslist+jwt", []byte(tokenString))
	})
}
