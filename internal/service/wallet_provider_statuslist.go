package service

import (
	"net/http"
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

	router.GET("/wallet-provider/status-list", func(c *gin.Context) {
		lst, err := statuslist.EmptyCompressedList(emptyStatusListSize)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "STATUS_LIST_GENERATION_FAILED"})
			return
		}

		now := time.Now()
		claims := jwt.MapClaims{
			"iat": now.Unix(),
			"status_list": map[string]interface{}{
				"bits": 1,
				"lst":  lst,
			},
		}
		if wp.cfg.Server.BaseURL != "" {
			claims["sub"] = wp.cfg.Server.BaseURL + "/wallet-provider/status-list"
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["typ"] = "statuslist+jwt"
		if len(wp.certChain) > 0 {
			token.Header["x5c"] = wp.certChain
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
