package service

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/statuslist"
)

// StatusListPath is the path RegisterWalletProviderStatusListRoute serves
// the wallet provider's own Token Status List on, and the path
// statusListURI appends to Server.BaseURL when no explicit URI is
// configured.
const StatusListPath = "/wallet-provider/status-list"

// Status list indices referenced by the WUA claims. CS-04 §7.2.3 offers two
// KA schemes; this is Option 1 (type-shared): every KA attesting keys held
// in the same kind of keystore references the same index, rather than each
// KA getting a fresh one. Option 2 (per-KA indices) would require
// allocating and persisting an index per KA, and would only be worth its
// cost if this wallet provider actually revoked through the list — it
// doesn't (see AttestationConfig's type-level comment), so every index
// below is permanently 0/VALID.
//
// The WIA's client_status shares a single index across all wallet
// instances for the same reason. Note the trade-off if that ever changes:
// a per-instance index makes instance-level revocation possible but is
// also a correlation handle across issuers, which is exactly what CS-04
// §7.2's "MUST NOT reuse the same per-KA index with different providers"
// rule exists to prevent.
const (
	// statusIndexWIA is the client_status index shared by every WIA.
	statusIndexWIA = 0

	// statusIndexKAHigh, ...Moderate and ...Basic are the type-shared
	// key_storage_status indices, one per keystore tier reported in the
	// KA's key_storage claim (see normalizeSecurityProperties, which maps
	// everything onto this iso_18045_* vocabulary).
	statusIndexKAHigh     = 1
	statusIndexKAModerate = 2
	statusIndexKABasic    = 3
)

// emptyStatusListSize is the number of entries in the always-empty status
// list this wallet provider publishes. It only has to cover the fixed
// indices above, rounded up to a whole byte so the published bitstring
// doesn't change size if another tier is added.
const emptyStatusListSize = 8

// kaStatusIndex maps a KA's normalized key_storage tiers onto the
// type-shared status list index for that keystore type (CS-04 §7.2.3
// Option 1). A KA carrying several tiers is indexed by its *lowest* one:
// the entry stands for the weakest keystore any attested key might be in,
// so an issuer reading it is never told the batch is better protected than
// it is. Falls back to the basic tier for an empty or unrecognized
// key_storage, matching normalizeSecurityProperties' own floor.
func kaStatusIndex(keyStorage []string) int {
	idx := -1
	for _, ks := range keyStorage {
		var candidate int
		switch ks {
		case "iso_18045_high":
			candidate = statusIndexKAHigh
		case "iso_18045_moderate", "iso_18045_enhanced-basic":
			candidate = statusIndexKAModerate
		default:
			candidate = statusIndexKABasic
		}
		// Indices are ordered strongest-first, so the lowest tier is the
		// highest index.
		if candidate > idx {
			idx = candidate
		}
	}
	if idx < 0 {
		return statusIndexKABasic
	}
	return idx
}

// statusListURI returns the URI the WUA status claims should reference:
// the explicitly configured one, or this wallet provider's own endpoint
// derived from Server.BaseURL. Returns "" when neither is available, which
// callers treat as "emit no status claim" — a status_list reference with
// no uri is worse than an absent claim, since a verifier can't even tell
// it's unresolvable until it tries.
func statusListURI(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if uri := strings.TrimSpace(cfg.WalletProvider.Attestation.StatusList.URI); uri != "" {
		return uri
	}
	base := strings.TrimSuffix(cfg.Server.BaseURL, "/")
	if base == "" {
		return ""
	}
	return base + StatusListPath
}

// statusClaim builds the shared body of the WIA's `client_status` and the
// KA's `key_storage_status` (CS-04 §7.1.2/§7.1.3, TS-03 clauses
// 2.3.1/2.3.2): a Token Status List reference plus the revocation
// *maintenance* commitment `exp`, which is deliberately independent of —
// and far longer than — the enclosing token's own exp (CS-04 §7.2's note;
// TS-03 clause 2.4.1).
//
// Returns nil when status claims are disabled or no URI can be determined,
// so callers can just skip setting the claim.
func statusClaim(cfg *config.Config, idx int, now time.Time) map[string]interface{} {
	if cfg == nil || !cfg.WalletProvider.Attestation.StatusList.Enabled {
		return nil
	}
	uri := statusListURI(cfg)
	if uri == "" {
		return nil
	}
	maintenance := cfg.WalletProvider.Attestation.StatusList.MaintenancePeriodSeconds
	if maintenance <= 0 {
		maintenance = config.StatusListRefMinMaintenanceSeconds
	}
	return map[string]interface{}{
		"status": map[string]interface{}{
			"status_list": map[string]interface{}{
				"uri": uri,
				"idx": idx,
			},
		},
		"exp": now.Add(time.Duration(maintenance) * time.Second).Unix(),
	}
}

// RegisterWalletProviderStatusListRoute registers the Token Status List
// endpoint that the `client_status` (WIA) and `key_storage_status` (KA)
// claims reference. It always serves a validly-shaped, all-VALID (never
// revoked) list: this wallet provider does not implement WUA
// revocation-chaining (see AttestationConfig's type-level comment in
// pkg/config), so no bit in it is ever set. The claims exist for CS-04
// §7.1 conformance; what actually bounds exposure is the short WIA/KA
// lifetime.
//
// No-op (never registers the route) when the wallet provider has no signing
// key configured, mirroring RegisterWalletProviderJWKSRoute.
func RegisterWalletProviderStatusListRoute(router gin.IRoutes, wp *WalletProviderService) {
	if wp == nil || wp.cfg == nil || wp.jwtSigner == nil {
		return
	}

	// emptyStatusListSize is fixed, so the compressed list is the same on
	// every request - compute it once at registration time rather than
	// redoing the DEFLATE work on every call.
	lst, err := statuslist.EmptyCompressedList(emptyStatusListSize)
	if err != nil {
		router.GET(StatusListPath, func(c *gin.Context) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "STATUS_LIST_GENERATION_FAILED"})
		})
		return
	}

	router.GET(StatusListPath, func(c *gin.Context) {
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
			claims["sub"] = base + StatusListPath
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
