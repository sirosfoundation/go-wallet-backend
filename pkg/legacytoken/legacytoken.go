// Package legacytoken provides a minimal helper for re-parsing a legacy
// HMAC-signed access/refresh token (the all-in-one JWT format
// service.WebAuthnService issues - see its generateToken/
// generateRefreshToken doc comments) to reach a claim go-tokenauth's shared
// *claims.Result deliberately doesn't expose, without depending on either
// side that needs it.
//
// This lives here (rather than in pkg/middleware, where TokenAuthMiddleware
// first needed it, or in internal/api/internal/engine, which also need it)
// for the same reason pkg/oidc.ClaimsMatch does: pkg/middleware's own tests
// import internal/service, and internal/service imports internal/engine, so
// internal/engine cannot import pkg/middleware without the test build
// cycling back on itself. pkg/legacytoken has no dependency on any of them,
// so it's the natural shared home for this one pure, dependency-free helper
// - callers include pkg/middleware.TokenAuthMiddleware, internal/api.
// Handlers.Logout, and internal/engine.Manager.validateToken, each of which
// used to carry its own near-identical copy (SonarCloud flagged the
// resulting duplication on PR #414).
package legacytoken

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-tokenauth/claims"
)

// ErrUnparseable is returned by ParseSID when rawToken cannot be
// signature-verified with the secret (or is not a JWT map-claims token).
var ErrUnparseable = errors.New("legacytoken: token signature could not be verified")

// ParseSID re-parses rawToken - a legacy HMAC-signed token already
// validated elsewhere (by go-tokenauth's Validator, or directly) - to read
// its "sid" (refresh-token family/session id, #402) claim.
//
// Only the HMAC signature is verified here. Time claims (exp/nbf/iat) are
// deliberately NOT re-validated: every caller supplies a token the primary
// validator already accepted, including within its configured clock-skew
// leeway, and a second zero-leeway check made this parse fail inside that
// window - hiding the sid and so skipping the revoked-family check
// (fail-open).
//
// Returns ("", nil) for a verified token carrying no sid claim (e.g. minted
// before #402). Returns ErrUnparseable when the signature cannot be
// verified: callers that apply a family check MUST treat that as a failure
// (reject / refuse to report a clean logout), never as "no family".
func ParseSID(secret, rawToken string) (string, error) {
	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
		jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}),
	)
	token, err := parser.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil || token == nil || !token.Valid {
		return "", ErrUnparseable
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrUnparseable
	}

	sid, _ := claims["sid"].(string)
	return sid, nil
}

// SID is ParseSID without the error: it returns "" both when the token has
// no sid and when it cannot be verified. Only use it where that distinction
// does not matter; family checks must use ParseSID and fail closed.
func SID(secret, rawToken string) string {
	sid, _ := ParseSID(secret, rawToken)
	return sid
}

// IsHMAC reports whether rawToken's (unverified) header names an HMAC
// algorithm, i.e. whether it is a legacy token rather than a new-style
// asymmetric one. Nothing about the token is trusted by this; it only routes.
func IsHMAC(rawToken string) bool {
	tok, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil || tok == nil {
		return false
	}
	switch alg, _ := tok.Header["alg"].(string); alg {
	case "HS256", "HS384", "HS512":
		return true
	}
	return false
}

// legacyLeeway matches go-tokenauth's default clock-skew allowance.
const legacyLeeway = 5 * time.Second

type legacyClaims struct {
	jwt.RegisteredClaims
	UserID   string `json:"user_id"`
	DID      string `json:"did,omitempty"`
	TenantID string `json:"tenant_id"`
}

// ValidateAnyAudience validates a legacy HMAC token WITHOUT looking at its
// "aud" claim. It exists for the deprecated registry-only configuration, which
// has no server.rp_id to put in go-tokenauth's mandatory audience list (see
// config.Config.RegistryLegacyAudienceIndependent).
//
// Everything else is enforced as go-tokenauth's legacy path does, and
// fail-closed: HMAC signature (HS256/384/512 only, never "none" or an
// asymmetric alg) with a non-empty secret, "iss" equal to one of issuers
// (at least one required), and "exp" present and not past (5s leeway; nbf and
// iat are validated when present). Revocation (jti, user, refresh-token
// family) and tenant checks are applied by the caller's middleware chain
// exactly as for any other legacy token.
func ValidateAnyAudience(secret string, issuers []string, rawToken string) (*claims.Result, error) {
	if secret == "" {
		return nil, errors.New("legacytoken: no HMAC secret configured")
	}
	if len(issuers) == 0 {
		return nil, errors.New("legacytoken: no legacy issuers configured; refusing to validate without an issuer restriction")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}),
		jwt.WithLeeway(legacyLeeway),
		jwt.WithExpirationRequired(),
	)
	lc := &legacyClaims{}
	token, err := parser.ParseWithClaims(rawToken, lc, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("legacytoken: invalid legacy token: %w", err)
	}
	for _, iss := range issuers {
		// An empty configured issuer must never match a token without "iss".
		if iss != "" && lc.Issuer == iss {
			return &claims.Result{
				UserID:   lc.UserID,
				DID:      lc.DID,
				TenantID: lc.TenantID,
				JTI:      lc.ID,
				Mode:     claims.ModeLegacy,
				Audience: []string(lc.Audience),
			}, nil
		}
	}
	return nil, fmt.Errorf("legacytoken: legacy token issuer %q not accepted", lc.Issuer)
}
