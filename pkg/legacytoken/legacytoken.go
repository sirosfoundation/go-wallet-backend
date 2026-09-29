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

import "github.com/golang-jwt/jwt/v5"

// SID re-parses rawToken - a legacy HMAC-signed token already validated
// elsewhere (by go-tokenauth's Validator, or directly) - to read its "sid"
// (refresh-token family/session id, #402) claim. Returns "" if the token
// can't be parsed with secret or carries no sid claim at all (e.g. minted
// before #402); callers must treat that as "no family to check", not an
// error.
func SID(secret, rawToken string) string {
	token, err := jwt.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return ""
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ""
	}

	sid, _ := claims["sid"].(string)
	return sid
}
