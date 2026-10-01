// Package audience holds the one audience-matching rule shared by the HTTP
// middleware and the engine WebSocket transport, in a dependency-light
// package so both can import it without a cycle.
package audience

import "github.com/sirosfoundation/go-tokenauth/claims"

// Allowed reports whether result's audience satisfies allowed.
//
// Legacy (HMAC) tokens are the user-session tokens minted by
// WebAuthnService/UserService; their "aud" is always Server.RPID, never one
// of the route-group audiences. go-tokenauth already validated it against
// AS.Audiences (Config.Validate requires the RP ID to be listed), so callers
// that pass admitLegacy=true accept them without an audience match -
// otherwise every real WebAuthn login token would be refused on routes
// guarded by "wallet-backend" unless the RP ID happened to equal that
// string. admitLegacy is an explicit parameter so every caller states
// whether it takes that exemption; pass false for any group that must be
// narrower than "any login token".
func Allowed(result *claims.Result, admitLegacy bool, allowed ...string) bool {
	if admitLegacy && result.Mode == claims.ModeLegacy {
		return true
	}
	return result.HasAudience(allowed...)
}
