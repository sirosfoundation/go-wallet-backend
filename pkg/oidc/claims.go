package oidc

import "reflect"

// ClaimsMatch compares expected and actual claim values.
// Supports subset matching for arrays (expected values must be present in actual).
//
// This lives here (rather than in pkg/middleware, where the OIDC gate first
// needed it, or in internal/service, which also needs it) so both packages
// can share one implementation without a dependency cycle: pkg/middleware's
// own tests import internal/service, so internal/service cannot import
// pkg/middleware without the test build cycling back on itself. pkg/oidc has
// no dependency on either, so it's the natural shared home for pure claim
// comparison logic - callers include pkg/middleware.OIDCGateMiddleware
// (validating a token against its own tenant's RequiredClaims) and
// internal/service.WebAuthnService.FinishLogin (re-validating a login
// credential's real tenant's own RequiredClaims - see
// service.OIDCGateBinding.Claims).
func ClaimsMatch(expected, actual interface{}) bool {
	switch e := expected.(type) {
	case bool:
		a, ok := actual.(bool)
		return ok && e == a
	case string:
		// String expected value can match either a string or be present in an array
		if a, ok := actual.(string); ok {
			return e == a
		}
		// Check if string is in array (e.g., expected: "admin", actual: ["admin", "user"])
		if arr, ok := actual.([]interface{}); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && s == e {
					return true
				}
			}
		}
		return false
	case float64:
		a, ok := actual.(float64)
		return ok && e == a
	case int:
		a, ok := actual.(float64)
		return ok && float64(e) == a
	case []interface{}:
		// For array expected values, check if all expected values are present in actual
		a, ok := actual.([]interface{})
		if !ok {
			// actual is not an array - check if single expected element matches
			if len(e) == 1 {
				return ClaimsMatch(e[0], actual)
			}
			return false
		}
		// All expected values must be present in actual (subset matching)
		for _, ev := range e {
			found := false
			for _, av := range a {
				if ClaimsMatch(ev, av) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default:
		// For complex types, use reflect.DeepEqual as fallback
		return reflect.DeepEqual(expected, actual)
	}
}
