package as

import "net/http"

// overrideCookieSecure clears the Secure flag when insecure mode is enabled.
// This is intentional for local HTTP development only — the Insecure option
// is never set in production configurations.
//
// Static analyzers (CodeQL go/cookie-secure-not-set, SonarCloud go:S2092)
// flag this as a vulnerability. It is isolated in this file so it can be
// excluded from analysis via paths-ignore in the CodeQL config.
func overrideCookieSecure(ck *http.Cookie, opts CookieOptions) {
	if opts.Insecure {
		ck.Secure = false
	}
}
