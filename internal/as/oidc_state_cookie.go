package as

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
)

// oidcStateCookieSecure/Insecure name the browser-side cookie that binds the
// OIDC `state` parameter to the browser that started the login (see
// go-wallet-backend#385 / T-4). Without this, the `state` value is only
// checked against server-side storage: an attacker can complete their own
// OIDC login against a tenant's IdP, capture the resulting (state, code)
// callback URL, and hand it to a victim (e.g. via a crafted link, a login
// CSRF). The victim's browser has no prior relationship with that state, so
// the callback would otherwise succeed and log the victim into a session
// tied to the attacker's identity/consent. Requiring a cookie set at
// /auth/oidc/login and re-checked at /auth/oidc/callback means the callback
// only succeeds in the same browser that initiated the flow.
const (
	oidcStateCookieSecure   = "__Host-oidc-state"
	oidcStateCookieInsecure = "oidc-state"
)

// oidcStateCookieName returns the cookie name for the given insecure mode,
// consistent with CookieOptions.cookieName() in cookie.go.
func oidcStateCookieName(insecure bool) string {
	if insecure {
		return oidcStateCookieInsecure
	}
	return oidcStateCookieSecure
}

// signOIDCState computes an HMAC-SHA256 over the OIDC `state` value, keyed
// by jwt.secret (already validated to be >=32 bytes - see
// pkg/config.Config.Validate). This is jwt.secret's only remaining use now
// that legacy HMAC tokens are gone. The "oidc-state-cookie:" prefix
// domain-separates the MAC input from any other use of the secret.
func signOIDCState(secret []byte, state string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("oidc-state-cookie:" + state))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// oidcStateCookie builds the state-binding cookie. SameSite=Lax (not
// Strict, unlike the AS session cookie in cookie.go) because this cookie
// MUST be sent back on the cross-site top-level GET redirect the IdP issues
// to our callback endpoint - a Strict cookie is withheld on that navigation
// and the flow would always fail.
//
// Path is "/", not scoped to "/auth/oidc/callback": the "__Host-" name
// prefix (production/secure mode) requires Path=/ - browsers silently
// refuse to store a "__Host-" cookie with any other path, which would make
// every real OIDC callback fail with "state cookie mismatch" (the cookie
// this code expects to read back would never have been set in the first
// place). A narrower path doesn't buy meaningful isolation here anyway:
// the cookie is HttpOnly (never readable by page script) and its value is
// HMAC-signed, so carrying it on other requests discloses nothing and
// authorizes nothing on its own.
func oidcStateCookie(value string, maxAge int, insecure bool) *http.Cookie {
	ck := &http.Cookie{
		Name:     oidcStateCookieName(insecure),
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	// Reuses cookie_dev.go's isolated override (see its doc comment) rather
	// than repeating "ck.Secure = false" here, so the CodeQL/SonarCloud
	// suppression for that pattern stays in one place.
	overrideCookieSecure(ck, CookieOptions{Insecure: insecure})
	return ck
}

// setOIDCStateCookie sets the signed state-binding cookie at login-start.
func setOIDCStateCookie(c *gin.Context, secret []byte, state string, maxAge int, insecure bool) {
	http.SetCookie(c.Writer, oidcStateCookie(signOIDCState(secret, state), maxAge, insecure))
}

// clearOIDCStateCookie removes the state-binding cookie once consumed (or on
// failure), so it can't be replayed for a later callback.
func clearOIDCStateCookie(c *gin.Context, insecure bool) {
	http.SetCookie(c.Writer, oidcStateCookie("", -1, insecure))
}

// verifyOIDCStateCookie reports whether the request carries a state cookie
// whose signature matches the given state parameter.
func verifyOIDCStateCookie(c *gin.Context, secret []byte, state string, insecure bool) bool {
	cookie, err := c.Request.Cookie(oidcStateCookieName(insecure))
	if err != nil || cookie.Value == "" {
		return false
	}
	got, err1 := base64.RawURLEncoding.DecodeString(cookie.Value)
	want, err2 := base64.RawURLEncoding.DecodeString(signOIDCState(secret, state))
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(got, want)
}
