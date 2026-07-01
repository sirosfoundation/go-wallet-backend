package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// sessionCookieSecure is the session cookie name with __Host- prefix (production).
	sessionCookieSecure = "__Host-session"
	// sessionCookieInsecure is the session cookie name without prefix (dev over HTTP).
	sessionCookieInsecure = "session"
)

// CookieOptions configures session cookie behavior.
type CookieOptions struct {
	// MaxAge is the cookie max-age in seconds. 0 means session cookie (browser closes).
	// Should match the session TTL.
	MaxAge int
	// Insecure disables __Host- prefix and Secure flag for local HTTP development.
	Insecure bool
}

// DefaultCookieOptions returns production-safe cookie defaults.
func DefaultCookieOptions() CookieOptions {
	return CookieOptions{
		MaxAge:   0, // session cookie
		Insecure: false,
	}
}

// cookieName returns the appropriate cookie name based on Insecure flag.
func (o CookieOptions) cookieName() string {
	if o.Insecure {
		return sessionCookieInsecure
	}
	return sessionCookieSecure
}

// sessionCookie builds a session cookie with secure defaults.
// The Secure flag is always true unless the caller explicitly opts into
// insecure mode for local HTTP development.
func sessionCookie(name, value string, maxAge int, insecure bool) *http.Cookie {
	ck := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if insecure {
		ck.Secure = false
	}
	return ck
}

// SetSessionCookie sets the session cookie on the response.
// Path is always "/" to comply with the __Host- prefix requirements.
// SameSite=Strict is used (not Lax) because the AS session cookie is never
// needed on cross-site navigations — login/register are same-origin API calls,
// and OIDC callbacks use a separate state parameter for CSRF protection.
func SetSessionCookie(c *gin.Context, jti string, opts CookieOptions) {
	http.SetCookie(c.Writer, sessionCookie(opts.cookieName(), jti, opts.MaxAge, opts.Insecure))
}

// ClearSessionCookie removes the session cookie.
// Path is always "/" to comply with the __Host- prefix requirements.
func ClearSessionCookie(c *gin.Context, opts CookieOptions) {
	http.SetCookie(c.Writer, sessionCookie(opts.cookieName(), "", -1, opts.Insecure))
}

// GetSessionCookie extracts the session JTI from the request cookie.
// Returns empty string if the cookie is not present.
func GetSessionCookie(c *gin.Context, opts CookieOptions) string {
	cookie, err := c.Request.Cookie(opts.cookieName())
	if err != nil {
		return ""
	}
	return cookie.Value
}
