package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// SessionCookieName is the name of the session cookie.
	// The __Host- prefix enforces: Secure, no Domain, Path=/.
	SessionCookieName = "__Host-session"
)

// CookieOptions configures session cookie behavior.
type CookieOptions struct {
	// MaxAge is the cookie max-age in seconds. 0 means session cookie (browser closes).
	// Should match the session TTL.
	MaxAge int
}

// DefaultCookieOptions returns production-safe cookie defaults.
func DefaultCookieOptions() CookieOptions {
	return CookieOptions{
		MaxAge: 0, // session cookie
	}
}

// SetSessionCookie sets the session cookie on the response.
// Path is always "/" to comply with the __Host- prefix requirements.
// SameSite=Strict is used (not Lax) because the AS session cookie is never
// needed on cross-site navigations — login/register are same-origin API calls,
// and OIDC callbacks use a separate state parameter for CSRF protection.
func SetSessionCookie(c *gin.Context, jti string, opts CookieOptions) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    jti,
		Path:     "/",
		MaxAge:   opts.MaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie removes the session cookie.
// Path is always "/" to comply with the __Host- prefix requirements.
func ClearSessionCookie(c *gin.Context, opts CookieOptions) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// GetSessionCookie extracts the session JTI from the request cookie.
// Returns empty string if the cookie is not present.
func GetSessionCookie(c *gin.Context) string {
	cookie, err := c.Request.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}
