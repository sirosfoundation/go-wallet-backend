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
	// Secure sets the Secure flag. Should be true in production (HTTPS).
	Secure bool

	// Path is the cookie path. Defaults to "/".
	Path string

	// MaxAge is the cookie max-age in seconds. 0 means session cookie (browser closes).
	// Should match the session TTL.
	MaxAge int
}

// DefaultCookieOptions returns production-safe cookie defaults.
func DefaultCookieOptions() CookieOptions {
	return CookieOptions{
		Secure: true,
		Path:   "/",
		MaxAge: 0, // session cookie
	}
}

// SetSessionCookie sets the session cookie on the response.
func SetSessionCookie(c *gin.Context, jti string, opts CookieOptions) {
	path := opts.Path
	if path == "" {
		path = "/"
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    jti,
		Path:     path,
		MaxAge:   opts.MaxAge,
		Secure:   opts.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie removes the session cookie.
func ClearSessionCookie(c *gin.Context, opts CookieOptions) {
	path := opts.Path
	if path == "" {
		path = "/"
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		Secure:   opts.Secure,
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
