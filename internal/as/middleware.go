package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ContextKeySession is the Gin context key holding the validated *Session.
const ContextKeySession = "as_session"

// SessionMiddleware validates the session cookie and sets the session in context.
// If the session cookie is not present, it does NOT abort — downstream handlers
// decide whether a session is required (see RequireSession).
func SessionMiddleware(store SessionStore, insecureCookies bool, logger *zap.Logger) gin.HandlerFunc {
	opts := CookieOptions{Insecure: insecureCookies}
	return func(c *gin.Context) {
		jti := GetSessionCookie(c, opts)
		if jti == "" {
			// No session cookie: continue without a session.
			c.Next()
			return
		}

		session, err := store.Get(c.Request.Context(), jti)
		if err != nil {
			logger.Error("failed to look up session", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		if session == nil {
			// Cookie references a nonexistent session — treat as unauthenticated.
			logger.Debug("session not found", zap.String("jti", jti))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session not found"})
			return
		}
		if !session.IsValid() {
			logger.Debug("session expired or revoked",
				zap.String("jti", jti),
				zap.Bool("revoked", session.Revoked),
				zap.Time("expires_at", session.ExpiresAt),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
			return
		}

		c.Set(ContextKeySession, session)
		c.Next()
	}
}

// RequireSession is middleware that requires a valid session in context.
// Must be placed after SessionMiddleware.
func RequireSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, exists := c.Get(ContextKeySession); !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}
		c.Next()
	}
}

// GetSession extracts the session from the Gin context.
// Returns nil if not set (no session cookie).
func GetSession(c *gin.Context) *Session {
	v, exists := c.Get(ContextKeySession)
	if !exists {
		return nil
	}
	session, _ := v.(*Session)
	return session
}
