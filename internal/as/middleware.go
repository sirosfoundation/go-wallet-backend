package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Context keys for session data.
const (
	ContextKeySession    = "as_session"
	ContextKeyClientMode = "as_client_mode"
)

// ClientMode indicates whether the request is from a legacy or new-style client.
type ClientMode string

const (
	ClientModeLegacy  ClientMode = "legacy"
	ClientModeSession ClientMode = "session"
)

// SessionMiddleware validates the session cookie and sets the session in context.
// If the session cookie is not present, it does NOT abort — downstream handlers
// or the legacy middleware path may handle the request.
func SessionMiddleware(store SessionStore, insecureCookies bool, logger *zap.Logger) gin.HandlerFunc {
	opts := CookieOptions{Insecure: insecureCookies}
	return func(c *gin.Context) {
		jti := GetSessionCookie(c, opts)
		if jti == "" {
			// No session cookie — mark as legacy mode and continue.
			c.Set(ContextKeyClientMode, ClientModeLegacy)
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
		c.Set(ContextKeyClientMode, ClientModeSession)
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
// Returns nil if not set (legacy client path).
func GetSession(c *gin.Context) *Session {
	v, exists := c.Get(ContextKeySession)
	if !exists {
		return nil
	}
	session, _ := v.(*Session)
	return session
}

// GetClientMode extracts the client mode from the Gin context.
func GetClientMode(c *gin.Context) ClientMode {
	v, exists := c.Get(ContextKeyClientMode)
	if !exists {
		return ClientModeLegacy
	}
	mode, _ := v.(ClientMode)
	return mode
}
