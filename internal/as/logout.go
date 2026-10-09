package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LogoutHandler handles DELETE /auth/session. It revokes the session and clears the session cookie.
//
// Best-effort, it also blacklists the bearer access token presented with the cookie, so a
// delegation-capable token cannot outlive the logout. The token's subject must match the session's
// UserID or nothing is blacklisted (otherwise a caller could revoke a stranger's token). blacklist may
// be nil; a missing, mismatched, expired or unparseable token is never an error.
func LogoutHandler(store SessionStore, issuer *TokenIssuer, blacklist TokenBlacklistChecker, insecureCookies bool, logger *zap.Logger) gin.HandlerFunc {
	opts := CookieOptions{Insecure: insecureCookies}
	return func(c *gin.Context) {
		sessionID := GetSessionCookie(c, opts)
		if sessionID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no session"})
			return
		}

		// Fetched before Revoke so a store that deletes rather than marks
		// revoked (MemorySessionStore doesn't, but this is defensive either
		// way) can't make the session's own UserID unavailable for the
		// subject-binding check below.
		session, sessErr := store.Get(c.Request.Context(), sessionID)

		if err := store.Revoke(c.Request.Context(), sessionID); err != nil {
			logger.Warn("session revocation failed",
				zap.String("session_id", sessionID),
				zap.Error(err),
			)
			// Don't expose internal errors — clear cookie regardless.
		}

		if blacklist != nil && sessErr == nil && session != nil {
			if bearerToken := extractBearerToken(c); bearerToken != "" {
				blacklistOwnBearerToken(c, bearerToken, session.UserID, issuer, blacklist, logger)
			}
		}

		ClearSessionCookie(c, opts)
		c.Status(http.StatusNoContent)
	}
}

// blacklistOwnBearerToken blacklists bearerToken's jti only if its subject matches sessionUserID;
// a mismatch is logged and ignored, never an error.
func blacklistOwnBearerToken(c *gin.Context, bearerToken, sessionUserID string, issuer *TokenIssuer, blacklist TokenBlacklistChecker, logger *zap.Logger) {
	if issuer == nil {
		return
	}
	// No audience restriction: only sub/jti/exp are needed.
	claims, err := issuer.ParseAndVerify(bearerToken, nil)
	if err != nil {
		return
	}
	if claims.Subject != sessionUserID {
		logger.Warn("logout: presented bearer token belongs to a different user than the session - not blacklisting",
			zap.String("session_user_id", sessionUserID),
		)
		return
	}
	if claims.ID == "" {
		return
	}
	if err := blacklist.Add(c.Request.Context(), claims.ID, claims.Expiry.Time()); err != nil {
		logger.Warn("failed to blacklist token on logout",
			zap.String("jti", claims.ID),
			zap.Error(err),
		)
	}
}
