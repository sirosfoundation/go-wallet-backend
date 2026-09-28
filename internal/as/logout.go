package as

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LogoutHandler handles DELETE /auth/session.
// It revokes the session (so no new access token can be minted from it via
// /auth/token) and clears the session cookie.
//
// It also, best-effort, blacklists the specific bearer access token
// presented alongside the session cookie (if any): revoking the session
// alone leaves that token fully usable against /auth/token's delegation
// path, which needs no live session at all - a delegation-capable token
// could otherwise keep minting fresh tokens for itself indefinitely even
// after "logout" (#391 review). issuer/blacklist may be nil (in which case
// this step is skipped); a missing, expired, or unparseable bearer token is
// not an error - the session is still revoked either way.
func LogoutHandler(store SessionStore, issuer *TokenIssuer, blacklist TokenBlacklistChecker, insecureCookies bool, logger *zap.Logger) gin.HandlerFunc {
	opts := CookieOptions{Insecure: insecureCookies}
	return func(c *gin.Context) {
		sessionID := GetSessionCookie(c, opts)
		if sessionID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no session"})
			return
		}

		if err := store.Revoke(c.Request.Context(), sessionID); err != nil {
			logger.Warn("session revocation failed",
				zap.String("session_id", sessionID),
				zap.Error(err),
			)
			// Don't expose internal errors — clear cookie regardless.
		}

		if issuer != nil && blacklist != nil {
			if bearerToken := extractBearerToken(c); bearerToken != "" {
				// No audience restriction: we only need this token's own
				// claims (jti/exp) to blacklist it, not to authorize
				// anything with it.
				if claims, err := issuer.ParseAndVerify(bearerToken, nil); err == nil && claims.ID != "" {
					if err := blacklist.Add(c.Request.Context(), claims.ID, claims.Expiry.Time()); err != nil {
						logger.Warn("failed to blacklist token on logout",
							zap.String("jti", claims.ID),
							zap.Error(err),
						)
					}
				}
			}
		}

		ClearSessionCookie(c, opts)
		c.Status(http.StatusNoContent)
	}
}
