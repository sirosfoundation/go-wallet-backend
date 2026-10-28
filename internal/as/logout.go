package as

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// LogoutHandler handles DELETE /auth/session. It revokes the session and clears the session cookie.
//
// Best-effort, it also blacklists the bearer access token presented with the cookie, so a
// delegation-capable token cannot outlive the logout. The token's subject must match the session's
// UserID or nothing is blacklisted (otherwise a caller could revoke a stranger's token). blacklist may
// be nil; a missing, mismatched, expired or unparseable token is never an error. A session lookup or
// revocation storage failure returns 500 and keeps the cookie so the client can retry.
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

		// A missing session (nil, nil, or ErrSessionNotFound from Revoke) is
		// already logged out. Any other storage failure must not be reported
		// as success: keep the cookie so the client can retry.
		revokeErr := store.Revoke(c.Request.Context(), sessionID)
		if sessErr != nil || (revokeErr != nil && !errors.Is(revokeErr, ErrSessionNotFound)) {
			logger.Error("logout: session lookup or revocation failed",
				zap.String("session_id", sessionID),
				zap.NamedError("lookup_error", sessErr),
				zap.NamedError("revoke_error", revokeErr),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke session"})
			return
		}

		// A failed jti write is reported, not swallowed: the bearer token may
		// still be usable, so the cookie is kept - it is the client's only
		// credential for the retry. (The session itself is already revoked.)
		if blacklist != nil && session != nil {
			if bearerToken := extractBearerToken(c); bearerToken != "" {
				if err := blacklistOwnBearerToken(c.Request.Context(), bearerToken, session.UserID, issuer, blacklist, logger); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke token"})
					return
				}
			}
		}

		ClearSessionCookie(c, opts)
		c.Status(http.StatusNoContent)
	}
}

// blacklistOwnBearerToken blacklists bearerToken's jti only if its subject matches sessionUserID;
// a mismatch is logged and ignored, never an error. A failing blacklist write is returned so the
// caller can fail closed. The jti entry is never withdrawn: an Add error means "outcome unknown"
// and the token is being revoked anyway.
func blacklistOwnBearerToken(ctx context.Context, bearerToken, sessionUserID string, issuer *TokenIssuer, blacklist TokenBlacklistChecker, logger *zap.Logger) error {
	if issuer == nil {
		return nil
	}
	// No audience restriction: only sub/jti/exp are needed.
	claims, err := issuer.ParseAndVerify(bearerToken, nil)
	if err != nil {
		return nil
	}
	if claims.Subject != sessionUserID {
		logger.Warn("logout: presented bearer token belongs to a different user than the session - not blacklisting",
			zap.String("session_user_id", sessionUserID),
		)
		return nil
	}
	if claims.ID == "" {
		return nil
	}
	if err := blacklist.Add(ctx, claims.ID, claims.Expiry.Time()); err != nil {
		logger.Error("failed to blacklist token on logout",
			zap.String("jti", claims.ID),
			zap.Error(err),
		)
		return err
	}
	return nil
}
