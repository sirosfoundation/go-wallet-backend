package as

import (
	"context"
	"net/http"
	"time"

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
// after "logout" (#391 review). Both the asymmetric issuer and the legacy
// HMAC issuer are tried, since a session cookie can be paired with either
// kind of bearer token depending on how the client authenticated (see
// PasskeyHandlers) - trying only the asymmetric one left a legacy bearer
// token silently un-blacklisted (#391 review, round 2). The parsed token's
// subject must match the session's own UserID, or it is not blacklisted at
// all: without that check, any caller with a valid session of their own
// could submit a stranger's token in the Authorization header and get it
// revoked as a denial-of-service (#391 review, round 2). issuer/
// legacyIssuer/blacklist may be nil (steps they'd perform are then
// skipped); a missing, mismatched, expired, or unparseable bearer token is
// never an error - the session is still revoked either way.
func LogoutHandler(store SessionStore, issuer *TokenIssuer, legacyIssuer *LegacyTokenIssuer, blacklist TokenBlacklistChecker, insecureCookies bool, logger *zap.Logger) gin.HandlerFunc {
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
				blacklistOwnBearerToken(c.Request.Context(), bearerToken, session.UserID, issuer, legacyIssuer, blacklist, logger)
			}
		}

		ClearSessionCookie(c, opts)
		c.Status(http.StatusNoContent)
	}
}

// blacklistOwnBearerToken parses bearerToken - trying the asymmetric issuer
// first, then the legacy HMAC one, since either kind can be presented
// alongside a session cookie - and blacklists its jti, but only if its
// subject matches sessionUserID (the session cookie's own owner). A
// mismatch is logged and otherwise ignored rather than treated as an
// error: refusing to revoke a token that isn't the caller's own is the
// safe behavior, not a failure of logout itself.
func blacklistOwnBearerToken(ctx context.Context, bearerToken, sessionUserID string, issuer *TokenIssuer, legacyIssuer *LegacyTokenIssuer, blacklist TokenBlacklistChecker, logger *zap.Logger) {
	if issuer != nil {
		// No audience restriction: we only need this token's own claims
		// (sub/jti/exp) to blacklist it, not to authorize anything with it.
		if claims, err := issuer.ParseAndVerify(bearerToken, nil); err == nil {
			if claims.Subject != sessionUserID {
				logger.Warn("logout: presented bearer token belongs to a different user than the session - not blacklisting",
					zap.String("session_user_id", sessionUserID),
				)
				return
			}
			if claims.ID == "" {
				return
			}
			if err := blacklist.Add(ctx, claims.ID, claims.Expiry.Time()); err != nil {
				logger.Warn("failed to blacklist token on logout",
					zap.String("jti", claims.ID),
					zap.Error(err),
				)
			}
			return
		}
	}

	if legacyIssuer != nil {
		if claims, err := legacyIssuer.Validate(bearerToken); err == nil {
			if claims.UserID != sessionUserID {
				logger.Warn("logout: presented legacy bearer token belongs to a different user than the session - not blacklisting",
					zap.String("session_user_id", sessionUserID),
				)
				return
			}
			if claims.ID == "" {
				return
			}
			expiry := time.Now().Add(24 * time.Hour) // shouldn't happen: legacy tokens always carry exp
			if claims.ExpiresAt != nil {
				expiry = claims.ExpiresAt.Time
			}
			if err := blacklist.Add(ctx, claims.ID, expiry); err != nil {
				logger.Warn("failed to blacklist legacy token on logout",
					zap.String("jti", claims.ID),
					zap.Error(err),
				)
			}
		}
	}
}
