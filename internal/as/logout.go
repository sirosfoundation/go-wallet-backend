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
// sidParser is a signature-only legacy HMAC parser used solely to read the
// presented bearer's sid and user_id for the pre-#402 family fallback. It is
// independent of legacyIssuer (which exists only when as.legacy.enabled), because
// /user/session/refresh stays mounted whenever jwt.refresh_days > 0 and can
// rotate a pre-#402 session's refresh token even with legacy authentication
// disabled; it never authenticates anything. nil falls back to legacyIssuer.
// legacyIssuer/blacklist may be nil (steps they'd perform are then
// skipped); a missing, mismatched, expired, or unparseable bearer token is
// never an error - the session is still revoked either way.
func LogoutHandler(store SessionStore, issuer *TokenIssuer, legacyIssuer, sidParser *LegacyTokenIssuer, blacklist TokenBlacklistChecker, familyRetention time.Duration, insecureCookies bool, logger *zap.Logger) gin.HandlerFunc {
	if sidParser == nil {
		sidParser = legacyIssuer
	}
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

		// Revoke the refresh-token family minted alongside this session at
		// login (#402): without it the paired refresh token stays usable
		// after AS logout. A failure here must not be reported as a clean
		// logout, so it surfaces as 500 (the session itself is already
		// revoked; the cookie is kept so the retry can work).
		//
		// The presented legacy bearer's own sid is revoked too: a session
		// created before #402 has an empty FamilyID, and once its refresh
		// token is rotated the replacement pair carries a freshly generated
		// sid that only the replacement JWTs know about.
		var bearerSID string
		if blacklist != nil && sessErr == nil && session != nil && sidParser != nil {
			if bearerToken := extractBearerToken(c); bearerToken != "" {
				if uid, sid, ok := sidParser.ParseSIDUnverifiedClaims(bearerToken); ok && uid == session.UserID {
					bearerSID = sid
				}
			}
		}
		familyErr := revokeSessionFamily(c.Request.Context(), session, sessErr, bearerSID, blacklist, familyRetention, logger)

		if familyErr != nil {
			// Keep the cookie: it is the client's only credential for the
			// idempotent retry that can still revoke the family. (The
			// session itself is already revoked.)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke refresh token"})
			return
		}
		ClearSessionCookie(c, opts)
		c.Status(http.StatusNoContent)
	}
}

// revokeSessionFamily revokes session.FamilyID via blacklist. It is a no-op
// when the session has no family (not paired with a legacy refresh token)
// or no blacklist is wired. A session lookup error or a failing RevokeFamily
// is returned so the caller can fail closed.
func revokeSessionFamily(ctx context.Context, session *Session, sessErr error, extraSID string, blacklist TokenBlacklistChecker, retention time.Duration, logger *zap.Logger) error {
	if blacklist == nil {
		return nil
	}
	if sessErr != nil {
		logger.Error("logout: session lookup failed, cannot revoke refresh-token family", zap.Error(sessErr))
		return sessErr
	}
	if session == nil {
		return nil
	}
	sids := []string{session.FamilyID}
	if extraSID != "" && extraSID != session.FamilyID {
		sids = append(sids, extraSID)
	}
	for _, sid := range sids {
		if sid == "" {
			continue
		}
		if err := blacklist.RevokeFamily(ctx, sid, time.Now().Add(retention)); err != nil {
			logger.Error("logout: failed to revoke refresh-token family",
				zap.String("sid", sid), zap.Error(err))
			return err
		}
	}
	return nil
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
