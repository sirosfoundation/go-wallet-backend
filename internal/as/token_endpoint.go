package as

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TokenBlacklistChecker is the token blacklist capability this package
// needs: checking whether a token has been revoked before it can be used
// to mint a delegated token - either the parent token's own jti (an
// explicit logout/revocation) or, in bulk, every token belonging to its
// subject (account deletion - see service.TokenBlacklist.RevokeUser) - and
// writing a new revocation (Add), used by LogoutHandler to blacklist the
// specific token being logged out. Mirrors pkg/middleware.
// TokenBlacklistChecker's read methods plus service.TokenBlacklist's own
// Add; *service.TokenBlacklist satisfies this.
type TokenBlacklistChecker interface {
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	IsUserRevoked(ctx context.Context, userID string) (bool, error)
	Add(ctx context.Context, jti string, expiry time.Time) error
}

// refuseRevocationUnavailable answers 503 when the revocation store cannot say
// whether a token is revoked. Only the error is logged, never token content.
func refuseRevocationUnavailable(c *gin.Context, logger *zap.Logger, err error) {
	if logger != nil {
		logger.Error("token request refused: revocation check failed", zap.Error(err))
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "revocation check unavailable"})
}

// sessionOwnerRevoked reports whether the session's user has been revoked
// (account deletion revokes the user before the sessions are purged, so an
// interrupted or unacknowledged deletion can leave a live session whose owner
// is already revoked). When it returns true a response has been written and
// the caller must stop: 401 for a revoked owner, 503 when the revocation
// store cannot say. Without a wired blacklist there is nothing to check.
//
// deletionOnly names the one token a revoked owner may still obtain: exactly
// the deletion permission, which is all DELETE /user/session needs and the
// only call the resource middleware lets a revoked user reach. It lets an
// interrupted deletion be completed after the previous access token expired,
// while every other token (including any anonymous one, whose missing "sub"
// would bypass the user revocation) stays refused.
func sessionOwnerRevoked(c *gin.Context, deps *tokenDeps, session *Session, deletionOnly bool, tac TAC) bool {
	revoked, err := deps.blacklist.IsUserRevoked(c.Request.Context(), session.UserID)
	if err != nil {
		refuseRevocationUnavailable(c, deps.logger, err)
		return true
	}
	if !revoked {
		return false
	}
	if deletionOnly && tac == TAC(string(TACDelete)) {
		return false
	}
	respondTokenError(c, errInvalidSession)
	return true
}

// tokenDeps groups the shared dependencies for token issuance handlers.
type tokenDeps struct {
	issuer *TokenIssuer
	policy PolicyEngine
	// ttlFunc, audiences and blacklist are used differently across the two
	// token-issuance paths: ttlFunc for both; audiences only by
	// handleDelegationTokenRequest, which verifies an already-issued Bearer
	// token. blacklist is used by every path: delegation checks the parent
	// token, the session paths check the session owner (sessionOwnerRevoked).
	ttlFunc   func(string) time.Duration
	audiences []string
	blacklist TokenBlacklistChecker
	logger    *zap.Logger
}

// TokenResponse is the response body for POST /auth/token.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// TokenEndpointConfig groups the dependencies for the /auth/token endpoint.
// Grouped into a struct (rather than individual parameters) to keep
// TokenEndpointHandler/RegisterTokenEndpoint's own signatures within reason
// - #381 added Audiences and Blacklist on top of the existing dependencies,
// which pushed the plain-parameter-list form over the usual limit.
type TokenEndpointConfig struct {
	Store   SessionStore
	Issuer  *TokenIssuer
	Policy  PolicyEngine
	TTLFunc func(string) time.Duration
	// Audiences is used only by the delegation-exchange path
	// (handleDelegationTokenRequest), which verifies an already-issued Bearer
	// token - see #381/#382. Blacklist is consulted by every path: delegation
	// checks the parent token; the session-cookie paths check that the
	// session's owner has not been revoked (account deletion).
	Audiences       []string
	Blacklist       TokenBlacklistChecker
	InsecureCookies bool
	Logger          *zap.Logger
}

// TokenEndpointHandler creates the handler for POST /auth/token.
//
// Two authentication paths:
//  1. Session cookie → standard token issuance from session (Anonymous, if
//     set, additionally omits "sub" from the issued token - see
//     handleAnonymousTokenRequest. It is NOT a third, unauthenticated path:
//     a valid session is still required either way.)
//  2. Bearer token (no cookie) → delegation: the bearer token must contain
//     the 'k' (delegate) permission, and the issued token is downscoped.
func TokenEndpointHandler(cfg TokenEndpointConfig) gin.HandlerFunc {
	opts := CookieOptions{Insecure: cfg.InsecureCookies}
	store := cfg.Store
	blacklist := cfg.Blacklist
	if blacklist == nil {
		// Kept non-nil so no handler has to branch on it; see noopBlacklist.
		blacklist = noopBlacklist{}
	}
	deps := &tokenDeps{
		issuer:    cfg.Issuer,
		policy:    cfg.Policy,
		ttlFunc:   cfg.TTLFunc,
		audiences: cfg.Audiences,
		blacklist: blacklist,
		logger:    cfg.Logger,
	}
	return func(c *gin.Context) {
		var req TokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
			return
		}

		// Audience is required per spec.
		if req.Audience == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "aud is required"})
			return
		}

		// Determine auth path: session cookie is required either way -
		// Anonymous only changes whether the issued token carries "sub".
		// There is deliberately no third, session-less path: an "anonymous"
		// token means "omit my identity from this specific token", not "no
		// authentication required at all" - see handleAnonymousTokenRequest.
		// Checked before the session-cookie branch below (rather than
		// falling through to Bearer-token delegation, a different and
		// unrelated auth path) so a caller who set Anonymous but sent no
		// session cookie gets a clear "authentication required" instead of
		// a confusing delegation-specific error.
		if req.Anonymous {
			sessionID := GetSessionCookie(c, opts)
			if sessionID == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
				return
			}
			handleAnonymousTokenRequest(c, store, deps, sessionID, &req)
			return
		}

		if sessionID := GetSessionCookie(c, opts); sessionID != "" {
			handleSessionTokenRequest(c, store, deps, sessionID, &req)
		} else {
			handleDelegationTokenRequest(c, deps, &req)
		}
	}
}

// handleSessionTokenRequest issues a token from a valid session.
func handleSessionTokenRequest(
	c *gin.Context,
	store SessionStore,
	deps *tokenDeps,
	sessionID string,
	req *TokenRequest,
) {
	session, err := store.Get(c.Request.Context(), sessionID)
	if err != nil || session == nil || !session.IsValid() {
		respondTokenError(c, errInvalidSession)
		return
	}

	tenantID, tac, err := authorizeSessionToken(session, req)
	if err != nil {
		respondTokenError(c, err)
		return
	}

	// After the policy, because the deletion-only exemption needs the
	// resolved TAC.
	if sessionOwnerRevoked(c, deps, session, true, tac) {
		return
	}

	issueToken(c, deps, session.UserID, req.Audience, tenantID, tac, session.ACR)
}

// handleAnonymousTokenRequest issues a token that omits the caller's
// identity ("sub"). Despite the name, this is NOT an unauthenticated path:
// the caller must have a valid, already-authenticated session, resolved and
// validated exactly like handleSessionTokenRequest. "Anonymous" means "omit
// my identity from this specific token" - e.g. for a privacy-preserving
// trust-evaluation or engine-transport call the caller doesn't want tied to
// their identity - not "no authentication required at all". A caller with
// no session never reaches this function (see TokenEndpointHandler).
//
// tenant_id and acr are threaded through from the real session exactly as
// handleSessionTokenRequest does: the "default" tenant gets no special
// treatment anywhere in this file, it is just whichever tenant the caller's
// own session happens to belong to. tac is additionally capped to read-only
// regardless of the session's own MaxTAC - the point of this path is a
// narrowly-scoped, identity-free token, not "everything my session can do,
// minus my name".
func handleAnonymousTokenRequest(
	c *gin.Context,
	store SessionStore,
	deps *tokenDeps,
	sessionID string,
	req *TokenRequest,
) {
	session, err := store.Get(c.Request.Context(), sessionID)
	if err != nil || session == nil || !session.IsValid() {
		respondTokenError(c, errInvalidSession)
		return
	}
	// Before the policy, and with no TAC: a revoked owner gets no anonymous
	// token at all, since a missing "sub" would bypass the user revocation.
	if sessionOwnerRevoked(c, deps, session, false, "") {
		return
	}

	tenantID, tac, err := authorizeAnonymousToken(session, req)
	if err != nil {
		respondTokenError(c, err)
		return
	}

	issueToken(c, deps, "", req.Audience, tenantID, tac, session.ACR)
}

// handleDelegationTokenRequest issues a downscoped token from a Bearer token
// that contains the 'k' (delegate) permission.
func handleDelegationTokenRequest(
	c *gin.Context,
	deps *tokenDeps,
	req *TokenRequest,
) {
	bearerToken := extractBearerToken(c)
	if bearerToken == "" {
		respondTokenError(c, errNoDelegateAuth)
		return
	}

	// Parse the delegating token, restricted to this AS's own accepted
	// audiences (config.ASConfig.Audiences - the same list go-tokenauth's
	// Validator enforces for every other resource-endpoint request, see
	// NewBackendProvider). Without this, a token minted for any audience at
	// all could be replayed here to mint a delegated token for a completely
	// different one (T-1). An empty deps.audiences skips the check, exactly
	// like ParseAndVerify's own "when empty, audience validation is skipped"
	// behavior for every other caller.
	parentClaims, err := deps.issuer.ParseAndVerify(bearerToken, deps.audiences)
	if err != nil {
		respondTokenError(c, errInvalidParent)
		return
	}

	if parentTokenRevoked(c, deps, parentClaims) {
		return
	}

	tenantID, tac, err := authorizeDelegationToken(parentClaims, req)
	if err != nil {
		respondTokenError(c, err)
		return
	}

	issueToken(c, deps, parentClaims.Subject, req.Audience, tenantID, tac, parentClaims.ACR)
}

// parentTokenRevoked reports whether the delegating token may no longer be
// exchanged. When it returns true a response has been written and the caller
// must stop: 401 for a revocation, 503 when the store cannot say.
//
// A revoked parent must not be usable to mint a fresh, differently-jti'd
// token - otherwise logout/account deletion (#382/#383) would not actually
// stop re-delegation. Both the parent's own jti (individually blacklisted,
// e.g. by AS logout - see LogoutHandler) and its subject in bulk (account
// deletion - see service.TokenBlacklist.RevokeUser) are checked: checking jti
// alone missed a different, not-yet-blacklisted delegation-capable token for
// the same deleted user still being exchangeable here (#391 review).
func parentTokenRevoked(c *gin.Context, deps *tokenDeps, parent *AccessTokenClaims) bool {
	ctx := c.Request.Context()
	if parent.ID != "" {
		jtiRevoked, err := deps.blacklist.IsBlacklisted(ctx, parent.ID)
		if err != nil {
			refuseRevocationUnavailable(c, deps.logger, err)
			return true
		}
		if jtiRevoked {
			respondTokenError(c, errParentRevoked)
			return true
		}
	}
	userRevoked, err := deps.blacklist.IsUserRevoked(ctx, parent.Subject)
	if err != nil {
		refuseRevocationUnavailable(c, deps.logger, err)
		return true
	}
	if userRevoked {
		respondTokenError(c, errParentUserGone)
		return true
	}
	return false
}

// issueToken is the common path for both session and delegation flows.
func issueToken(
	c *gin.Context,
	deps *tokenDeps,
	sub, audience, tenantID string,
	tac TAC,
	acr string,
) {
	// Validate TAC characters.
	if err := tac.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build SPOCP query and evaluate.
	query := BuildTokenQuery(sub, audience, tenantID, tac, acr)

	allowed, err := deps.policy.Evaluate(query)
	if err != nil {
		deps.logger.Error("SPOCP evaluation error",
			zap.Error(err),
			zap.String("query", query),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "policy evaluation failed"})
		return
	}

	if !allowed {
		deps.logger.Info("token request denied by policy",
			zap.String("user_id", sub),
			zap.String("audience", audience),
			zap.String("tenant_id", tenantID),
			zap.String("tac", string(tac)),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "denied by policy"})
		return
	}

	// Issue signed access token.
	tokenStr, err := deps.issuer.Issue(sub, audience, tenantID, tac, acr)
	if err != nil {
		deps.logger.Error("token issuance failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token issuance failed"})
		return
	}

	ttl := deps.ttlFunc(audience)

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
	})
}

// RegisterTokenEndpoint registers POST /auth/token on the given router group.
func RegisterTokenEndpoint(group *gin.RouterGroup, cfg TokenEndpointConfig) {
	group.POST("/token", TokenEndpointHandler(cfg))
}
