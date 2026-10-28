package as

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
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

// respondTokenError writes a policy refusal. Together with
// refuseRevocationUnavailable it is the whole of this endpoint's knowledge of
// the error wire format; the policy itself (token_policy.go) has none and
// imports no web framework.
func respondTokenError(c *gin.Context, err error) {
	var te *tokenError
	if !errors.As(err, &te) {
		te = &tokenError{http.StatusInternalServerError, "server_error", "token issuance failed"}
	}
	c.JSON(te.Status, gin.H{"error": te.Message})
}

// respondCutoff answers a failed lifecycle cut-off check: a refusal is
// rendered as is, a store failure is logged and answered 500 "internal error".
func respondCutoff(c *gin.Context, deps *tokenDeps, err error) {
	var cc *cutoffCheckError
	if errors.As(err, &cc) {
		if deps.logger != nil {
			deps.logger.Error("token cut-off check failed", zap.Error(cc.err))
		}
		respondTokenError(c, errCutoffUnavailable)
		return
	}
	respondTokenError(c, err)
}

// respondRevocation answers a failed revocation check and is the only caller
// that has to tell the two kinds of failure apart: a refusal, which is a
// *tokenError, or a store that could not answer, which is anything else.
func respondRevocation(c *gin.Context, deps *tokenDeps, err error) {
	var te *tokenError
	if errors.As(err, &te) {
		respondTokenError(c, te)
		return
	}
	refuseRevocationUnavailable(c, deps.logger, err)
}

// sessionOwnerRevoked returns the refusal when the session's user has been
// revoked, or nil when a token may still be issued. Account deletion revokes
// the user before the sessions are purged, so an interrupted or
// unacknowledged deletion can leave a live session whose owner is already
// revoked.
//
// deletionOnly names the one token a revoked owner may still obtain: exactly
// the deletion permission, which is all DELETE /user/session needs and the
// only call the resource middleware lets a revoked user reach. It lets an
// interrupted deletion be completed after the previous access token expired,
// while every other token (including any anonymous one, whose missing "sub"
// would bypass the user revocation) stays refused.
func sessionOwnerRevoked(ctx context.Context, bl TokenBlacklistChecker, session *Session, deletionOnly bool, tac TAC) error {
	revoked, err := bl.IsUserRevoked(ctx, session.UserID)
	if err != nil {
		return err
	}
	if !revoked {
		return nil
	}
	if deletionOnly && tac == TAC(string(TACDelete)) {
		return nil
	}
	return errInvalidSession
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
	// gate refuses tokens issued before the user's SID-AUTH-06 cut-off (nil: none).
	gate *tokengate.Gate
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
	// Gate refuses tokens issued before the user's SID-AUTH-06 cut-off (nil: none).
	Gate   *tokengate.Gate
	Logger *zap.Logger
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
	deps := &tokenDeps{
		issuer:    cfg.Issuer,
		policy:    cfg.Policy,
		ttlFunc:   cfg.TTLFunc,
		audiences: cfg.Audiences,
		blacklist: blacklistOrNoop(cfg.Blacklist),
		logger:    cfg.Logger,
		gate:      cfg.Gate,
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
	if err := sessionPredatesCutoff(c.Request.Context(), deps.gate, session); err != nil {
		respondCutoff(c, deps, err)
		return
	}

	tenantID, tac, err := authorizeSessionToken(session, req)
	if err != nil {
		respondTokenError(c, err)
		return
	}

	// After the policy, because the deletion-only exemption needs the
	// resolved TAC. Both gates apply: the lifecycle cut-off above and the
	// shared revocation store here (a revoked owner may still obtain a
	// deletion-only token, which does not lift the cut-off).
	if err := sessionOwnerRevoked(c.Request.Context(), deps.blacklist, session, true, tac); err != nil {
		respondRevocation(c, deps, err)
		return
	}

	issueToken(c, deps, sessionSubject(session), session.UserID, req.Audience, tenantID, tac, session.ACR)
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
	if err := sessionPredatesCutoff(c.Request.Context(), deps.gate, session); err != nil {
		respondCutoff(c, deps, err)
		return
	}
	// Before the policy, and with no TAC: a revoked owner gets no anonymous
	// token at all, since a missing "sub" would bypass the user revocation.
	if err := sessionOwnerRevoked(c.Request.Context(), deps.blacklist, session, false, ""); err != nil {
		respondRevocation(c, deps, err)
		return
	}

	tenantID, tac, err := authorizeAnonymousToken(session, req)
	if err != nil {
		respondTokenError(c, err)
		return
	}

	issueToken(c, deps, sessionSubject(session), "", req.Audience, tenantID, tac, session.ACR)
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

	if err := parentTokenRevoked(c.Request.Context(), deps.blacklist, parentClaims); err != nil {
		respondRevocation(c, deps, err)
		return
	}

	// SID-AUTH-06: a delegating token issued before the revocation must not
	// mint a fresh one; the parent is judged, as a child would carry a fresh iat.
	parent := parentSubject(parentClaims, bearerToken)
	if err := parentPredatesCutoff(c.Request.Context(), deps.gate, parent); err != nil {
		respondCutoff(c, deps, err)
		return
	}

	tenantID, tac, err := authorizeDelegationToken(parentClaims, req)
	if err != nil {
		respondTokenError(c, err)
		return
	}

	issueToken(c, deps, parent, parentClaims.Subject, req.Audience, tenantID, tac, parentClaims.ACR)
}

// parentTokenRevoked returns the refusal when the delegating token may no
// longer be exchanged, or nil when it may. A revoked parent must not be
// usable to mint a fresh, differently-jti'd token, or logout and account
// deletion (#382/#383) would not actually stop re-delegation.
//
// The two checks below are independent and both are needed; see each.
func parentTokenRevoked(ctx context.Context, bl TokenBlacklistChecker, parent *AccessTokenClaims) error {
	if err := parentJTIRevoked(ctx, bl, parent.ID); err != nil {
		return err
	}
	return parentUserRevoked(ctx, bl, parent.Subject)
}

// parentJTIRevoked refuses a delegating token whose own jti was individually
// blacklisted, e.g. by AS logout (see LogoutHandler).
//
// A parent with no jti has nothing to look up and is passed to the user
// check, which is the only thing that can still refuse it.
func parentJTIRevoked(ctx context.Context, bl TokenBlacklistChecker, jti string) error {
	if jti == "" {
		return nil
	}
	revoked, err := bl.IsBlacklisted(ctx, jti)
	if err != nil {
		return err
	}
	if revoked {
		return errParentRevoked
	}
	return nil
}

// parentUserRevoked refuses a delegating token whose subject was revoked in
// bulk (account deletion - see service.TokenBlacklist.RevokeUser).
//
// It is not covered by the jti check: a different, not-yet-blacklisted
// delegation-capable token belonging to the same deleted user was still
// exchangeable here when only the jti was checked (#391 review).
func parentUserRevoked(ctx context.Context, bl TokenBlacklistChecker, subject string) error {
	revoked, err := bl.IsUserRevoked(ctx, subject)
	if err != nil {
		return err
	}
	if revoked {
		return errParentUserGone
	}
	return nil
}

// issueToken is the common path for the session, anonymous and delegation flows.
// subject is the credential behind the request, re-checked against the cut-off.
func issueToken(
	c *gin.Context,
	deps *tokenDeps,
	subject cutoffSubject,
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

	// SID-AUTH-06: a revocation landing since the check above must not be
	// handed a token with a fresh iat.
	if err := issuedAfterCutoff(c.Request.Context(), deps.gate, subject); err != nil {
		respondCutoff(c, deps, err)
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
