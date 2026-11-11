package as

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
	deps := &tokenDeps{
		issuer:    cfg.Issuer,
		policy:    cfg.Policy,
		ttlFunc:   cfg.TTLFunc,
		audiences: cfg.Audiences,
		blacklist: blacklistOrNoop(cfg.Blacklist),
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

		// The pseudonymous engine kind: a real session behind the mint, a
		// random pseudonym in the token (engine-parity.md §8 G3). Like the
		// anonymous branch it has no session-less form - checked before the
		// delegation fallthrough for the same clear-error reason.
		if req.Pseudonymous {
			sessionID := GetSessionCookie(c, opts)
			if sessionID == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
				return
			}
			handlePseudonymousTokenRequest(c, store, deps, sessionID, &req)
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
	if err := sessionOwnerRevoked(c.Request.Context(), deps.blacklist, session, true, tac); err != nil {
		respondRevocation(c, deps, err)
		return
	}

	issueToken(c, deps, session.UserID, session.UserID, req.Audience, tenantID, tac, session.ACR)
}

// handleIdentityKindToken is the shared shape of the session-backed
// identity kinds - the anonymous kind (the token omits "sub") and the
// pseudonymous engine kind (the token carries a fresh per-mint pseudonym,
// engine-parity.md §8 G3). Neither is an unauthenticated path: the caller
// must hold a valid, already-authenticated session, resolved and validated
// exactly like handleSessionTokenRequest's.
//
// The kind supplies its policy (the authorize function: the tenant scoping,
// the kind's own TAC ceiling, the session's grants) and its two subjects:
// the subject the POLICY sees (none at all for the anonymous kind; the
// session's real subject for the pseudonymous one - the question it answers
// is "may this authenticated user mint an engine token", which the pseudonym
// would not carry) and the subject the MINT carries.
//
// The revocation check runs before the policy, with the deletion-only
// exemption off and no TAC: a revoked owner gets no identity-kind token at
// all - the anonymous kind's missing "sub" would bypass the user revocation,
// and the pseudonymous kind's fresh sub would name nobody the revocation
// lists.
func handleIdentityKindToken(
	c *gin.Context,
	store SessionStore,
	deps *tokenDeps,
	sessionID string,
	req *TokenRequest,
	authorize func(*Session, *TokenRequest) (string, TAC, error),
	subs func(*Session) (policy, minted string),
) {
	session, err := store.Get(c.Request.Context(), sessionID)
	if err != nil || session == nil || !session.IsValid() {
		respondTokenError(c, errInvalidSession)
		return
	}
	if err := sessionOwnerRevoked(c.Request.Context(), deps.blacklist, session, false, ""); err != nil {
		respondRevocation(c, deps, err)
		return
	}

	tenantID, tac, err := authorize(session, req)
	if err != nil {
		respondTokenError(c, err)
		return
	}

	policySub, mintedSub := subs(session)
	issueToken(c, deps, policySub, mintedSub, req.Audience, tenantID, tac, session.ACR)
}

// handleAnonymousTokenRequest issues a token that omits the caller's
// identity ("sub"): a privacy-preserving, narrowly-scoped, identity-free
// token - tac capped to read-only regardless of the session's own MaxTAC -
// not "everything my session can do, minus my name". The policy sees no
// subject at all; tenant_id and acr thread through from the real session
// exactly as handleSessionTokenRequest's, the "default" tenant getting no
// special treatment anywhere in this file.
func handleAnonymousTokenRequest(
	c *gin.Context,
	store SessionStore,
	deps *tokenDeps,
	sessionID string,
	req *TokenRequest,
) {
	handleIdentityKindToken(c, store, deps, sessionID, req,
		authorizeAnonymousToken,
		func(*Session) (string, string) { return "", "" },
	)
}

// handlePseudonymousTokenRequest issues the engine-transport token kind
// (engine-parity.md §8 G3): the caller's real, authenticated session stands
// behind the mint, but the token's `sub` is a fresh random pseudonym - per
// mint, so it identifies nothing and cannot be correlated across mints. The
// privacy point: the remote engine consumes this kind and attributes its
// traffic to the TENANT, never to a person (its session store, its logs, its
// KV flow registry all key the tenant's pseudonym, which rotates with the
// token's TTL).
//
// The token is engine-shaped: `tac` defaults to and is capped at "ri" - the
// two flow gates the WMP engine enforces (read for OID4VP sharing an
// existing credential, insert for OID4VCI receiving a new one); the tenant
// claimed as today.
func handlePseudonymousTokenRequest(
	c *gin.Context,
	store SessionStore,
	deps *tokenDeps,
	sessionID string,
	req *TokenRequest,
) {
	handleIdentityKindToken(c, store, deps, sessionID, req,
		authorizePseudonymousToken,
		// The policy sees the session's REAL subject; the mint carries a
		// fresh pseudonym - NOT the user id.
		func(session *Session) (string, string) {
			return session.UserID, "p-" + uuid.New().String()
		},
	)
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

	tenantID, tac, err := authorizeDelegationToken(parentClaims, req)
	if err != nil {
		respondTokenError(c, err)
		return
	}

	issueToken(c, deps, parentClaims.Subject, parentClaims.Subject, req.Audience, tenantID, tac, parentClaims.ACR)
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

// issueToken is the common path for both session and delegation flows.
func issueToken(
	c *gin.Context,
	deps *tokenDeps,
	policySub, mintSub, audience, tenantID string,
	tac TAC,
	acr string,
) {
	// Validate TAC characters.
	if err := tac.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build SPOCP query and evaluate.
	query := BuildTokenQuery(policySub, audience, tenantID, tac, acr)

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
			zap.String("user_id", policySub),
			zap.String("audience", audience),
			zap.String("tenant_id", tenantID),
			zap.String("tac", string(tac)),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "denied by policy"})
		return
	}

	// Issue signed access token.
	tokenStr, err := deps.issuer.Issue(mintSub, audience, tenantID, tac, acr)
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
