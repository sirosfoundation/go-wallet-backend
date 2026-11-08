package as

import (
	"context"
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
	IsBlacklisted(ctx context.Context, jti string) bool
	IsUserRevoked(ctx context.Context, userID string) bool
	Add(ctx context.Context, jti string, expiry time.Time) error
}

// tokenDeps groups the shared dependencies for token issuance handlers.
type tokenDeps struct {
	issuer *TokenIssuer
	policy PolicyEngine
	// ttlFunc, audiences and blacklist are used differently across the two
	// token-issuance paths: ttlFunc for both; audiences and blacklist only
	// by handleDelegationTokenRequest, which is the only path that verifies
	// an already-issued Bearer token rather than trusting a server-side
	// session record.
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
	// Audiences and Blacklist are used only by the delegation-exchange path
	// (handleDelegationTokenRequest), which is the only one that verifies an
	// already-issued Bearer token rather than trusting a server-side session
	// record - see #381/#382.
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
		blacklist: cfg.Blacklist,
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

		// The pseudonymous engine kind: a real session behind the mint,
		// a random pseudonym in the token (engine-parity.md §8 G3). Like
		// the anonymous branch it has no session-less form - checked
		// before the delegation fallthrough for the same clear-error
		// reason.
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
		return
	}

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = session.TenantID
	}

	// Enforce tenant scoping: session-based tokens cannot target a different tenant
	// unless the session itself is cross-tenant (TenantID == "*").
	if session.TenantID != "*" && tenantID != session.TenantID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "cannot issue token for a different tenant",
		})
		return
	}

	tac := TAC(req.TAC)
	if tac == "" {
		tac = session.MaxTAC
	}

	// An empty MaxTAC means the session grants no permissions.
	if session.MaxTAC == "" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "session has no granted permissions",
		})
		return
	}

	// Validate requested TAC is a subset of session MaxTAC.
	if !tac.IsSubsetOf(session.MaxTAC) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "requested permissions exceed session maximum",
		})
		return
	}

	issueToken(c, deps, session.UserID, session.UserID, req.Audience, tenantID, tac, session.ACR)
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
		return
	}

	// ACR proves this session came from a real authentication event. Every
	// login flow sets it, so this should be unreachable in practice, but
	// fail closed rather than mint a token with no authentication context
	// behind it at all if a session somehow lacks one.
	if session.ACR == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session has no authentication context"})
		return
	}

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = session.TenantID
	}

	// Enforce tenant scoping: identical to handleSessionTokenRequest - a
	// session-backed token (identity-free or not) cannot target a different
	// tenant unless the session itself is cross-tenant (TenantID == "*").
	if session.TenantID != "*" && tenantID != session.TenantID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "cannot issue token for a different tenant",
		})
		return
	}

	tac := TAC(req.TAC)
	if tac == "" {
		tac = TAC("r") // anonymous tokens default to read-only
	}

	// Anonymous tokens are capped to read-only regardless of what the
	// session's own MaxTAC allows.
	if !tac.IsSubsetOf(TAC("rl")) {
		c.JSON(http.StatusForbidden, gin.H{"error": "anonymous tokens are read-only"})
		return
	}

	// An empty MaxTAC means the session grants no permissions at all.
	if session.MaxTAC == "" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "session has no granted permissions",
		})
		return
	}

	// Validate requested TAC is a subset of session MaxTAC (in addition to
	// the read-only cap above - a session with only "w" granted, for
	// instance, still can't be used to mint even a read-only token).
	if !tac.IsSubsetOf(session.MaxTAC) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "requested permissions exceed session maximum",
		})
		return
	}

	issueToken(c, deps, "", "", req.Audience, tenantID, tac, session.ACR)
}

// handlePseudonymousTokenRequest issues the engine-transport token kind
// (engine-parity.md §8 G3): the caller's real, authenticated session
// stands behind the mint exactly as the session path's does, but the
// token's `sub` is a fresh random pseudonym - per mint, so it identifies
// nothing and cannot be correlated across mints. The privacy point: the
// remote engine consumes this kind and attributes its traffic to the
// TENANT, never to a person (its session store, its logs, its KV flow
// registry all key the tenant's pseudonym, which rotates with the
// token's TTL).
//
// The token is engine-shaped: `tac` defaults to and is capped at "ri" -
// the two flow gates the WMP engine enforces (read for OID4VCI's
// presentations... rather: read for OID4VP sharing an existing
// credential, insert for OID4VCI receiving a new one). Tenant claimed
// as today (the session's own, unless the session is cross-tenant).
// The policy sees the session's REAL subject - the question it answers
// is "may this authenticated user mint an engine token", which the
// pseudonym in the answer would not carry.
func handlePseudonymousTokenRequest(
	c *gin.Context,
	store SessionStore,
	deps *tokenDeps,
	sessionID string,
	req *TokenRequest,
) {
	session, err := store.Get(c.Request.Context(), sessionID)
	if err != nil || session == nil || !session.IsValid() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
		return
	}

	if session.ACR == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session has no authentication context"})
		return
	}

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = session.TenantID
	}

	// Enforce tenant scoping: identical to the other session-backed
	// paths - the pseudonym token cannot target a different tenant than
	// the session that minted it.
	if session.TenantID != "*" && tenantID != session.TenantID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "cannot issue token for a different tenant",
		})
		return
	}

	tac := TAC(req.TAC)
	if tac == "" {
		tac = TAC("ri") // the engine's own two flow gates
	}

	// The pseudonymous kind is capped to the engine's needs, regardless
	// of the session's own MaxTAC: read (present) and insert (receive) -
	// not "everything my session can do, minus my name".
	if !tac.IsSubsetOf(TAC("ri")) {
		c.JSON(http.StatusForbidden, gin.H{"error": "pseudonymous tokens are engine-scoped (read, insert)"})
		return
	}

	if session.MaxTAC == "" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "session has no granted permissions",
		})
		return
	}

	if !tac.IsSubsetOf(session.MaxTAC) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "requested permissions exceed session maximum",
		})
		return
	}

	// The minted subject: a fresh pseudonym per mint. It is NOT the
	// session's user id - the engine-mode deployments key the tenant,
	// never a person.
	pseudonym := "p-" + uuid.New().String()

	issueToken(c, deps, session.UserID, pseudonym, req.Audience, tenantID, tac, session.ACR)
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
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
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid delegating token"})
		return
	}

	// A revoked parent token must not be usable to mint a fresh, differently
	// -jti'd token - otherwise logout/account deletion (#382/#383) would not
	// actually stop re-delegation. Checks both the parent's own jti
	// (individually blacklisted, e.g. by AS logout - see LogoutHandler) and
	// its subject in bulk (account deletion - see
	// service.TokenBlacklist.RevokeUser): checking jti alone missed a
	// different, not-yet-blacklisted delegation-capable token for the same
	// deleted user still being exchangeable here (#391 review). Only fails
	// closed when a blacklist is actually wired (deps.blacklist != nil);
	// ASModule always wires one from NewBackendProvider, so this is only
	// ever nil in tests that don't care.
	if deps.blacklist != nil {
		ctx := c.Request.Context()
		if parentClaims.ID != "" && deps.blacklist.IsBlacklisted(ctx, parentClaims.ID) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "delegating token has been revoked"})
			return
		}
		if deps.blacklist.IsUserRevoked(ctx, parentClaims.Subject) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "delegating token's user has been revoked"})
			return
		}
	}

	// Delegating token must have the 'k' permission.
	if !parentClaims.TAC.Has(TACDelegate) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "delegating token lacks delegate (k) permission",
		})
		return
	}

	// Derive tenant — delegation must match or narrow.
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = parentClaims.TenantID
	}
	// Delegated token must have the same tenant_id, unless the parent has
	// cross-tenant scope ("*"), in which case it may be narrowed to a specific tenant.
	if parentClaims.TenantID != "*" && tenantID != parentClaims.TenantID {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "delegation cannot change tenant",
		})
		return
	}

	// Derive TAC — must be a subset of parent, and 'k' is stripped by default
	// unless explicitly requested (re-delegation).
	tac := TAC(req.TAC)
	if tac == "" {
		// Default: same as parent minus 'k'.
		tac = parentClaims.TAC.Without(TACDelegate)
	}

	// Validate downscoping: delegated TAC must be subset of parent TAC.
	// This is the complete security boundary for delegation - a delegated
	// token can never exceed what its own parent already had, regardless
	// of what SPOCP evaluation below would otherwise allow - see
	// rules/delegation.rules for why SPOCP itself doesn't independently
	// restrict this.
	if !tac.IsSubsetOf(parentClaims.TAC) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "delegated permissions exceed parent token",
		})
		return
	}

	issueToken(c, deps, parentClaims.Subject, parentClaims.Subject, req.Audience, tenantID, tac, parentClaims.ACR)
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

	// Build SPOCP query and evaluate. The policy sees the requester the
	// session stands behind (policySub); the minted subject (mintSub) is
	// what the token carries - the same value everywhere except the
	// pseudonymous engine kind, which mints a random per-mint pseudonym
	// while the policy still sees the real, authenticated user.
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
