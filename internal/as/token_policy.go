package as

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Token issuance policy, separated from the HTTP handlers.
//
// The three /auth/token paths (session cookie, anonymous, delegation) share
// most of their rules: tenant scoping, the "no granted permissions" refusal
// and the downscoping check were written out three times, with a comment on
// one copy saying it is "identical to handleSessionTokenRequest". A rule
// stated three times drifts, and none of it could be exercised without a
// *gin.Context. The rules live here as pure functions over a Session or a
// parent token's claims, and the handlers keep only the I/O: reading the
// session, consulting the blacklist, and writing the response.
//
// Revocation checks deliberately stay in the handlers. They are I/O against
// the revocation store with their own failure mode (503, not a policy
// refusal), and the session path needs the resolved TAC to apply the
// deletion-only exemption, so they cannot move ahead of the policy anyway.

// tokenError is a policy refusal: the HTTP status and message the endpoint
// answers with, plus the RFC 6749 section 5.2 error code that identifies the
// failure independently of its prose.
//
// Code is not on the wire yet. Every message below is byte-identical to what
// the handlers sent before, so this change is invisible to clients; emitting
// the registered code (with the message as error_description, as section 5.2
// prescribes) is a separate, breaking change that belongs in its own commit.
type tokenError struct {
	Status  int
	Code    string
	Message string
}

func (e *tokenError) Error() string { return e.Code + ": " + e.Message }

// RFC 6749 section 5.2 registered error codes.
const (
	oauthErrInvalidRequest = "invalid_request"
	oauthErrInvalidGrant   = "invalid_grant"
	oauthErrInvalidScope   = "invalid_scope"
	oauthErrInvalidClient  = "invalid_client"
)

var (
	errInvalidSession = &tokenError{http.StatusUnauthorized, oauthErrInvalidGrant, "invalid or expired session"}
	errNoAuthContext  = &tokenError{http.StatusUnauthorized, oauthErrInvalidGrant, "session has no authentication context"}
	errNoDelegateAuth = &tokenError{http.StatusUnauthorized, oauthErrInvalidClient, "authentication required"}
	errInvalidParent  = &tokenError{http.StatusUnauthorized, oauthErrInvalidGrant, "invalid delegating token"}
	errParentRevoked  = &tokenError{http.StatusUnauthorized, oauthErrInvalidGrant, "delegating token has been revoked"}
	errParentUserGone = &tokenError{http.StatusUnauthorized, oauthErrInvalidGrant, "delegating token's user has been revoked"}

	errTenantMismatch    = &tokenError{http.StatusForbidden, oauthErrInvalidRequest, "cannot issue token for a different tenant"}
	errNoGrantedPerms    = &tokenError{http.StatusForbidden, oauthErrInvalidScope, "session has no granted permissions"}
	errTACExceedsSession = &tokenError{http.StatusForbidden, oauthErrInvalidScope, "requested permissions exceed session maximum"}
	errAnonymousReadOnly = &tokenError{http.StatusForbidden, oauthErrInvalidScope, "anonymous tokens are read-only"}
	errNoDelegatePerm    = &tokenError{http.StatusForbidden, oauthErrInvalidScope, "delegating token lacks delegate (k) permission"}
	errDelegationTenant  = &tokenError{http.StatusForbidden, oauthErrInvalidRequest, "delegation cannot change tenant"}
	errTACExceedsParent  = &tokenError{http.StatusForbidden, oauthErrInvalidScope, "delegated permissions exceed parent token"}
)

// respondTokenError writes a policy refusal. It is the only place in the
// token endpoint that knows the error wire format.
func respondTokenError(c *gin.Context, err error) {
	var te *tokenError
	if !errors.As(err, &te) {
		te = &tokenError{http.StatusInternalServerError, "server_error", "token issuance failed"}
	}
	c.JSON(te.Status, gin.H{"error": te.Message})
}

// Anonymous tokens are narrowly scoped by design: identity-free, and capped
// regardless of what the session's own MaxTAC allows.
const (
	anonymousDefaultTAC = TAC("r")
	anonymousMaxTAC     = TAC("rl")
)

// authorizeSessionToken applies the policy for a token minted from a session
// cookie, returning the tenant and TAC to issue it with.
func authorizeSessionToken(s *Session, req *TokenRequest) (string, TAC, error) {
	tac := TAC(req.TAC)
	if tac == "" {
		tac = s.MaxTAC
	}
	return authorizeSessionScoped(s, req, tac, "")
}

// authorizeAnonymousToken applies the policy for a token that omits "sub".
// Despite the name this is not an unauthenticated path: the caller still
// holds a valid session, and that session must carry an ACR, so a token is
// never minted with no authentication event behind it.
func authorizeAnonymousToken(s *Session, req *TokenRequest) (string, TAC, error) {
	// Every login flow sets ACR, so this should be unreachable; fail closed
	// rather than mint a token with no authentication context at all.
	if s.ACR == "" {
		return "", "", errNoAuthContext
	}
	tac := TAC(req.TAC)
	if tac == "" {
		tac = anonymousDefaultTAC
	}
	return authorizeSessionScoped(s, req, tac, anonymousMaxTAC)
}

// authorizeSessionScoped is the policy both session-cookie paths share. cap,
// when non-empty, is a hard ceiling applied before the session's own MaxTAC:
// a session granting only "w" still cannot mint even a read-only anonymous
// token, so both checks are needed and neither subsumes the other.
func authorizeSessionScoped(s *Session, req *TokenRequest, tac, cap TAC) (string, TAC, error) {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = s.TenantID
	}
	// A session-backed token cannot target a different tenant unless the
	// session itself is cross-tenant.
	if s.TenantID != "*" && tenantID != s.TenantID {
		return "", "", errTenantMismatch
	}
	if cap != "" && !tac.IsSubsetOf(cap) {
		return "", "", errAnonymousReadOnly
	}
	// An empty MaxTAC means the session grants no permissions at all.
	if s.MaxTAC == "" {
		return "", "", errNoGrantedPerms
	}
	if !tac.IsSubsetOf(s.MaxTAC) {
		return "", "", errTACExceedsSession
	}
	return tenantID, tac, nil
}

// authorizeDelegationToken applies the policy for exchanging a delegation-
// capable Bearer token for a downscoped one. The subset check against the
// parent is the complete security boundary for delegation: a delegated token
// can never exceed what its parent already had, regardless of what SPOCP
// would otherwise allow (see rules/delegation.rules).
func authorizeDelegationToken(parent *AccessTokenClaims, req *TokenRequest) (string, TAC, error) {
	if !parent.TAC.Has(TACDelegate) {
		return "", "", errNoDelegatePerm
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = parent.TenantID
	}
	// Delegation must match or narrow: same tenant, unless the parent is
	// cross-tenant ("*"), in which case it may be narrowed to a specific one.
	if parent.TenantID != "*" && tenantID != parent.TenantID {
		return "", "", errDelegationTenant
	}
	tac := TAC(req.TAC)
	if tac == "" {
		// Default: same as parent, minus the right to re-delegate.
		tac = parent.TAC.Without(TACDelegate)
	}
	if !tac.IsSubsetOf(parent.TAC) {
		return "", "", errTACExceedsParent
	}
	return tenantID, tac, nil
}

// noopBlacklist is the TokenBlacklistChecker used when none is configured, so
// deps.blacklist is never nil and no caller has to branch on it. It answers
// "not revoked", which is exactly what the nil checks it replaces did.
//
// Only tests reach it: ASModule always wires a real blacklist through
// NewBackendProvider. Whether an unconfigured blacklist should instead fail
// closed is a deliberate behaviour change and not decided here; this type is
// where that decision would be made, rather than in eleven nil checks spread
// across six packages.
type noopBlacklist struct{}

func (noopBlacklist) IsBlacklisted(context.Context, string) (bool, error) { return false, nil }
func (noopBlacklist) IsUserRevoked(context.Context, string) (bool, error) { return false, nil }
func (noopBlacklist) Add(context.Context, string, time.Time) error        { return nil }

// blacklistOrNoop keeps a wired blacklist non-nil, so no caller has to branch
// on it. It is the one place the unconfigured default is decided: should that
// become "fail closed" rather than "not revoked", it changes here instead of
// at every call site.
func blacklistOrNoop(b TokenBlacklistChecker) TokenBlacklistChecker {
	if b == nil {
		return noopBlacklist{}
	}
	return b
}
