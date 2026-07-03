package as

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// tokenDeps groups the shared dependencies for token issuance handlers.
type tokenDeps struct {
	issuer  *TokenIssuer
	policy  PolicyEngine
	ttlFunc func(string) time.Duration
	logger  *zap.Logger
}

// TokenResponse is the response body for POST /auth/token.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// TokenEndpointHandler creates the handler for POST /auth/token.
//
// Two authentication paths:
//  1. Session cookie → standard token issuance from session
//  2. Bearer token (no cookie) → delegation: the bearer token must contain
//     the 'k' (delegate) permission, and the issued token is downscoped.
func TokenEndpointHandler(
	store SessionStore,
	issuer *TokenIssuer,
	policy PolicyEngine,
	ttlFunc func(string) time.Duration,
	insecureCookies bool,
	logger *zap.Logger,
) gin.HandlerFunc {
	opts := CookieOptions{Insecure: insecureCookies}
	deps := &tokenDeps{issuer: issuer, policy: policy, ttlFunc: ttlFunc, logger: logger}
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

		// Determine auth path: anonymous (explicit flag), session cookie, or Bearer delegation.
		// Anonymous is checked first so it is honored even when a session cookie is present.
		if req.Anonymous {
			handleAnonymousTokenRequest(c, deps, &req)
		} else if sessionID := GetSessionCookie(c, opts); sessionID != "" {
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

	issueToken(c, deps, session.UserID, req.Audience, tenantID, tac, session.ACR)
}

// handleAnonymousTokenRequest issues a user-less token.
// The token has no subject ("sub") claim. TAC defaults to read-only.
// Policy rules must explicitly allow anonymous tokens.
func handleAnonymousTokenRequest(
	c *gin.Context,
	deps *tokenDeps,
	req *TokenRequest,
) {
	tac := TAC(req.TAC)
	if tac == "" {
		tac = TAC("r") // anonymous tokens default to read-only
	}

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = "default"
	}

	issueToken(c, deps, "", req.Audience, tenantID, tac, "")
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

	// Parse the delegating token without audience restriction — we need its claims.
	parentClaims, err := deps.issuer.ParseAndVerify(bearerToken, nil)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid delegating token"})
		return
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
	if !tac.IsSubsetOf(parentClaims.TAC) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "delegated permissions exceed parent token",
		})
		return
	}

	issueToken(c, deps, parentClaims.Subject, req.Audience, tenantID, tac, parentClaims.ACR)
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
func RegisterTokenEndpoint(
	group *gin.RouterGroup,
	store SessionStore,
	issuer *TokenIssuer,
	policy PolicyEngine,
	ttlFunc func(string) time.Duration,
	insecureCookies bool,
	logger *zap.Logger,
) {
	group.POST("/token", TokenEndpointHandler(store, issuer, policy, ttlFunc, insecureCookies, logger))
}
