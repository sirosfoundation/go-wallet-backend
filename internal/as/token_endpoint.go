package as

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// TokenResponse is the response body for POST /auth/token.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// TokenEndpointHandler creates the handler for POST /auth/token.
// It resolves the session, builds a candidate token, evaluates SPOCP policy,
// and returns a signed access token or 403.
func TokenEndpointHandler(
	store SessionStore,
	issuer *TokenIssuer,
	policy PolicyEngine,
	ttlFunc func(string) time.Duration,
	logger *zap.Logger,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Resolve session from cookie.
		sessionID := GetSessionCookie(c)
		if sessionID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session required"})
			return
		}

		session, err := store.Get(c.Request.Context(), sessionID)
		if err != nil || session == nil || !session.IsValid() {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
			return
		}

		// 2. Parse request.
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

		// 3. Build candidate claims, merging request with session defaults.
		tenantID := req.TenantID
		if tenantID == "" {
			tenantID = session.TenantID
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

		// Validate TAC characters.
		if err := tac.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 4. Build SPOCP query and evaluate.
		query := BuildTokenQuery(session.UserID, req.Audience, tenantID, tac, session.ACR)

		allowed, err := policy.Evaluate(query)
		if err != nil {
			logger.Error("SPOCP evaluation error",
				zap.Error(err),
				zap.String("query", query),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "policy evaluation failed"})
			return
		}

		if !allowed {
			logger.Info("token request denied by policy",
				zap.String("user_id", session.UserID),
				zap.String("audience", req.Audience),
				zap.String("tenant_id", tenantID),
				zap.String("tac", string(tac)),
			)
			c.JSON(http.StatusForbidden, gin.H{"error": "denied by policy"})
			return
		}

		// 5. Issue signed access token.
		tokenStr, err := issuer.Issue(session.UserID, req.Audience, tenantID, tac, session.ACR)
		if err != nil {
			logger.Error("token issuance failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token issuance failed"})
			return
		}

		ttl := ttlFunc(req.Audience)

		c.JSON(http.StatusOK, TokenResponse{
			AccessToken: tokenStr,
			TokenType:   "Bearer",
			ExpiresIn:   int(ttl.Seconds()),
		})
	}
}

// RegisterTokenEndpoint registers POST /auth/token on the given router group.
func RegisterTokenEndpoint(
	group *gin.RouterGroup,
	store SessionStore,
	issuer *TokenIssuer,
	policy PolicyEngine,
	ttlFunc func(string) time.Duration,
	logger *zap.Logger,
) {
	group.POST("/token", TokenEndpointHandler(store, issuer, policy, ttlFunc, logger))
}
