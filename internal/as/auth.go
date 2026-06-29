package as

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AuthContext is the unified authentication context set by UnifiedAuthMiddleware.
// Downstream handlers see the same fields regardless of auth method.
type AuthContext struct {
	UserID   string
	DID      string
	TenantID string
	TAC      TAC
	ACR      string
	Mode     ClientMode
}

const authContextKey = "as_auth_context"

// GetAuthContext retrieves the AuthContext from a gin request context.
// Returns nil if no authentication was performed.
func GetAuthContext(c *gin.Context) *AuthContext {
	v, exists := c.Get(authContextKey)
	if !exists {
		return nil
	}
	ac, _ := v.(*AuthContext)
	return ac
}

// UnifiedAuthMiddleware validates both legacy bearer tokens and new-style
// session-based access tokens. It sets a unified AuthContext for downstream use.
//
// Flow:
//  1. Check for session cookie → new-style: validate asymmetric access token
//  2. No cookie, has Bearer token → try HMAC validation (legacy)
//  3. Neither → 401
func UnifiedAuthMiddleware(
	store SessionStore,
	tokenIssuer *TokenIssuer,
	legacyIssuer *LegacyTokenIssuer,
	audiences []string,
	logger *zap.Logger,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Path 1: Session cookie present → new-style auth
		sessionID := GetSessionCookie(c)
		if sessionID != "" {
			session, err := store.Get(c.Request.Context(), sessionID)
			if err != nil || session == nil || !session.IsValid() {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid or expired session",
				})
				return
			}

			// For new-style clients, require a Bearer access token signed by AS
			bearerToken := extractBearerToken(c)
			if bearerToken == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "missing access token",
				})
				return
			}

			claims, err := tokenIssuer.ParseAndVerify(bearerToken, audiences)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid access token",
				})
				return
			}

			// Verify the access token belongs to this session's user.
			if claims.Subject != session.UserID {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "access token does not match session",
				})
				return
			}

			// Verify the token's tenant matches the session (unless session is cross-tenant).
			if session.TenantID != "*" && claims.TenantID != session.TenantID {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "access token tenant does not match session",
				})
				return
			}

			// Verify the token's TAC is a subset of the session's MaxTAC.
			if !claims.TAC.IsSubsetOf(session.MaxTAC) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "access token exceeds session permissions",
				})
				return
			}

			c.Set(authContextKey, &AuthContext{
				UserID:   claims.Subject,
				TenantID: claims.TenantID,
				TAC:      claims.TAC,
				ACR:      claims.ACR,
				Mode:     ClientModeSession,
			})
			c.Set(ContextKeyClientMode, ClientModeSession)
			logger.Debug("new-style auth",
				zap.String("user_id", claims.Subject),
				zap.String("tenant_id", claims.TenantID),
			)
			c.Next()
			return
		}

		// Path 2: No session cookie, try legacy Bearer token
		bearerToken := extractBearerToken(c)
		if bearerToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			return
		}

		if legacyIssuer == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "legacy authentication disabled",
			})
			return
		}

		claims, err := legacyIssuer.Validate(bearerToken, audiences...)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		c.Set(authContextKey, &AuthContext{
			UserID:   claims.UserID,
			DID:      claims.DID,
			TenantID: claims.TenantID,
			Mode:     ClientModeLegacy,
		})
		c.Set(ContextKeyClientMode, ClientModeLegacy)
		logger.Debug("legacy auth",
			zap.String("user_id", claims.UserID),
			zap.String("tenant_id", claims.TenantID),
		)
		c.Next()
	}
}

// extractBearerToken extracts the token from the Authorization: Bearer header.
func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
