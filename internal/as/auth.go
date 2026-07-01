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

// errInternalError is the generic error message returned for internal server errors.
// Using a constant avoids duplicated string literals across handlers.
const errInternalError = "internal error"

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

// authenticateSession validates a session cookie and its associated access token.
// Returns the AuthContext on success, or an error string for the JSON response.
func authenticateSession(
	c *gin.Context,
	store SessionStore,
	tokenIssuer *TokenIssuer,
	audiences []string,
	insecureCookies bool,
) (*AuthContext, string) {
	sessionID := GetSessionCookie(c, CookieOptions{Insecure: insecureCookies})
	if sessionID == "" {
		return nil, ""
	}

	session, err := store.Get(c.Request.Context(), sessionID)
	if err != nil || session == nil || !session.IsValid() {
		return nil, "invalid or expired session"
	}

	bearerToken := extractBearerToken(c)
	if bearerToken == "" {
		return nil, "missing access token"
	}

	claims, err := tokenIssuer.ParseAndVerify(bearerToken, audiences)
	if err != nil {
		return nil, "invalid access token"
	}

	if claims.Subject != session.UserID {
		return nil, "access token does not match session"
	}

	if session.TenantID != "*" && claims.TenantID != session.TenantID {
		return nil, "access token tenant does not match session"
	}

	if !claims.TAC.IsSubsetOf(session.MaxTAC) {
		return nil, "access token exceeds session permissions"
	}

	return &AuthContext{
		UserID:   claims.Subject,
		TenantID: claims.TenantID,
		TAC:      claims.TAC,
		ACR:      claims.ACR,
		Mode:     ClientModeSession,
	}, ""
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
	insecureCookies bool,
	logger *zap.Logger,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Path 1: Session cookie present → new-style auth
		authCtx, errMsg := authenticateSession(c, store, tokenIssuer, audiences, insecureCookies)
		if errMsg != "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": errMsg})
			return
		}
		if authCtx != nil {
			c.Set(authContextKey, authCtx)
			c.Set(ContextKeyClientMode, ClientModeSession)
			logger.Debug("new-style auth",
				zap.String("user_id", authCtx.UserID),
				zap.String("tenant_id", authCtx.TenantID),
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
