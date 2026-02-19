package registry

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// JWTMiddleware validates JWT tokens and sets authentication status
// It only validates that the token is valid and from the expected issuer
// No user-specific claims are extracted or required
func JWTMiddleware(config JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Default to unauthenticated
		c.Set(string(AuthenticatedKey), false)

		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No auth header, check if auth is required
			if config.RequireAuth {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "Authorization header required",
				})
				c.Abort()
				return
			}
			c.Next()
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			if config.RequireAuth {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "Invalid authorization header format",
				})
				c.Abort()
				return
			}
			c.Next()
			return
		}

		tokenString := parts[1]

		// Reject validation if secret is empty (prevents empty-key HMAC attacks)
		if config.Secret == "" {
			logger.Debug("JWT secret is empty, rejecting token")
			if config.RequireAuth {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "Authentication not configured",
				})
				c.Abort()
				return
			}
			c.Next()
			return
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(config.Secret), nil
		}, jwt.WithIssuer(config.Issuer), jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}))

		if err != nil {
			logger.Debug("JWT validation failed", zap.Error(err))
			if config.RequireAuth {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "Invalid or expired token",
				})
				c.Abort()
				return
			}
			// Token invalid but auth not required, continue as unauthenticated
			c.Next()
			return
		}

		if !token.Valid {
			logger.Debug("JWT token not valid")
			if config.RequireAuth {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   "unauthorized",
					"message": "Invalid token",
				})
				c.Abort()
				return
			}
			c.Next()
			return
		}

		// Token is valid, mark as authenticated
		c.Set(string(AuthenticatedKey), true)
		logger.Debug("request authenticated")

		c.Next()
	}
}

// OptionalJWTMiddleware is a variant that never requires authentication
// but still validates tokens when present and sets authenticated status
func OptionalJWTMiddleware(config JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	// Force RequireAuth to false
	optionalConfig := config
	optionalConfig.RequireAuth = false
	return JWTMiddleware(optionalConfig, logger)
}
