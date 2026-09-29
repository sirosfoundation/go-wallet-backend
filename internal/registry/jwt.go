package registry

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"
	pkgconfig "github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// NewTokenValidator builds the session-token validator: ES256/ES384/EdDSA
// tokens are verified against the AS JWKS (when jwks_url is set) and HMAC
// tokens against jwt.secret only while legacy is enabled. The sunset date is
// additionally enforced per request by JWTMiddleware.
func NewTokenValidator(config JWTConfig) *tokenvalidator.Validator {
	asIssuer := config.ASIssuer
	if asIssuer == "" {
		asIssuer = config.Issuer
	}
	v := tokenvalidator.New(tokenvalidator.Config{
		JWKSURL:   config.JWKSURL,
		Issuer:    asIssuer,
		Audiences: config.Audiences,
		Legacy: tokenvalidator.LegacyConfig{
			// Empty secret must never enable HMAC (empty-key forgery).
			Enabled:    config.Secret != "" && (config.LegacyEnabled == nil || *config.LegacyEnabled),
			HMACSecret: []byte(config.Secret),
			Issuers:    []string{config.Issuer},
		},
	})
	return v
}

// LogLegacyStatus logs whether HMAC tokens are accepted, with a deprecation
// warning inside the 30-day window before jwt.legacy_sunset_date.
func (j JWTConfig) LogLegacyStatus(logger *zap.Logger, now time.Time) {
	sunset, hasSunset := time.Time{}, false
	if j.LegacySunsetDate != "" {
		if t, err := time.Parse(time.RFC3339, j.LegacySunsetDate); err == nil {
			sunset, hasSunset = t, true
		}
	}
	switch {
	case j.Secret == "" || (j.LegacyEnabled != nil && !*j.LegacyEnabled):
		logger.Info("legacy HMAC JWT validation is disabled", zap.Bool("jwks_configured", j.JWKSURL != ""))
	case !j.legacyActive(now):
		logger.Warn("legacy HMAC JWT validation is DISABLED: jwt.legacy_sunset_date has passed", zap.String("sunset_date", j.LegacySunsetDate))
	case hasSunset && sunset.Sub(now) <= pkgconfig.LegacySunsetWarnWindow:
		logger.Warn("DEPRECATION: legacy HMAC JWT validation will be disabled soon", zap.String("sunset_date", j.LegacySunsetDate))
	default:
		logger.Info("legacy HMAC JWT validation is enabled", zap.String("sunset_date", j.LegacySunsetDate))
	}
}

// JWTMiddleware validates JWT tokens and sets authentication status.
// When present and valid, it also extracts tenant_id from claims and sets it in context.
// This enables per-tenant authorization for authenticated endpoints.
func JWTMiddleware(config JWTConfig, logger *zap.Logger) gin.HandlerFunc {
	// Nothing can validate without a JWKS endpoint or an HMAC secret; in that
	// case no validator (and no background fetcher) is built and every token
	// is rejected.
	var validator *tokenvalidator.Validator
	if config.JWKSURL != "" || config.Secret != "" {
		validator = NewTokenValidator(config)
		if config.JWKSURL != "" {
			validator.Start(context.Background())
		}
	}
	return func(c *gin.Context) {
		// Default to unauthenticated
		c.Set(string(AuthenticatedKey), false)

		reject := func(status int, errCode, message string) {
			if config.RequireAuth {
				c.JSON(status, gin.H{"error": errCode, "message": message})
				c.Abort()
				return
			}
			c.Next()
		}

		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			reject(http.StatusUnauthorized, "unauthorized", "Authorization header required")
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			reject(http.StatusUnauthorized, "unauthorized", "Invalid authorization header format")
			return
		}

		tokenString := parts[1]

		if validator == nil {
			logger.Debug("no JWKS URL or JWT secret configured, rejecting token")
			reject(http.StatusUnauthorized, "unauthorized", "Authentication not configured")
			return
		}

		result, err := validator.Validate(c.Request.Context(), tokenString)
		if err != nil {
			logger.Debug("JWT validation failed", zap.Error(err))
			reject(http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			return
		}

		// Sunset enforcement, evaluated per request so a long-running
		// process stops accepting HMAC tokens at the sunset instant.
		if result.Mode == claims.ModeLegacy && !config.legacyActive(time.Now()) {
			logger.Debug("legacy JWT refused: legacy sunset date has passed")
			reject(http.StatusUnauthorized, "unauthorized", "Invalid or expired token")
			return
		}

		// Token is valid, mark as authenticated
		c.Set(string(AuthenticatedKey), true)

		if result.TenantID != "" {
			c.Set(string(TenantIDKey), result.TenantID)
			logger.Debug("request authenticated with tenant",
				zap.String("tenant_id", result.TenantID))
		} else {
			logger.Debug("request authenticated (no tenant_id in token)")
		}

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
