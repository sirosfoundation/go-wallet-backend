package middleware

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/oidc"
)

// OIDCGateContextKey is the context key for OIDC gate validation result
const OIDCGateContextKey = "oidc_gate_result"

// ValidatorCache caches OIDC validators per issuer
type ValidatorCache struct {
	mu         sync.RWMutex
	validators map[string]*oidc.Validator
	logger     *zap.Logger
}

// NewValidatorCache creates a new validator cache
func NewValidatorCache(logger *zap.Logger) *ValidatorCache {
	return &ValidatorCache{
		validators: make(map[string]*oidc.Validator),
		logger:     logger,
	}
}

// GetOrCreate returns an existing validator or creates a new one
func (c *ValidatorCache) GetOrCreate(config *domain.OIDCProviderConfig) *oidc.Validator {
	key := config.Issuer + "|" + config.ClientID

	c.mu.RLock()
	if v, ok := c.validators[key]; ok {
		c.mu.RUnlock()
		return v
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if v, ok := c.validators[key]; ok {
		return v
	}

	audience := config.Audience
	if audience == "" {
		audience = config.ClientID
	}

	v := oidc.NewValidator(oidc.ValidatorConfig{
		Issuer:   config.Issuer,
		Audience: audience,
		JWKSURI:  config.JWKSURI,
	}, c.logger)

	c.validators[key] = v
	return v
}

// OIDCGateMiddleware creates middleware that validates OIDC ID tokens for gated endpoints.
// It checks the tenant's OIDC gate configuration and validates tokens accordingly.
//
// Parameters:
//   - validatorCache: shared cache for OIDC validators
//   - gateType: "registration" or "login" - determines which gate config to check
//   - logger: zap logger
//
// The middleware expects TenantHeaderMiddleware to have run first to set the tenant in context.
// If OIDC gating is not enabled for this gate type, the request proceeds normally.
// If enabled, the Authorization header must contain a valid ID token.
func OIDCGateMiddleware(validatorCache *ValidatorCache, gateType string, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get tenant from context (set by TenantHeaderMiddleware)
		tenantVal, exists := c.Get("tenant")
		if !exists {
			// No tenant context - let request proceed (tenant middleware will handle)
			c.Next()
			return
		}

		tenant, ok := tenantVal.(*domain.Tenant)
		if !ok {
			c.JSON(500, gin.H{"error": "invalid tenant context"})
			c.Abort()
			return
		}

		// Check if OIDC gate is required for this gate type
		var requiresGate bool
		var opConfig *domain.OIDCProviderConfig

		switch gateType {
		case "registration":
			requiresGate = tenant.OIDCGate.RequiresGateForRegistration()
			opConfig = tenant.OIDCGate.GetRegistrationOP()
		case "login":
			requiresGate = tenant.OIDCGate.RequiresGateForLogin()
			opConfig = tenant.OIDCGate.GetLoginOP()
		default:
			logger.Error("invalid gate type", zap.String("gate_type", gateType))
			c.JSON(500, gin.H{"error": "internal server error"})
			c.Abort()
			return
		}

		if !requiresGate {
			// OIDC gate not required for this operation
			c.Next()
			return
		}

		if opConfig == nil {
			logger.Error("OIDC gate enabled but no OP configured",
				zap.String("tenant", string(tenant.ID)),
				zap.String("gate_type", gateType))
			c.JSON(500, gin.H{"error": "OIDC gate misconfigured"})
			c.Abort()
			return
		}

		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			respondOIDCRequired(c, opConfig, "Authorization header required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			respondOIDCRequired(c, opConfig, "Invalid authorization header format")
			return
		}

		tokenString := strings.TrimSpace(parts[1])
		if tokenString == "" {
			respondOIDCRequired(c, opConfig, "Token required")
			return
		}

		// Get or create validator for this OP
		validator := validatorCache.GetOrCreate(opConfig)

		// Validate the token
		result, err := validator.Validate(c.Request.Context(), tokenString)
		if err != nil {
			logger.Debug("OIDC token validation failed",
				zap.String("tenant", string(tenant.ID)),
				zap.String("gate_type", gateType),
				zap.Error(err))

			switch {
			case errors.Is(err, oidc.ErrTokenExpired):
				respondOIDCRequired(c, opConfig, "Token expired")
			case errors.Is(err, oidc.ErrInvalidSignature):
				respondOIDCRequired(c, opConfig, "Invalid token signature")
			case errors.Is(err, oidc.ErrInvalidIssuer):
				respondOIDCRequired(c, opConfig, "Invalid token issuer")
			case errors.Is(err, oidc.ErrInvalidAudience):
				respondOIDCRequired(c, opConfig, "Invalid token audience")
			case errors.Is(err, oidc.ErrMissingClaim), errors.Is(err, oidc.ErrClaimMismatch):
				respondOIDCRequired(c, opConfig, "Required claims not satisfied")
			default:
				respondOIDCRequired(c, opConfig, "Token validation failed")
			}
			return
		}

		// Validate required claims from tenant config
		if len(tenant.OIDCGate.RequiredClaims) > 0 {
			for key, expected := range tenant.OIDCGate.RequiredClaims {
				actual, exists := result.Claims[key]
				if !exists {
					logger.Debug("Missing required claim",
						zap.String("claim", key),
						zap.String("tenant", string(tenant.ID)))
					respondOIDCRequired(c, opConfig, "Missing required claim: "+key)
					return
				}
				if !claimsMatch(expected, actual) {
					logger.Debug("Claim mismatch",
						zap.String("claim", key),
						zap.Any("expected", expected),
						zap.Any("actual", actual))
					respondOIDCRequired(c, opConfig, "Claim mismatch: "+key)
					return
				}
			}
		}

		logger.Debug("OIDC gate passed",
			zap.String("tenant", string(tenant.ID)),
			zap.String("gate_type", gateType),
			zap.String("subject", result.Subject),
			zap.String("issuer", result.Issuer))

		// Store validation result in context for downstream handlers
		c.Set(OIDCGateContextKey, result)

		c.Next()
	}
}

// respondOIDCRequired sends a 401 response with OIDC gate information
func respondOIDCRequired(c *gin.Context, opConfig *domain.OIDCProviderConfig, message string) {
	c.JSON(401, gin.H{
		"error":   "oidc_gate_required",
		"message": message,
		"oidc_config": gin.H{
			"display_name": opConfig.EffectiveDisplayName(),
			"issuer":       opConfig.Issuer,
			"client_id":    opConfig.ClientID,
			"scopes":       opConfig.EffectiveScopes(),
		},
	})
	c.Abort()
}

// claimsMatch compares expected and actual claim values
func claimsMatch(expected, actual interface{}) bool {
	switch e := expected.(type) {
	case bool:
		a, ok := actual.(bool)
		return ok && e == a
	case string:
		a, ok := actual.(string)
		return ok && e == a
	case float64:
		a, ok := actual.(float64)
		return ok && e == a
	case int:
		a, ok := actual.(float64)
		return ok && float64(e) == a
	default:
		// For complex types, try direct comparison
		return expected == actual
	}
}

// GetOIDCGateResult returns the OIDC gate validation result from context
func GetOIDCGateResult(ctx context.Context) (*oidc.ValidationResult, bool) {
	if c, ok := ctx.(*gin.Context); ok {
		if val, exists := c.Get(OIDCGateContextKey); exists {
			if result, ok := val.(*oidc.ValidationResult); ok {
				return result, true
			}
		}
	}
	return nil, false
}

// GetOIDCGateResultGin returns the OIDC gate validation result from Gin context
func GetOIDCGateResultGin(c *gin.Context) (*oidc.ValidationResult, bool) {
	if val, exists := c.Get(OIDCGateContextKey); exists {
		if result, ok := val.(*oidc.ValidationResult); ok {
			return result, true
		}
	}
	return nil, false
}
