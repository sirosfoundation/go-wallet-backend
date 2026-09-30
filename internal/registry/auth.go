package registry

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// AuthConfig configures the registry's request authentication. Tokens are
// validated by the same go-tokenauth validator the other roles use; the
// registry only adds the audience rule and the context keys its rate limiter
// reads (AuthenticatedKey, TenantIDKey).
type AuthConfig struct {
	// Validator validates Bearer tokens. May be nil only when RequireAuth is
	// false, in which case every request is treated as unauthenticated.
	Validator *validator.Validator

	// Tenants is consulted for enabled/known tenants when RequireAuth is true
	// (via middleware.TokenAuthMiddleware). When nil - the registry runs
	// without a tenant store - any tenant_id claim is accepted.
	Tenants middleware.TenantLookup

	// Blacklist optionally rejects tokens of revoked users.
	Blacklist middleware.TokenBlacklistChecker

	// RequireAuth rejects requests without a valid token with 401. When
	// false, requests without (or with an invalid) token continue as
	// unauthenticated.
	RequireAuth bool

	Logger *zap.Logger
}

// anyTenant accepts every tenant id; used when there is no tenant store.
type anyTenant struct{}

func (anyTenant) GetByID(_ context.Context, id domain.TenantID) (*domain.Tenant, error) {
	return &domain.Tenant{ID: id, Enabled: true}, nil
}

// AuthMiddlewares returns the authentication middleware chain for the
// registry routes.
//
// Audience rule: new-style (asymmetric) tokens must carry the
// "wallet-registry" audience; legacy HMAC tokens are never rejected on
// audience grounds (whether they are accepted at all is decided by
// as.legacy.enabled in the validator).
//
// After a successful validation the context has AuthenticatedKey=true and,
// when the token has a tenant_id claim, TenantIDKey set to it.
func AuthMiddlewares(cfg AuthConfig) []gin.HandlerFunc {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	if !cfg.RequireAuth {
		return []gin.HandlerFunc{optionalAuth(cfg.Validator, logger)}
	}

	tenants := cfg.Tenants
	if tenants == nil {
		tenants = anyTenant{}
	}
	strict := middleware.TokenAuthMiddleware(cfg.Validator, tenants, cfg.Blacklist, logger)
	return []gin.HandlerFunc{
		strict,
		func(c *gin.Context) {
			res := resultFrom(c)
			if res == nil || !audienceAllowed(res) {
				c.JSON(403, gin.H{"error": "Token audience not permitted for this endpoint"})
				c.Abort()
				return
			}
			markAuthenticated(c, res)
			c.Next()
		},
	}
}

func resultFrom(c *gin.Context) *claims.Result {
	v, ok := c.Get("tokenauth_result")
	if !ok {
		return nil
	}
	res, _ := v.(*claims.Result)
	return res
}

// audienceAllowed implements the registry audience rule.
func audienceAllowed(res *claims.Result) bool {
	if res.Mode == claims.ModeLegacy {
		return true
	}
	return res.HasAudience(config.RegistryAudience)
}

func markAuthenticated(c *gin.Context, res *claims.Result) {
	c.Set(string(AuthenticatedKey), true)
	// TokenAuthMiddleware defaults a missing tenant to "default"; the
	// registry has always keyed per-tenant behaviour on the token's own
	// tenant_id claim only, so an absent claim leaves the key unset.
	if res.TenantID != "" {
		c.Set(string(TenantIDKey), res.TenantID)
	} else if c.Keys != nil {
		delete(c.Keys, string(TenantIDKey))
	}
}

// optionalAuth recognises valid tokens but never rejects a request.
func optionalAuth(v *validator.Validator, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(string(AuthenticatedKey), false)

		if v == nil {
			c.Next()
			return
		}
		auth := c.GetHeader("Authorization")
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.Next()
			return
		}
		res, err := v.Validate(c.Request.Context(), strings.TrimSpace(parts[1]))
		if err != nil {
			logger.Debug("registry token validation failed, continuing unauthenticated", zap.Error(err))
			c.Next()
			return
		}
		if !audienceAllowed(res) {
			logger.Debug("registry token audience not permitted, continuing unauthenticated",
				zap.Strings("aud", res.Audience))
			c.Next()
			return
		}
		markAuthenticated(c, res)
		c.Next()
	}
}
