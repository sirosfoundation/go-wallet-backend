package registry

import (
	"context"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audience"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/legacytoken"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// AuthConfig configures the registry's request authentication. Tokens are
// validated by the same go-tokenauth validator the other roles use; the
// registry only adds the audience rule and the context keys its rate limiter
// reads (AuthenticatedKey, TenantIDKey).
type AuthConfig struct {
	// Config supplies jwt.secret, used to read the refresh-token family (sid)
	// of legacy tokens for family revocation. When nil, legacy tokens cannot
	// be tied to a family and are rejected whenever a Blacklist is set (fail
	// closed).
	Config *config.Config

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

	// LegacyAudienceIndependent validates legacy HMAC tokens without checking
	// their "aud" claim (see legacytoken.ValidateAnyAudience): issuer
	// (Config.JWT.Issuer), expiry and signature (Config.JWT.Secret) are still
	// enforced, and the revocation/tenant checks below apply unchanged.
	// Asymmetric tokens still go through Validator with its audience list.
	// Set only for the deprecated registry.yaml compatibility path, which has
	// no server.rp_id to give the validator; never for the new config shape.
	LegacyAudienceIndependent bool

	Logger *zap.Logger
}

// validateFunc returns the token validation step: the go-tokenauth validator,
// except that, with LegacyAudienceIndependent, HMAC tokens are validated by
// legacytoken.ValidateAnyAudience and never reach the validator (so there is
// no fallback that could re-introduce an audience check or skip the issuer
// check).
func (cfg AuthConfig) validateFunc() func(context.Context, string) (*claims.Result, error) {
	return func(ctx context.Context, raw string) (*claims.Result, error) {
		if cfg.LegacyAudienceIndependent && legacytoken.IsHMAC(raw) {
			if cfg.Config == nil {
				return nil, errors.New("registry: no configuration for legacy token validation")
			}
			return legacytoken.ValidateAnyAudience(cfg.Config.JWT.Secret, []string{cfg.Config.JWT.Issuer}, raw)
		}
		return cfg.Validator.Validate(ctx, raw)
	}
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
//
// The registry has no user database and never serves user-scoped writes, so
// its token chain is given tokengate.NoUserRecords (an explicit no-op
// SID-AUTH-06 lookup: no record, no cut-off) rather than a real or nil one.
func AuthMiddlewares(cfg AuthConfig) []gin.HandlerFunc {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	if !cfg.RequireAuth {
		return []gin.HandlerFunc{optionalAuth(cfg, logger)}
	}

	tenants := cfg.Tenants
	if tenants == nil {
		tenants = anyTenant{}
	}
	mwCfg := cfg.Config
	if mwCfg == nil {
		mwCfg = &config.Config{}
	}
	strict := middleware.TokenAuthMiddlewareWithValidate(mwCfg, cfg.validateFunc(), tenants, cfg.Blacklist, tokengate.NoUserRecords{}, logger)
	return []gin.HandlerFunc{
		strict,
		func(c *gin.Context) {
			res := resultFrom(c)
			if res == nil || !audienceAllowed(res) {
				c.JSON(403, gin.H{"error": "Token audience not permitted for this endpoint"})
				c.Abort()
				return
			}
			// Per-jti revocation for every token type (go-tokenauth v0.4.0
			// only applies its own checker to asymmetric tokens).
			if cfg.Blacklist != nil && res.JTI != "" && cfg.Blacklist.IsBlacklisted(c.Request.Context(), res.JTI) {
				c.JSON(401, gin.H{"error": "Token has been revoked"})
				c.Abort()
				return
			}
			markAuthenticated(c, res)
			c.Next()
		},
	}
}

// acceptedInOptionalMode applies the same tenant and revocation checks as the
// strict chain; a failure downgrades the request to unauthenticated.
func acceptedInOptionalMode(c *gin.Context, cfg AuthConfig, res *claims.Result, rawToken string, logger *zap.Logger) bool {
	ctx := c.Request.Context()
	if cfg.Blacklist != nil {
		if (res.JTI != "" && cfg.Blacklist.IsBlacklisted(ctx, res.JTI)) || cfg.Blacklist.IsUserRevoked(ctx, res.UserID) {
			logger.Debug("registry token revoked, continuing unauthenticated")
			return false
		}
		// Refresh-token family revocation, legacy tokens only (as in
		// TokenAuthMiddleware). Fail closed: if the family cannot be
		// determined the token is not treated as authenticated.
		if res.Mode == claims.ModeLegacy {
			secret := ""
			if cfg.Config != nil {
				secret = cfg.Config.JWT.Secret
			}
			sid, err := legacytoken.ParseSID(secret, rawToken)
			if err != nil {
				logger.Debug("cannot determine refresh-token family of legacy registry token, continuing unauthenticated", zap.Error(err))
				return false
			}
			if sid != "" && cfg.Blacklist.IsFamilyRevoked(ctx, sid) {
				logger.Debug("registry token family revoked, continuing unauthenticated")
				return false
			}
		}
	}
	if cfg.Tenants != nil {
		tid := res.TenantID
		if tid == "" {
			tid = string(domain.DefaultTenantID)
		}
		t, err := cfg.Tenants.GetByID(ctx, domain.TenantID(tid))
		if err != nil || t == nil || !t.Enabled {
			logger.Debug("registry token tenant unknown or disabled, continuing unauthenticated", zap.String("tenant_id", tid))
			return false
		}
	}
	return true
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
	return audience.Allowed(res, true, config.RegistryAudience)
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
func optionalAuth(cfg AuthConfig, logger *zap.Logger) gin.HandlerFunc {
	v := cfg.Validator
	validate := cfg.validateFunc()
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
		rawToken := strings.TrimSpace(parts[1])
		res, err := validate(c.Request.Context(), rawToken)
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
		if !acceptedInOptionalMode(c, cfg, res, rawToken, logger) {
			c.Next()
			return
		}
		markAuthenticated(c, res)
		c.Next()
	}
}
