// Package middleware provides HTTP middleware for the wallet backend.
//
// TokenAuthMiddleware bridges go-tokenauth validation to the context keys
// that existing handlers expect (user_id, did, tenant_id, tenant).
package middleware

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audience"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/legacytoken"
)

// TenantLookup is the subset of storage.TenantStore needed by TokenAuthMiddleware.
type TenantLookup interface {
	GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error)
}

// TokenAuthMiddleware validates Bearer tokens using a go-tokenauth validator
// and populates the Gin context with the same keys that legacy AuthMiddleware
// sets, so existing handlers work unchanged.
//
// Context keys set on success:
//
//	"user_id"        (string)           — from claims.Result.UserID
//	"did"            (string)           — from claims.Result.DID
//	"tenant_id"      (string)           — from claims.Result.TenantID
//	"tenant"         (*domain.Tenant)   — looked up from the tenant store
//	"tenant_from_jwt" (bool)           — always true
//	"token"          (string)           — raw Bearer token
//	"tokenauth_result" (*claims.Result) — full validation result
//
// blacklist, when non-nil, is checked for user-level revocation
// (IsUserRevoked) after a token validates - see #391 review: per-jti
// revocation is already enforced *inside* v.Validate itself (the
// go-tokenauth Validator's own Revocation checker, wired in
// internal/server/providers.go to the same blacklist), but that checker's
// interface only takes a jti, not a user_id, so DeleteUser's user-level
// RevokeUser (#383) would otherwise never be consulted for tokens
// validated through this path - only for tokens validated through the
// legacy AuthMiddlewareWithBlacklist.
//
// cfg is used only to re-parse a legacy-mode token (result.Mode ==
// ModeLegacy) far enough to read its "sid" (refresh-token family) claim for
// the same family-revocation check (#402) - go-tokenauth's *claims.Result
// is shared with AS-issued tokens and deliberately doesn't expose a
// wallet-backend-specific claim like "sid", so this re-parses the same
// legacy HMAC token go-tokenauth already validated (see
// legacytoken.SID) rather than growing that shared type/module for one
// caller's claim.
func TokenAuthMiddleware(cfg *config.Config, v *validator.Validator, tenants TenantLookup, blacklist TokenBlacklistChecker, logger *zap.Logger) gin.HandlerFunc {
	return TokenAuthMiddlewareWithValidate(cfg, v.Validate, tenants, blacklist, logger)
}

// TokenAuthMiddlewareWithValidate is TokenAuthMiddleware with the token
// validation step supplied by the caller (validate must return the same
// *claims.Result a go-tokenauth Validator would, and an error to reject).
// Every check after validation - user, refresh-token family and tenant
// handling - is identical. It lets a caller route some tokens through a
// different validation (the registry's audience-independent legacy path)
// without duplicating the post-validation chain.
func TokenAuthMiddlewareWithValidate(cfg *config.Config, validate func(ctx context.Context, rawToken string) (*claims.Result, error), tenants TenantLookup, blacklist TokenBlacklistChecker, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract Bearer token
		rawToken := extractBearer(c)
		if rawToken == "" {
			logAuthReject(logger, c, "missing_or_malformed_bearer_token")
			c.JSON(401, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Validate via go-tokenauth (auto-detects new-style vs legacy HMAC).
		// Per-jti revocation is already checked inside Validate itself (see
		// this function's doc comment).
		result, err := validate(c.Request.Context(), rawToken)
		if err != nil {
			logAuthReject(logger, c, "token_validation_failed", zap.Error(err))
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// User-level revocation (#383/#391): rejects any token for a
		// deleted user, even one whose own jti was never individually
		// blacklisted. A no-op for anonymous tokens (empty UserID - see
		// TokenBlacklist.IsUserRevoked).
		if blacklist != nil && blacklist.IsUserRevoked(c.Request.Context(), result.UserID) {
			logger.Warn("Token for revoked user used",
				zap.String("user_id", result.UserID),
			)
			c.JSON(401, gin.H{"error": "Token has been revoked"})
			c.Abort()
			return
		}

		// Refresh-token family revocation (#402), legacy-mode tokens only:
		// go-tokenauth "auto-detects new-style vs legacy" (this function's
		// own doc comment above), so a WebAuthnService-issued legacy HMAC
		// token can reach this middleware instead of
		// AuthMiddlewareWithBlacklist whenever the AS is enabled - and
		// without this check, revoking its family on logout would be
		// silently ineffective for exactly that deployment mode. New-style
		// AS-issued tokens (ModeSession) have no sid/family concept at all;
		// only ModeLegacy is checked.
		if blacklist != nil && result.Mode == claims.ModeLegacy {
			// Fail closed: the token was already accepted above, so an
			// unverifiable re-parse means we cannot tell which family it
			// belongs to - reject rather than skip the check.
			sid, sidErr := legacytoken.ParseSID(cfg.JWT.Secret, rawToken)
			if sidErr != nil {
				logger.Warn("Cannot determine refresh-token family for legacy token", zap.Error(sidErr))
				c.JSON(401, gin.H{"error": "Invalid token"})
				c.Abort()
				return
			}
			if sid != "" && blacklist.IsFamilyRevoked(c.Request.Context(), sid) {
				logger.Warn("Token for revoked refresh-token family used",
					zap.String("sid", sid),
				)
				c.JSON(401, gin.H{"error": "Token has been revoked"})
				c.Abort()
				return
			}
		}

		// Tenant validation: look up and check enabled
		tenantID := result.TenantID
		if tenantID == "" {
			tenantID = "default"
		}

		tenant, err := tenants.GetByID(c.Request.Context(), domain.TenantID(tenantID))
		if err != nil {
			if err == storage.ErrNotFound {
				logger.Warn("Token contains invalid tenant_id",
					zap.String("tenant_id", tenantID),
					zap.String("mode", string(result.Mode)),
				)
				c.JSON(401, gin.H{"error": "Invalid tenant in token"})
			} else {
				logger.Error("Failed to lookup tenant from token",
					zap.String("tenant_id", tenantID),
					zap.Error(err),
				)
				c.JSON(500, gin.H{"error": "Internal server error"})
			}
			c.Abort()
			return
		}

		if !tenant.Enabled {
			logger.Warn("Token tenant is disabled",
				zap.String("tenant_id", tenantID),
				zap.String("mode", string(result.Mode)),
			)
			c.JSON(403, gin.H{"error": "Tenant is disabled"})
			c.Abort()
			return
		}

		// Log header mismatch (JWT is authoritative)
		if h := c.GetHeader("X-Tenant-ID"); h != "" && h != tenantID {
			logger.Warn("X-Tenant-ID header mismatches token tenant_id — using token (authoritative)",
				zap.String("header_tenant_id", h),
				zap.String("token_tenant_id", tenantID),
			)
		}

		// Populate context keys for existing handlers.
		//
		// user_id/did are deliberately only set when non-empty: an anonymous
		// token (see AS's handleAnonymousTokenRequest) validates successfully
		// with an empty UserID/DID, and the common handler idiom is
		// `val, exists := c.Get("user_id")`. If we always called c.Set here,
		// exists would be true even for an anonymous caller — a value of ""
		// looks like "we know who this is, and it's the empty string" rather
		// than "no identity at all". Handlers must be able to tell the two
		// apart via the exists boolean alone, without also remembering to
		// check for an empty string every time.
		if result.UserID != "" {
			c.Set("user_id", result.UserID)
		}
		if result.DID != "" {
			c.Set("did", result.DID)
		}
		c.Set("token", rawToken)
		c.Set("tenant_id", tenantID)
		c.Set("tenant", tenant)
		c.Set("tenant_from_jwt", true)
		c.Set("tokenauth_result", result)

		c.Next()
	}
}

// MustHaveTAC returns middleware that requires the token to contain all
// the specified TAC permission characters (e.g. "rw" for read+write).
// Must be placed after TokenAuthMiddleware in the middleware chain.
func MustHaveTAC(required string) gin.HandlerFunc {
	return func(c *gin.Context) {
		v, exists := c.Get("tokenauth_result")
		if !exists {
			c.JSON(401, gin.H{"error": "Not authenticated"})
			c.Abort()
			return
		}
		result, ok := v.(*claims.Result)
		if !ok || result == nil {
			c.JSON(401, gin.H{"error": "Not authenticated"})
			c.Abort()
			return
		}

		if !result.TAC.HasAll(required) {
			c.JSON(403, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAudience returns middleware that requires the token's "aud" claim
// to contain at least one of the given values. Must be placed after
// TokenAuthMiddleware in the middleware chain.
//
// This is a separate, narrower check from TokenAuthMiddleware's own
// audience validation: that only confirms the token's audience is *some*
// value from the deployment's shared Config.Audiences allowlist (e.g.
// "wallet-backend" OR "wallet-registry" OR "wallet-engine", whichever the
// operator configured) - it has no way to restrict a specific route group
// to a narrower audience than "anything the deployment accepts overall".
// RequireAudience is that narrower restriction, applied per route group -
// e.g. the AuthZEN proxy and engine transport only ever need
// "wallet-registry"/"wallet-backend" (identity-free calls), while general
// user-facing routes should reject a "wallet-registry"-only token even
// though the deployment as a whole accepts that audience for other
// purposes.
//
// LEGACY TOKEN EXEMPTION: RequireAudience admits ModeLegacy (HMAC login)
// tokens regardless of their audience (see audience.Allowed). That is correct
// for every group guarded today, but a group that must be restricted to a
// NARROWER audience (one ordinary login tokens must not reach) cannot use
// this function: it would silently admit them. Such a group must opt in to
// strictness by using RequireAudienceStrict instead.
func RequireAudience(allowed ...string) gin.HandlerFunc {
	return requireAudience(true, allowed)
}

// RequireAudienceStrict is RequireAudience without the ModeLegacy exemption:
// the token's audience must match one of allowed, whatever its mode. Use it
// for any future route group restricted to a narrower audience than the
// deployment-wide AS.Audiences.
func RequireAudienceStrict(allowed ...string) gin.HandlerFunc {
	return requireAudience(false, allowed)
}

func requireAudience(admitLegacy bool, allowed []string) gin.HandlerFunc {
	if len(allowed) == 0 {
		// allowed is fixed at route-registration time, not per-request, so
		// this is always a programming error, never a runtime condition -
		// panic here (once, at startup) rather than have the match loop
		// below silently 403 every request forever.
		panic("middleware: RequireAudience called with no allowed audiences")
	}
	return func(c *gin.Context) {
		v, exists := c.Get("tokenauth_result")
		if !exists {
			c.JSON(401, gin.H{"error": "Not authenticated"})
			c.Abort()
			return
		}
		result, ok := v.(*claims.Result)
		if !ok || result == nil {
			c.JSON(401, gin.H{"error": "Not authenticated"})
			c.Abort()
			return
		}

		// Legacy-token exemption is decided by admitLegacy (see audience.Allowed).
		if !audience.Allowed(result, admitLegacy, allowed...) {
			c.JSON(403, gin.H{"error": "Token audience not permitted for this endpoint"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// extractBearer extracts the token from the Authorization: Bearer header.
func extractBearer(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
