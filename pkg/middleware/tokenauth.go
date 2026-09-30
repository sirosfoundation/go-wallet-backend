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
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// TenantLookup is the subset of storage.TenantStore needed by TokenAuthMiddleware.
type TenantLookup interface {
	GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error)
}

// TokenAuthMiddleware is TokenAuthMiddlewareWithUsers without the user lookup,
// so it does NOT enforce the SID-AUTH-06 token cut-off: tokens issued before a
// wallet instance was revoked keep working. It exists only so that downstream
// code compiled against the previous exported signature keeps building, and
// nothing in this repository calls it (TestNoProductionCallerUsesTheWeakTokenAuthMiddleware
// keeps it that way).
//
// Deprecated: use TokenAuthMiddlewareWithUsers, which enforces the cut-off.
func TokenAuthMiddleware(v *validator.Validator, tenants TenantLookup, blacklist TokenBlacklistChecker, logger *zap.Logger) gin.HandlerFunc {
	return TokenAuthMiddlewareWithUsers(v, tenants, nil, blacklist, logger)
}

// TokenAuthMiddlewareWithUsers validates Bearer tokens using a go-tokenauth validator
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
// users may be nil; when set, tokens issued before the user's SID-AUTH-06
// authorization cut-off (User.AuthInvalidBefore) are refused with 401.
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
func TokenAuthMiddlewareWithUsers(v *validator.Validator, tenants TenantLookup, users tokengate.UserLookup, blacklist TokenBlacklistChecker, logger *zap.Logger) gin.HandlerFunc {
	gate := tokengate.New(users)
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
		result, err := v.Validate(c.Request.Context(), rawToken)
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

		// SID-AUTH-06 token cut-off. An anonymous token has no user to judge and
		// passes here; routes that need an identity refuse it with RequireUser.
		if !checkTokenGate(c, gate, result.UserID, tokengate.IssuedAt(rawToken), logger) {
			return
		}
		// Carried to the writes further down, which judge the token against
		// the user record they load (tokengate.RefuseLoaded).
		c.Request = c.Request.WithContext(tokengate.WithSubject(c.Request.Context(), result.UserID, tokengate.IssuedAt(rawToken)))

		tenant, tenantID, ok := resolveTokenTenant(c, tenants, result, logger)
		if !ok {
			return
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

// resolveTokenTenant looks up the token's tenant (an empty tenant_id means
// "default") and refuses the request when the tenant is unknown (401) or
// disabled (403). On refusal the response has been written and the request
// aborted, and ok is false. The JWT's tenant_id is authoritative; a
// mismatching X-Tenant-ID header is only logged.
func resolveTokenTenant(c *gin.Context, tenants TenantLookup, result *claims.Result, logger *zap.Logger) (tenant *domain.Tenant, tenantID string, ok bool) {
	tenantID = result.TenantID
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
		return nil, "", false
	}

	if !tenant.Enabled {
		logger.Warn("Token tenant is disabled",
			zap.String("tenant_id", tenantID),
			zap.String("mode", string(result.Mode)),
		)
		c.JSON(403, gin.H{"error": "Tenant is disabled"})
		c.Abort()
		return nil, "", false
	}

	// Log header mismatch (JWT is authoritative)
	if h := c.GetHeader("X-Tenant-ID"); h != "" && h != tenantID {
		logger.Warn("X-Tenant-ID header mismatches token tenant_id — using token (authoritative)",
			zap.String("header_tenant_id", h),
			zap.String("token_tenant_id", tenantID),
		)
	}
	return tenant, tenantID, true
}

// AnonymousTokenMessage is the error the routes that need an identity answer
// an anonymous token with.
const AnonymousTokenMessage = "anonymous tokens are not accepted on this route"

// RequireUser refuses a request whose bearer token names no user (an anonymous
// token: one the AS issued without "sub", or a legacy token with an empty
// user id) with 403. Anonymous tokens exist for registry lookups and public
// metadata (the AuthZEN proxy, the registry, VCTM lookups); every route that
// acts on a wallet, an account or a tenant's configuration on behalf of a
// user must sit behind it. The token gate cannot do this job: it judges a
// user against the lifecycle cut-off, and an anonymous token has no user to
// judge, so without this an anonymous token issued before a revocation or an
// account deletion would stay usable on wallet-scoped routes until it
// expires.
//
// Must be placed after the authentication middleware, which sets "user_id"
// only for a token that names a user.
func RequireUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		if userID, _ := c.Get("user_id"); userID == nil || userID == "" {
			c.JSON(403, gin.H{"error": AnonymousTokenMessage})
			c.Abort()
			return
		}
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
func RequireAudience(allowed ...string) gin.HandlerFunc {
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

		if !result.HasAudience(allowed...) {
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
