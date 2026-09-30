package middleware

import (
	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

// BuildLoginOIDCGateBinding constructs a service.OIDCGateBinding from the
// gin context's validated OIDC gate result and tenant (as set by
// OIDCGateMiddleware and TenantHeaderMiddleware respectively), for handlers
// that call service.WebAuthnService.FinishLogin. Returns nil if no OIDC gate
// result is present in context (the gate wasn't required for this request,
// or didn't run).
//
// Shared by internal/as.PasskeyHandlers.LoginFinish and
// internal/api/handlers.go's FinishWebAuthnLogin (#386, #408, #409) so the
// same tenant-aware binding construction - Issuer/Subject/Email plus the
// Audience/Claims FinishLogin re-validates against the credential's real
// tenant - isn't duplicated between the two otherwise-independent login
// paths.
func BuildLoginOIDCGateBinding(c *gin.Context) *service.OIDCGateBinding {
	oidcResult, exists := GetOIDCGateResultGin(c)
	if !exists {
		return nil
	}

	var email string
	if emailClaim, ok := oidcResult.Claims["email"].(string); ok {
		email = emailClaim
	}

	binding := &service.OIDCGateBinding{
		Issuer:  oidcResult.Issuer,
		Subject: oidcResult.Subject,
		Email:   email,
		// Record the full validated claims too, so FinishLogin can re-check
		// them against the credential's real tenant's own RequiredClaims -
		// see OIDCGateBinding.Claims's doc comment.
		Claims: oidcResult.Claims,
	}

	// Record which audience this token was actually validated against (this
	// request's header tenant's LoginOP) so FinishLogin can compare it
	// against the credential's real tenant's own configured audience -
	// issuer alone doesn't prove the token was meant for that tenant if two
	// tenants share an IdP domain. See OIDCGateBinding.Audience.
	if headerTenant, ok := GetTenant(c); ok {
		if loginOP := headerTenant.OIDCGate.GetLoginOP(); loginOP != nil {
			binding.Audience = loginOP.EffectiveAudience()
		}
	}

	return binding
}
