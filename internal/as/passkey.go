package as

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// WebAuthnProvider is the interface for WebAuthn operations needed by the AS.
// This abstraction allows testing with mocks.
type WebAuthnProvider interface {
	BeginLogin(ctx context.Context) (*service.BeginLoginResponse, error)
	FinishLogin(ctx context.Context, req *service.FinishLoginRequest) (*service.FinishLoginResponse, error)
	BeginRegistration(ctx context.Context, req *service.BeginRegistrationRequest) (*service.BeginRegistrationResponse, error)
	FinishRegistration(ctx context.Context, req *service.FinishRegistrationRequest) (*service.FinishRegistrationResponse, error)
}

// PasskeyHandlers provides the new AS wrappers around the existing WebAuthnService.
// On successful authentication, they create an AS session and set the session cookie.
// For legacy clients (no X-Token-Mode: session header), the existing response format
// is preserved.
type PasskeyHandlers struct {
	webauthn     WebAuthnProvider
	sessions     SessionStore
	legacyIssuer *LegacyTokenIssuer
	cfg          *config.ASConfig
	logger       *zap.Logger
}

// NewPasskeyHandlers creates passkey auth handlers for the AS.
func NewPasskeyHandlers(
	webauthn WebAuthnProvider,
	sessions SessionStore,
	legacyIssuer *LegacyTokenIssuer,
	cfg *config.ASConfig,
	logger *zap.Logger,
) *PasskeyHandlers {
	return &PasskeyHandlers{
		webauthn:     webauthn,
		sessions:     sessions,
		legacyIssuer: legacyIssuer,
		cfg:          cfg,
		logger:       logger,
	}
}

// LoginBegin handles POST /auth/passkey/login/begin.
// Delegates to WebAuthnService.BeginLogin.
func (h *PasskeyHandlers) LoginBegin(c *gin.Context) {
	resp, err := h.webauthn.BeginLogin(c.Request.Context())
	if err != nil {
		h.logger.Error("passkey login begin failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login begin failed"})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// LoginFinish handles POST /auth/passkey/login/finish.
// Delegates to WebAuthnService.FinishLogin, then creates an AS session.
// The tenant itself is determined by FinishLogin from the passkey credential,
// not from the request — see FinishLogin's own tenant-isolation checks. The
// OIDC gate result, if the tenant's OIDCGate.RequiresGateForLogin() gated
// this request (see RegisterRoutes' OIDCGateMiddleware), is passed through so
// FinishLogin can verify it against the credential's actual tenant.
func (h *PasskeyHandlers) LoginFinish(c *gin.Context) {
	var req service.FinishLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	// Builds Issuer/Subject/Email/Audience/Claims the same way
	// internal/api/handlers.go's FinishWebAuthnLogin does - shared to avoid
	// duplicating this tenant-aware binding construction between the two
	// login paths (see middleware.BuildLoginOIDCGateBinding's doc comment).
	if binding := middleware.BuildLoginOIDCGateBinding(c); binding != nil {
		req.OIDCGateBinding = binding
	}

	resp, err := h.webauthn.FinishLogin(c.Request.Context(), &req)
	if err != nil {
		h.logger.Warn("passkey login finish failed", zap.Error(err))
		switch {
		case errors.Is(err, service.ErrChallengeNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "challenge not found"})
		case errors.Is(err, service.ErrChallengeExpired):
			c.JSON(http.StatusGone, gin.H{"error": "challenge expired"})
		case errors.Is(err, service.ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		case errors.Is(err, service.ErrCredentialNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		case errors.Is(err, service.ErrVerificationFailed):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		case errors.Is(err, service.ErrOIDCGateRequired):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "oidc gate authentication required", "code": "oidc_gate_required"})
		case errors.Is(err, service.ErrTenantAccessDenied):
			c.JSON(http.StatusForbidden, gin.H{"error": "tenant user must use tenant-scoped login endpoint"})
		case errors.Is(err, service.ErrIdentityNotBound):
			c.JSON(http.StatusForbidden, gin.H{"error": "no enterprise identity bound for this wallet"})
		case errors.Is(err, service.ErrIdentityBindingMismatch):
			c.JSON(http.StatusForbidden, gin.H{"error": "enterprise identity does not match registered identity"})
		default:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		}
		return
	}

	// Create AS session.
	sessionID, err := GenerateSessionID()
	if err != nil {
		h.logger.Error("failed to generate session ID", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}

	now := time.Now()
	session := &Session{
		JTI:       sessionID,
		UserID:    resp.UUID,
		DID:       "", // DID is not in FinishLoginResponse; populated if needed.
		TenantID:  resp.TenantID,
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC(h.cfg.DefaultMaxTAC),
		CreatedAt: now,
		ExpiresAt: now.Add(h.cfg.SessionTTL),
	}

	// Only legacy-mode clients receive the appToken/refresh token pair, so
	// only they have a refresh-token family for AS logout to revoke (#402).
	// Session-mode clients never get those tokens; recording a family for
	// them would just leave a long-lived revocation marker for nothing.
	mode := DetectClientMode(c)
	if mode == ClientModeLegacy {
		session.FamilyID = resp.SID
	}

	if err := h.sessions.Create(c.Request.Context(), session); err != nil {
		h.logger.Error("failed to create session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}

	// Set session cookie.
	SetSessionCookie(c, sessionID, CookieOptions{
		MaxAge:   int(h.cfg.SessionTTL.Seconds()),
		Insecure: h.cfg.InsecureCookies,
	})

	// Determine response format based on client mode.
	if mode == ClientModeSession {
		// New-style client: no token in body.
		c.JSON(http.StatusOK, gin.H{
			"uuid":              resp.UUID,
			"displayName":       resp.DisplayName,
			"tenantId":          resp.TenantID,
			"tenantDisplayName": resp.TenantDisplayName,
		})
	} else {
		// Legacy client: return existing response format (appToken included).
		c.JSON(http.StatusOK, resp)
	}

	h.logger.Info("passkey login success",
		zap.String("user_id", resp.UUID),
		zap.String("tenant_id", resp.TenantID),
		zap.String("client_mode", string(mode)),
	)
}

// RegisterBegin handles POST /auth/passkey/register/begin.
// Tenant is taken from the validated X-Tenant-ID header (set by
// TenantHeaderMiddleware in RegisterRoutes) — a body "tenantId" field, if
// present, is ignored for tenant selection. This prevents a caller from
// picking a tenant (and thereby skipping that tenant's invite requirement,
// which is only enforced once a tenant is known) via an unvalidated body
// field. See issue #374.
func (h *PasskeyHandlers) RegisterBegin(c *gin.Context) {
	var req service.BeginRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Body is optional for registration begin.
		req = service.BeginRegistrationRequest{}
	}
	req.TenantID = string(requestTenantID(c))

	resp, err := h.webauthn.BeginRegistration(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("passkey registration begin failed", zap.Error(err))
		switch {
		case errors.Is(err, service.ErrTenantNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "tenant not found"})
		case errors.Is(err, service.ErrInviteRequired):
			c.JSON(http.StatusForbidden, gin.H{"error": "invite_required"})
		case errors.Is(err, service.ErrInvalidInvite):
			c.JSON(http.StatusForbidden, gin.H{"error": "invite_invalid"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "registration begin failed"})
		}
		return
	}
	c.JSON(http.StatusOK, resp)
}

// requestTenantID extracts the tenant ID set in context by
// middleware.TenantHeaderMiddleware. It defaults to the "default" tenant if
// unset, matching TenantHeaderMiddleware's own fallback for backwards
// compatibility with single-tenant deployments.
func requestTenantID(c *gin.Context) domain.TenantID {
	if tenantID, ok := middleware.GetTenantID(c); ok {
		return tenantID
	}
	return domain.DefaultTenantID
}

// RegisterFinish handles POST /auth/passkey/register/finish.
// Creates a session on successful registration (auto-login).
func (h *PasskeyHandlers) RegisterFinish(c *gin.Context) {
	var req service.FinishRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// SECURITY: the tenant that actually governs this registration is
	// whichever tenant BeginRegistration recorded on the challenge - not
	// necessarily this request's X-Tenant-ID header. Without this, a caller
	// could begin under tenant A and finish the very same challenge with a
	// different header tenant B: the bind_identity check below would then
	// run against B's policy (and B's OIDC issuer) while the registration is
	// still written under A regardless of what B required, or vice versa.
	// FinishRegistration enforces this against the challenge's real tenant
	// and rejects with ErrTenantMismatch on a mismatch (found by Copilot on
	// this PR; see #374's follow-up).
	req.ExpectedTenantID = string(requestTenantID(c))

	// SECURITY: when the tenant requires identity binding, an OIDC gate
	// result MUST be present before we ever call FinishRegistration — this
	// mirrors internal/api/handlers.go's FinishWebAuthnRegistration, which
	// enforces the same check for the /user/* routes. Checked up front, not
	// left to the service layer, so a misconfigured or bypassed gate fails
	// closed instead of silently registering an unbound user.
	if tenant, ok := middleware.GetTenant(c); ok && tenant.OIDCGate.BindIdentity {
		oidcResult, hasResult := middleware.GetOIDCGateResultGin(c)
		if !hasResult {
			h.logger.Error("bind_identity enabled but no OIDC result in context",
				zap.String("tenant_id", string(tenant.ID)))
			c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
			return
		}

		regOP := tenant.OIDCGate.GetRegistrationOP()
		if regOP == nil {
			h.logger.Error("bind_identity enabled but no RegistrationOP configured",
				zap.String("tenant_id", string(tenant.ID)))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "OIDC gate misconfigured"})
			return
		}
		if oidcResult.Issuer != regOP.Issuer {
			h.logger.Warn("OIDC issuer mismatch during registration binding",
				zap.String("tenant_id", string(tenant.ID)),
				zap.String("expected_issuer", regOP.Issuer),
				zap.String("actual_issuer", oidcResult.Issuer))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "OIDC issuer mismatch", "code": "oidc_issuer_mismatch"})
			return
		}

		var email string
		if emailClaim, ok := oidcResult.Claims["email"].(string); ok {
			email = emailClaim
		}
		req.OIDCGateBinding = &service.OIDCGateBinding{
			Issuer:      oidcResult.Issuer,
			Subject:     oidcResult.Subject,
			Email:       email,
			BindingType: "registration",
		}
	}

	resp, err := h.webauthn.FinishRegistration(c.Request.Context(), &req)
	if err != nil {
		h.logger.Warn("passkey registration finish failed", zap.Error(err))
		switch {
		case errors.Is(err, service.ErrChallengeNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "challenge not found"})
		case errors.Is(err, service.ErrChallengeExpired):
			c.JSON(http.StatusGone, gin.H{"error": "challenge expired"})
		case errors.Is(err, service.ErrVerificationFailed):
			c.JSON(http.StatusBadRequest, gin.H{"error": "verification failed"})
		case errors.Is(err, service.ErrAAGUIDBlacklisted):
			c.JSON(http.StatusForbidden, gin.H{"error": "authenticator not allowed"})
		case errors.Is(err, service.ErrInvalidInvite):
			c.JSON(http.StatusForbidden, gin.H{"error": "invite_invalid"})
		case errors.Is(err, service.ErrTenantMismatch):
			c.JSON(http.StatusForbidden, gin.H{"error": "tenant mismatch"})
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "registration failed: " + err.Error()})
		}
		return
	}

	// Auto-login: create session.
	sessionID, err := GenerateSessionID()
	if err != nil {
		h.logger.Error("failed to generate session ID", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}

	now := time.Now()
	session := &Session{
		JTI:       sessionID,
		UserID:    resp.UUID,
		TenantID:  resp.TenantID,
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC(h.cfg.DefaultMaxTAC),
		CreatedAt: now,
		ExpiresAt: now.Add(h.cfg.SessionTTL),
	}

	if err := h.sessions.Create(c.Request.Context(), session); err != nil {
		h.logger.Error("failed to create session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": errInternalError})
		return
	}

	SetSessionCookie(c, sessionID, CookieOptions{
		MaxAge:   int(h.cfg.SessionTTL.Seconds()),
		Insecure: h.cfg.InsecureCookies,
	})

	mode := DetectClientMode(c)
	if mode == ClientModeSession {
		c.JSON(http.StatusOK, gin.H{
			"uuid":              resp.UUID,
			"displayName":       resp.DisplayName,
			"tenantId":          resp.TenantID,
			"tenantDisplayName": resp.TenantDisplayName,
		})
	} else {
		c.JSON(http.StatusOK, resp)
	}

	h.logger.Info("passkey registration success",
		zap.String("user_id", resp.UUID),
		zap.String("tenant_id", resp.TenantID),
	)
}
