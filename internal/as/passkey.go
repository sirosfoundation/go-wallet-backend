package as

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"go.uber.org/zap"
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
func (h *PasskeyHandlers) LoginFinish(c *gin.Context) {
	var req service.FinishLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	resp, err := h.webauthn.FinishLogin(c.Request.Context(), &req)
	if err != nil {
		h.logger.Warn("passkey login finish failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return
	}

	// Create AS session.
	sessionID, err := GenerateSessionID()
	if err != nil {
		h.logger.Error("failed to generate session ID", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
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

	if err := h.sessions.Create(c.Request.Context(), session); err != nil {
		h.logger.Error("failed to create session", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Set session cookie.
	SetSessionCookie(c, sessionID, CookieOptions{
		MaxAge: int(h.cfg.SessionTTL.Seconds()),
	})

	// Determine response format based on client mode.
	mode := DetectClientMode(c)
	if mode == ClientModeSession {
		// New-style client: no token in body.
		c.JSON(http.StatusOK, gin.H{
			"uuid":        resp.UUID,
			"displayName": resp.DisplayName,
			"tenantId":    resp.TenantID,
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
func (h *PasskeyHandlers) RegisterBegin(c *gin.Context) {
	var req service.BeginRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Body is optional for registration begin.
		req = service.BeginRegistrationRequest{}
	}

	resp, err := h.webauthn.BeginRegistration(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("passkey registration begin failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "registration begin failed"})
		return
	}
	c.JSON(http.StatusOK, resp)
}

// RegisterFinish handles POST /auth/passkey/register/finish.
// Creates a session on successful registration (auto-login).
func (h *PasskeyHandlers) RegisterFinish(c *gin.Context) {
	var req service.FinishRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	resp, err := h.webauthn.FinishRegistration(c.Request.Context(), &req)
	if err != nil {
		h.logger.Warn("passkey registration finish failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "registration failed: " + err.Error()})
		return
	}

	// Auto-login: create session.
	sessionID, err := GenerateSessionID()
	if err != nil {
		h.logger.Error("failed to generate session ID", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	SetSessionCookie(c, sessionID, CookieOptions{
		MaxAge: int(h.cfg.SessionTTL.Seconds()),
	})

	mode := DetectClientMode(c)
	if mode == ClientModeSession {
		c.JSON(http.StatusOK, gin.H{
			"uuid":        resp.UUID,
			"displayName": resp.DisplayName,
			"tenantId":    resp.TenantID,
		})
	} else {
		c.JSON(http.StatusOK, resp)
	}

	h.logger.Info("passkey registration success",
		zap.String("user_id", resp.UUID),
		zap.String("tenant_id", resp.TenantID),
	)
}
