package api

import (
	"errors"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
	"github.com/sirosfoundation/go-wallet-backend/pkg/taggedbinary"
)

// Handlers aggregates all HTTP handlers
type Handlers struct {
	services *service.Services
	store    storage.Store
	cfg      *config.Config
	logger   *zap.Logger
	roles    []string
}

// NewHandlers creates a new Handlers instance
func NewHandlers(services *service.Services, cfg *config.Config, logger *zap.Logger, roles []string) *Handlers {
	return &Handlers{
		services: services,
		cfg:      cfg,
		logger:   logger.Named("handlers"),
		roles:    roles,
	}
}

// NewHandlersWithStore creates a new Handlers instance with store for health checks
func NewHandlersWithStore(services *service.Services, store storage.Store, cfg *config.Config, logger *zap.Logger, roles []string) *Handlers {
	return &Handlers{
		services: services,
		store:    store,
		cfg:      cfg,
		logger:   logger.Named("handlers"),
		roles:    roles,
	}
}

// Status handles the /status endpoint
// This endpoint returns the server status and API version for client capability detection.
func (h *Handlers) Status(c *gin.Context) {
	status := "ok"

	// Check storage health if store is available
	if h.store != nil {
		if err := h.store.Ping(c.Request.Context()); err != nil {
			h.logger.Warn("Storage health check failed", zap.Error(err))
			status = "degraded"
		}
	}

	c.JSON(200, StatusResponse{
		Status:       status,
		Service:      "wallet-backend",
		Roles:        h.roles,
		APIVersion:   CurrentAPIVersion,
		Capabilities: APICapabilities[CurrentAPIVersion],
	})
}

// RegisterUser handles user registration
// Deprecated: Use WebAuthn registration (/webauthn/register/start) instead.
// This endpoint will be removed in a future version.
func (h *Handlers) RegisterUser(c *gin.Context) {
	c.JSON(410, gin.H{
		"error":   "Password-based registration is deprecated",
		"message": "Please use WebAuthn registration at /webauthn/register/start",
	})
}

// LoginUser handles user login
// Deprecated: Use WebAuthn login (/webauthn/login/start) instead.
// This endpoint will be removed in a future version.
func (h *Handlers) LoginUser(c *gin.Context) {
	c.JSON(410, gin.H{
		"error":   "Password-based login is deprecated",
		"message": "Please use WebAuthn login at /webauthn/login/start",
	})
}

// WebAuthn handlers

// StartWebAuthnRegistration begins the WebAuthn registration process
// Tenant is taken from X-Tenant-ID header (set by TenantHeaderMiddleware)
func (h *Handlers) StartWebAuthnRegistration(c *gin.Context) {
	if h.services.WebAuthn == nil {
		c.JSON(503, gin.H{"error": "WebAuthn not available"})
		return
	}

	var req service.BeginRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body - all fields are optional
		req = service.BeginRegistrationRequest{}
	}

	// Get tenant from header (set by TenantHeaderMiddleware for this unauthenticated endpoint)
	tenantID, _ := h.getTenantID(c)
	req.TenantID = string(tenantID)

	resp, err := h.services.WebAuthn.BeginRegistration(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to start WebAuthn registration", zap.Error(err))
		if errors.Is(err, service.ErrTenantNotFound) {
			c.JSON(404, gin.H{"error": "Tenant not found"})
			return
		}
		if errors.Is(err, service.ErrInviteRequired) {
			c.JSON(403, gin.H{"error": "invite_required"})
			return
		}
		if errors.Is(err, service.ErrInvalidInvite) {
			c.JSON(403, gin.H{"error": "invite_invalid"})
			return
		}
		c.JSON(500, gin.H{"error": "Failed to start registration"})
		return
	}

	c.JSON(200, resp)
}

// FinishWebAuthnRegistration completes the WebAuthn registration process
func (h *Handlers) FinishWebAuthnRegistration(c *gin.Context) {
	if h.services.WebAuthn == nil {
		c.JSON(503, gin.H{"error": "WebAuthn not available"})
		return
	}

	var req service.FinishRegistrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Check for OIDC gate identity binding
	if oidcResult, ok := middleware.GetOIDCGateResultGin(c); ok {
		// Get tenant to check if bind_identity is true
		if tenantVal, exists := c.Get("tenant"); exists {
			if tenant, ok := tenantVal.(*domain.Tenant); ok && tenant.OIDCGate.BindIdentity {
				// Get email from claims if available
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
				h.logger.Debug("OIDC identity binding prepared for registration",
					zap.String("issuer", oidcResult.Issuer),
					zap.String("subject", oidcResult.Subject))
			}
		}
	}

	resp, err := h.services.WebAuthn.FinishRegistration(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to finish WebAuthn registration", zap.Error(err))
		switch {
		case errors.Is(err, service.ErrChallengeNotFound):
			c.JSON(404, gin.H{"error": "Challenge not found"})
		case errors.Is(err, service.ErrChallengeExpired):
			c.JSON(410, gin.H{"error": "Challenge expired"})
		case errors.Is(err, service.ErrVerificationFailed):
			c.JSON(400, gin.H{"error": "Verification failed"})
		case errors.Is(err, service.ErrAAGUIDBlacklisted):
			c.JSON(403, gin.H{"error": "Authenticator not allowed"})
		default:
			c.JSON(500, gin.H{"error": "Failed to complete registration"})
		}
		return
	}

	// Set private data ETag header if available
	if len(resp.PrivateData) > 0 {
		c.Header("X-Private-Data-ETag", domain.ComputePrivateDataETag(resp.PrivateData))
	}

	c.JSON(200, resp)
}

// StartWebAuthnLogin begins the WebAuthn login process
func (h *Handlers) StartWebAuthnLogin(c *gin.Context) {
	if h.services.WebAuthn == nil {
		c.JSON(503, gin.H{"error": "WebAuthn not available"})
		return
	}

	resp, err := h.services.WebAuthn.BeginLogin(c.Request.Context())
	if err != nil {
		h.logger.Error("Failed to start WebAuthn login", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to start login"})
		return
	}

	c.JSON(200, resp)
}

// FinishWebAuthnLogin completes the WebAuthn login process
func (h *Handlers) FinishWebAuthnLogin(c *gin.Context) {
	if h.services.WebAuthn == nil {
		c.JSON(503, gin.H{"error": "WebAuthn not available"})
		return
	}

	var req service.FinishLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Check if OIDC gate authentication result is present
	// Note: For login, we can't get tenant ID from request - it's determined from the credential
	// The middleware sets the result in context, and the service will verify it matches the user's bound identity
	if oidcResult, exists := middleware.GetOIDCGateResultGin(c); exists {
		// Extract email from claims if available
		var email string
		if emailClaim, ok := oidcResult.Claims["email"].(string); ok {
			email = emailClaim
		}
		req.OIDCGateBinding = &service.OIDCGateBinding{
			Issuer:  oidcResult.Issuer,
			Subject: oidcResult.Subject,
			Email:   email,
		}
	}

	resp, err := h.services.WebAuthn.FinishLogin(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to finish WebAuthn login", zap.Error(err))

		switch {
		case errors.Is(err, service.ErrChallengeNotFound):
			c.JSON(404, gin.H{"error": "Challenge not found"})
		case errors.Is(err, service.ErrChallengeExpired):
			c.JSON(410, gin.H{"error": "Challenge expired"})
		case errors.Is(err, service.ErrUserNotFound):
			c.JSON(404, gin.H{"error": "User not found"})
		case errors.Is(err, service.ErrCredentialNotFound):
			c.JSON(404, gin.H{"error": "Credential not found"})
		case errors.Is(err, service.ErrVerificationFailed):
			c.JSON(401, gin.H{"error": "Authentication failed"})
		case errors.Is(err, service.ErrTenantAccessDenied):
			c.JSON(403, gin.H{"error": "Tenant user must use tenant-scoped login endpoint"})
		case errors.Is(err, service.ErrIdentityNotBound):
			c.JSON(403, gin.H{"error": "No enterprise identity bound for this wallet"})
		case errors.Is(err, service.ErrIdentityBindingMismatch):
			c.JSON(403, gin.H{"error": "Enterprise identity does not match registered identity"})
		default:
			c.JSON(500, gin.H{"error": "Failed to complete login"})
		}
		return
	}

	// Set private data ETag header if available
	if len(resp.PrivateData) > 0 {
		c.Header("X-Private-Data-ETag", domain.ComputePrivateDataETag(resp.PrivateData))
	}

	c.JSON(200, resp)
}

// RefreshToken exchanges a valid refresh token for a new access token
func (h *Handlers) RefreshToken(c *gin.Context) {
	if h.services.WebAuthn == nil {
		c.JSON(503, gin.H{"error": "WebAuthn not available"})
		return
	}

	var req service.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.services.WebAuthn.RefreshAccessToken(c.Request.Context(), &req)
	if err != nil {
		h.logger.Warn("Token refresh failed", zap.Error(err))
		switch {
		case errors.Is(err, service.ErrInvalidRefreshToken):
			c.JSON(401, gin.H{"error": "Invalid or expired refresh token"})
		default:
			c.JSON(500, gin.H{"error": "Failed to refresh token"})
		}
		return
	}

	c.JSON(200, resp)
}

// Storage handlers - Credentials

// getHolderDID retrieves the holder DID from context
func (h *Handlers) getHolderDID(c *gin.Context) (string, bool) {
	did, exists := c.Get("did")
	if exists && did.(string) != "" {
		return did.(string), true
	}
	// Fallback to user_id if did is not set
	userID, exists := c.Get("user_id")
	if !exists {
		return "", false
	}
	return userID.(string), true
}

// getTenantID retrieves the tenant ID from context.
// For authenticated requests, this comes from the JWT token (security boundary).
// For unauthenticated requests, this comes from X-Tenant-ID header.
// Handles both string (from JWT via AuthMiddleware) and domain.TenantID types.
func (h *Handlers) getTenantID(c *gin.Context) (domain.TenantID, bool) {
	tenantID, exists := c.Get("tenant_id")
	if !exists {
		// Default to "default" tenant for backward compatibility
		return domain.DefaultTenantID, true
	}

	// Handle string type (from JWT via AuthMiddleware)
	if tidStr, ok := tenantID.(string); ok {
		return domain.TenantID(tidStr), true
	}

	// Handle domain.TenantID type (from header via TenantHeaderMiddleware)
	if tid, ok := tenantID.(domain.TenantID); ok {
		return tid, true
	}

	h.logger.Warn("tenant_id in context has unexpected type; falling back to default tenant",
		zap.Any("tenant_id", tenantID))
	return domain.DefaultTenantID, true
}

// GetAllCredentials returns all credentials for the authenticated user
func (h *Handlers) GetAllCredentials(c *gin.Context) {
	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	tenantID, _ := h.getTenantID(c)
	credentials, err := h.services.Credential.GetAll(c.Request.Context(), tenantID, holderDID)
	if err != nil {
		h.logger.Error("Failed to get credentials", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to retrieve credentials"})
		return
	}

	c.JSON(200, gin.H{"vc_list": credentials})
}

// StoreCredential stores one or more credentials
func (h *Handlers) StoreCredential(c *gin.Context) {
	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	// Parse as batch request (reference implementation uses credentials array)
	var batchReq struct {
		Credentials []domain.StoreCredentialRequest `json:"credentials"`
	}
	if err := c.ShouldBindJSON(&batchReq); err != nil {
		c.JSON(400, gin.H{"error": "Missing or invalid 'credentials' body param"})
		return
	}

	if len(batchReq.Credentials) == 0 {
		c.JSON(400, gin.H{"error": "Missing or invalid 'credentials' body param"})
		return
	}

	tenantID, _ := h.getTenantID(c)
	// Batch storage
	for _, credReq := range batchReq.Credentials {
		credReq.HolderDID = holderDID
		if _, err := h.services.Credential.Store(c.Request.Context(), tenantID, &credReq); err != nil {
			h.logger.Error("Failed to store credential", zap.Error(err))
			// Continue storing other credentials
		}
	}
	c.JSON(200, gin.H{})
}

// UpdateCredential updates an existing credential
func (h *Handlers) UpdateCredential(c *gin.Context) {
	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	// Reference impl expects {credential: {...}}
	var wrapper struct {
		Credential domain.UpdateCredentialRequest `json:"credential"`
	}
	if err := c.ShouldBindJSON(&wrapper); err != nil {
		c.JSON(400, gin.H{"error": "Missing or invalid 'credential' body param"})
		return
	}

	req := wrapper.Credential
	if req.CredentialIdentifier == "" {
		c.JSON(400, gin.H{"error": "credential_identifier is required"})
		return
	}

	tenantID, _ := h.getTenantID(c)
	credential, err := h.services.Credential.Update(c.Request.Context(), tenantID, holderDID, &req)
	if err != nil {
		h.logger.Error("Failed to update credential", zap.Error(err))
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Credential not found"})
			return
		}
		c.JSON(500, gin.H{"error": "Failed to update credential"})
		return
	}

	_ = credential // Reference returns empty response
	c.JSON(200, gin.H{})
}

// GetCredentialByIdentifier retrieves a credential by its identifier
func (h *Handlers) GetCredentialByIdentifier(c *gin.Context) {
	credentialID := c.Param("credential_identifier")
	if credentialID == "" {
		c.JSON(400, gin.H{"error": "Credential ID required"})
		return
	}

	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	tenantID, _ := h.getTenantID(c)
	credential, err := h.services.Credential.GetByIdentifier(c.Request.Context(), tenantID, holderDID, credentialID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Credential not found"})
			return
		}
		h.logger.Error("Failed to get credential", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to retrieve credential"})
		return
	}

	c.JSON(200, credential)
}

// DeleteCredential deletes a credential
func (h *Handlers) DeleteCredential(c *gin.Context) {
	credentialID := c.Param("credential_identifier")
	if credentialID == "" {
		c.JSON(400, gin.H{"error": "Credential ID required"})
		return
	}

	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	tenantID, _ := h.getTenantID(c)

	// Delete associated presentations first (like the reference implementation)
	if err := h.services.Presentation.DeleteByCredentialID(c.Request.Context(), tenantID, holderDID, credentialID); err != nil {
		// Log but continue - presentations may not exist
		h.logger.Warn("Error deleting presentations for credential",
			zap.String("credential_id", credentialID),
			zap.Error(err))
	}

	if err := h.services.Credential.Delete(c.Request.Context(), tenantID, holderDID, credentialID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Credential not found"})
			return
		}
		h.logger.Error("Failed to delete credential", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to delete credential"})
		return
	}

	c.JSON(200, gin.H{"message": "Verifiable Credential deleted successfully."})
}

// Presentation handlers

// GetAllPresentations returns all presentations for the authenticated user
func (h *Handlers) GetAllPresentations(c *gin.Context) {
	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	tenantID, _ := h.getTenantID(c)
	presentations, err := h.services.Presentation.GetAll(c.Request.Context(), tenantID, holderDID)
	if err != nil {
		h.logger.Error("Failed to get presentations", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to get presentations"})
		return
	}

	c.JSON(200, gin.H{"vp_list": presentations})
}

// StorePresentation stores a new presentation
func (h *Handlers) StorePresentation(c *gin.Context) {
	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	var presentation domain.VerifiablePresentation
	if err := c.ShouldBindJSON(&presentation); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	tenantID, _ := h.getTenantID(c)
	presentation.HolderDID = holderDID

	if err := h.services.Presentation.Store(c.Request.Context(), tenantID, &presentation); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			c.JSON(409, gin.H{"error": "Presentation already exists"})
			return
		}
		h.logger.Error("Failed to store presentation", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to store presentation"})
		return
	}

	c.JSON(200, gin.H{})
}

// GetPresentationByIdentifier retrieves a presentation by identifier
func (h *Handlers) GetPresentationByIdentifier(c *gin.Context) {
	presentationID := c.Param("presentation_identifier")
	if presentationID == "" {
		c.JSON(400, gin.H{"error": "Presentation ID required"})
		return
	}

	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	tenantID, _ := h.getTenantID(c)
	presentation, err := h.services.Presentation.Get(c.Request.Context(), tenantID, holderDID, presentationID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Presentation not found"})
			return
		}
		h.logger.Error("Failed to get presentation", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to get presentation"})
		return
	}

	c.JSON(200, presentation)
}

// DeletePresentation deletes a presentation
func (h *Handlers) DeletePresentation(c *gin.Context) {
	presentationID := c.Param("presentation_identifier")
	if presentationID == "" {
		c.JSON(400, gin.H{"error": "Presentation ID required"})
		return
	}

	holderDID, ok := h.getHolderDID(c)
	if !ok {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	tenantID, _ := h.getTenantID(c)
	if err := h.services.Presentation.Delete(c.Request.Context(), tenantID, holderDID, presentationID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Presentation not found"})
			return
		}
		h.logger.Error("Failed to delete presentation", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to delete presentation"})
		return
	}

	c.JSON(204, nil)
}

// Issuer handlers

// GetAllIssuers returns all credential issuers
func (h *Handlers) GetAllIssuers(c *gin.Context) {
	tenantID, _ := h.getTenantID(c)
	issuers, err := h.services.Issuer.GetAll(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get issuers", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to get issuers"})
		return
	}

	c.JSON(200, issuers)
}

// GetIssuerByID retrieves an issuer by ID
func (h *Handlers) GetIssuerByID(c *gin.Context) {
	issuerID := c.Param("id")
	if issuerID == "" {
		c.JSON(400, gin.H{"error": "Issuer ID required"})
		return
	}

	// Parse ID
	var id int64
	if _, err := fmt.Sscanf(issuerID, "%d", &id); err != nil {
		c.JSON(400, gin.H{"error": "Invalid issuer ID"})
		return
	}

	tenantID, _ := h.getTenantID(c)
	issuer, err := h.services.Issuer.GetByID(c.Request.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Issuer not found"})
			return
		}
		h.logger.Error("Failed to get issuer", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to get issuer"})
		return
	}

	c.JSON(200, issuer)
}

// Verifier handlers

// GetAllVerifiers returns all verifiers
func (h *Handlers) GetAllVerifiers(c *gin.Context) {
	tenantID, _ := h.getTenantID(c)
	verifiers, err := h.services.Verifier.GetAll(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get verifiers", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to get verifiers"})
		return
	}

	c.JSON(200, verifiers)
}

// ProxyRequest handles proxied HTTP requests
func (h *Handlers) ProxyRequest(c *gin.Context) {
	var req service.ProxyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	resp, binaryData, err := h.services.Proxy.Execute(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Proxy request failed", zap.Error(err))
		c.JSON(500, gin.H{"error": "Proxy request failed"})
		return
	}

	// Handle binary responses
	if binaryData != nil {
		// Forward headers
		for key, value := range resp.Headers {
			c.Header(key, value)
		}
		c.Data(resp.Status, resp.Headers["Content-Type"], binaryData)
		return
	}

	// Return JSON response with status, headers, and data
	c.JSON(200, resp)
}

// Helper handlers

// GetCertificate fetches the SSL certificate chain from a URL
func (h *Handlers) GetCertificate(c *gin.Context) {
	var req struct {
		URL string `json:"url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.services.Helper.GetCertificateChain(c.Request.Context(), req.URL)
	if err != nil {
		h.logger.Error("Failed to get certificate", zap.Error(err))
		c.JSON(400, gin.H{"error": "INVALID_CERT"})
		return
	}

	c.JSON(200, resp)
}

// GenerateKeyAttestation generates a key attestation JWT
func (h *Handlers) GenerateKeyAttestation(c *gin.Context) {
	var req struct {
		JWKS       []map[string]interface{} `json:"jwks"`
		OpenID4VCI struct {
			Nonce string `json:"nonce"`
		} `json:"openid4vci"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{
			"error":   "INVALID_REQUEST",
			"message": "Invalid request body",
		})
		return
	}

	if len(req.JWKS) == 0 {
		c.JSON(400, gin.H{
			"error":   "INVALID_JWKS",
			"message": "'jwks' JSON body parameter is missing or not type of 'array' or array is empty",
		})
		return
	}

	if req.OpenID4VCI.Nonce == "" {
		c.JSON(400, gin.H{
			"error":   "INVALID_OPENID4VCI_NONCE_VALUE",
			"message": "'openid4vci.nonce' JSON body parameter is missing or not type of 'string'",
		})
		return
	}

	keyAttestation, err := h.services.WalletProvider.GenerateKeyAttestation(c.Request.Context(), req.JWKS, req.OpenID4VCI.Nonce)
	if err != nil {
		h.logger.Error("Failed to generate key attestation", zap.Error(err))
		c.JSON(400, gin.H{
			"error":   "UNSUPPORTED",
			"message": "key attestation generation is not supported",
		})
		return
	}

	c.JSON(200, gin.H{"key_attestation": keyAttestation})
}

// Private data handlers

// GetPrivateData retrieves the user's private data
func (h *Handlers) GetPrivateData(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	data, etag, err := h.services.User.GetPrivateData(c.Request.Context(), domain.UserIDFromString(userID.(string)))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		h.logger.Error("Failed to get private data", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to get private data"})
		return
	}

	// Check If-None-Match for conditional GET
	ifNoneMatch := c.GetHeader("If-None-Match")
	if ifNoneMatch == "" {
		ifNoneMatch = c.GetHeader("X-Private-Data-If-None-Match")
	}

	if ifNoneMatch == etag {
		c.Header("X-Private-Data-ETag", etag)
		c.Status(304)
		return
	}

	c.Header("X-Private-Data-ETag", etag)
	c.JSON(200, gin.H{"privateData": taggedbinary.TaggedBytes(data)})
}

// UpdatePrivateData updates the user's private data
func (h *Handlers) UpdatePrivateData(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	// Get the raw body as the private data
	rawData, err := c.GetRawData()
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to read request body"})
		return
	}

	// Decode tagged binary format if present
	// The frontend sends private data as {"$b64u": "base64url-encoded-data"}
	var privateData taggedbinary.TaggedBytes
	if err := privateData.UnmarshalJSON(rawData); err != nil {
		// If not tagged binary format, use raw data directly
		privateData = rawData
	}

	// Get If-Match header for optimistic locking
	ifMatch := c.GetHeader("X-Private-Data-If-Match")

	newEtag, err := h.services.User.UpdatePrivateData(
		c.Request.Context(),
		domain.UserIDFromString(userID.(string)),
		[]byte(privateData),
		ifMatch,
	)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		if errors.Is(err, service.ErrPrivateDataConflict) {
			c.Header("X-Private-Data-ETag", newEtag)
			c.Status(412)
			return
		}
		h.logger.Error("Failed to update private data", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to update private data"})
		return
	}

	c.Header("X-Private-Data-ETag", newEtag)
	c.Status(204)
}

// Logout invalidates the current session by blacklisting the JWT
func (h *Handlers) Logout(c *gin.Context) {
	// Get the token from context (set by auth middleware)
	tokenString, exists := c.Get("token")
	if !exists {
		// No token? Already logged out effectively
		c.Status(200)
		return
	}

	// Parse the token to get claims (we need jti and exp)
	token, _ := jwt.Parse(tokenString.(string), func(token *jwt.Token) (interface{}, error) {
		return []byte(h.cfg.JWT.Secret), nil
	})

	if token != nil && token.Claims != nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			jti, _ := claims["jti"].(string)
			if jti != "" && h.services.TokenBlacklist != nil {
				// Get expiry time for blacklist entry
				var expiry time.Time
				if exp, ok := claims["exp"].(float64); ok {
					expiry = time.Unix(int64(exp), 0)
				} else {
					// Default to 24 hours if no expiry (shouldn't happen)
					expiry = time.Now().Add(24 * time.Hour)
				}

				// Add to blacklist
				if err := h.services.TokenBlacklist.Add(c.Request.Context(), jti, expiry); err != nil {
					h.logger.Warn("Failed to blacklist token", zap.Error(err))
				} else {
					h.logger.Info("User logged out, token blacklisted",
						zap.String("jti", jti),
					)
				}
			}
		}
	}

	c.JSON(200, gin.H{"message": "Logged out successfully"})
}

// DeleteUser deletes the current user and all associated data
func (h *Handlers) DeleteUser(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	holderDID := userID.(string) // Using userID as holderDID

	if err := h.services.User.DeleteUser(
		c.Request.Context(),
		domain.UserIDFromString(userID.(string)),
		holderDID,
	); err != nil {
		h.logger.Error("Failed to delete user", zap.Error(err))
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"result": "DELETED"})
}

// AccountInfo represents the account info response
type AccountInfoResponse struct {
	UUID                string                   `json:"uuid"`
	Username            *string                  `json:"username,omitempty"`
	DisplayName         *string                  `json:"displayName,omitempty"`
	HasPassword         bool                     `json:"hasPassword"`
	Settings            AccountSettings          `json:"settings"`
	WebauthnCredentials []WebauthnCredentialInfo `json:"webauthnCredentials"`
}

type AccountSettings struct {
	OpenIDRefreshTokenMaxAgeInSeconds int64 `json:"openidRefreshTokenMaxAgeInSeconds,omitempty"`
}

type WebauthnCredentialInfo struct {
	ID           string                   `json:"id"`
	CredentialID taggedbinary.TaggedBytes `json:"credentialId"`
	Nickname     *string                  `json:"nickname,omitempty"`
	PRFCapable   bool                     `json:"prfCapable"`
	CreateTime   time.Time                `json:"createTime"`
	LastUseTime  *time.Time               `json:"lastUseTime,omitempty"`
}

// GetAccountInfo returns account information for the current user
func (h *Handlers) GetAccountInfo(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	user, err := h.services.User.GetUserByID(c.Request.Context(), domain.UserIDFromString(userID.(string)))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(403, gin.H{})
			return
		}
		h.logger.Error("Failed to get user", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to get user"})
		return
	}

	// Convert webauthn credentials to response format
	credentials := make([]WebauthnCredentialInfo, 0, len(user.WebauthnCredentials))
	for _, cred := range user.WebauthnCredentials {
		credentials = append(credentials, WebauthnCredentialInfo{
			ID:           cred.ID,
			CredentialID: cred.CredentialID,
			Nickname:     cred.Nickname,
			PRFCapable:   cred.PRFCapable,
			CreateTime:   cred.CreatedAt,
			LastUseTime:  cred.LastUseTime,
		})
	}

	response := AccountInfoResponse{
		UUID:        user.UUID.String(),
		Username:    user.Username,
		DisplayName: user.DisplayName,
		HasPassword: user.PasswordHash != nil,
		Settings: AccountSettings{
			OpenIDRefreshTokenMaxAgeInSeconds: user.OpenIDRefreshTokenMaxAge,
		},
		WebauthnCredentials: credentials,
	}

	c.JSON(200, response)
}

// UpdateSettingsRequest represents a settings update request
type UpdateSettingsRequest struct {
	OpenIDRefreshTokenMaxAgeInSeconds *int64 `json:"openidRefreshTokenMaxAgeInSeconds,omitempty"`
}

// UpdateSettings updates user settings
func (h *Handlers) UpdateSettings(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	var req UpdateSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	user, err := h.services.User.GetUserByID(c.Request.Context(), domain.UserIDFromString(userID.(string)))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(403, gin.H{})
			return
		}
		h.logger.Error("Failed to get user", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to get user"})
		return
	}

	if req.OpenIDRefreshTokenMaxAgeInSeconds != nil {
		user.OpenIDRefreshTokenMaxAge = *req.OpenIDRefreshTokenMaxAgeInSeconds
	}

	if err := h.services.User.UpdateUser(c.Request.Context(), user); err != nil {
		h.logger.Error("Failed to update user settings", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to update settings"})
		return
	}

	c.JSON(200, gin.H{
		"openidRefreshTokenMaxAgeInSeconds": user.OpenIDRefreshTokenMaxAge,
	})
}

// WebAuthn credential management

// StartAddWebAuthnCredential begins adding a new credential to an existing user
func (h *Handlers) StartAddWebAuthnCredential(c *gin.Context) {
	if h.services.WebAuthn == nil {
		c.JSON(503, gin.H{"error": "WebAuthn not available"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	resp, err := h.services.WebAuthn.BeginAddCredential(c.Request.Context(), domain.UserIDFromString(userID.(string)))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(403, gin.H{})
			return
		}
		h.logger.Error("Failed to start adding credential", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to start registration"})
		return
	}

	c.JSON(200, resp)
}

// FinishAddWebAuthnCredential completes adding a new credential to an existing user
func (h *Handlers) FinishAddWebAuthnCredential(c *gin.Context) {
	if h.services.WebAuthn == nil {
		c.JSON(503, gin.H{"error": "WebAuthn not available"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	var req service.FinishAddCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Get If-Match header for private data
	ifMatch := c.GetHeader("X-Private-Data-If-Match")

	resp, err := h.services.WebAuthn.FinishAddCredential(
		c.Request.Context(),
		domain.UserIDFromString(userID.(string)),
		&req,
		ifMatch,
	)
	if err != nil {
		h.logger.Error("Failed to finish adding credential", zap.Error(err))
		switch {
		case errors.Is(err, service.ErrChallengeNotFound):
			c.JSON(404, gin.H{})
		case errors.Is(err, service.ErrChallengeExpired):
			c.JSON(404, gin.H{})
		case errors.Is(err, service.ErrVerificationFailed):
			c.JSON(400, gin.H{"error": "Registration response could not be verified"})
		case errors.Is(err, service.ErrAAGUIDBlacklisted):
			c.JSON(403, gin.H{"error": "Authenticator not allowed"})
		case errors.Is(err, service.ErrPrivateDataConflict):
			// Get current ETag
			user, _ := h.services.User.GetUserByID(c.Request.Context(), domain.UserIDFromString(userID.(string)))
			if user != nil {
				c.Header("X-Private-Data-ETag", user.PrivateDataETag)
			}
			c.Status(412)
			return
		case errors.Is(err, storage.ErrNotFound):
			c.JSON(403, gin.H{})
		default:
			c.JSON(500, gin.H{})
		}
		return
	}

	c.Header("X-Private-Data-ETag", resp.PrivateDataETag)
	c.JSON(200, gin.H{"credentialId": resp.CredentialID})
}

// DeleteWebAuthnCredential deletes a WebAuthn credential
func (h *Handlers) DeleteWebAuthnCredential(c *gin.Context) {
	credentialID := c.Param("id")
	if credentialID == "" {
		c.JSON(400, gin.H{"error": "Credential ID required"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		PrivateData taggedbinary.TaggedBytes `json:"privateData"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body
		req.PrivateData = nil
	}

	ifMatch := c.GetHeader("X-Private-Data-If-Match")

	newEtag, err := h.services.User.DeleteWebAuthnCredential(
		c.Request.Context(),
		domain.UserIDFromString(userID.(string)),
		credentialID,
		[]byte(req.PrivateData),
		ifMatch,
	)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Credential not found"})
			return
		}
		if errors.Is(err, service.ErrLastWebAuthnCredential) {
			c.JSON(409, gin.H{"error": "Cannot delete last credential"})
			return
		}
		if errors.Is(err, service.ErrPrivateDataConflict) {
			c.Header("X-Private-Data-ETag", newEtag)
			c.Status(412)
			return
		}
		h.logger.Error("Failed to delete WebAuthn credential", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to delete credential"})
		return
	}

	c.Header("X-Private-Data-ETag", newEtag)
	c.Status(204)
}

// RenameWebAuthnCredential renames a WebAuthn credential
func (h *Handlers) RenameWebAuthnCredential(c *gin.Context) {
	credentialID := c.Param("id")
	if credentialID == "" {
		c.JSON(400, gin.H{"error": "Credential ID required"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Nickname string `json:"nickname"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := h.services.User.RenameWebAuthnCredential(
		c.Request.Context(),
		domain.UserIDFromString(userID.(string)),
		credentialID,
		req.Nickname,
	); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Credential not found"})
			return
		}
		h.logger.Error("Failed to rename WebAuthn credential", zap.Error(err))
		c.JSON(500, gin.H{"error": "Failed to rename credential"})
		return
	}

	c.Status(204)
}

// AuthCheck handles the auth check endpoint (used by relay)
func (h *Handlers) AuthCheck(c *gin.Context) {
	c.Status(200)
}

// WebSocketKeystore handles WebSocket connections for client-side keystores
// The wallet client connects here to receive signing requests from the server
func (h *Handlers) WebSocketKeystore(c *gin.Context) {
	h.services.Keystore.HandleWebSocket(c.Writer, c.Request)
}

// KeystoreStatus checks if a user's keystore client is connected
func (h *Handlers) KeystoreStatus(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	connected := h.services.Keystore.IsClientConnected(userID.(string))
	c.JSON(200, gin.H{
		"connected": connected,
	})
}

// =============================================================================
// Public Tenant Config
// =============================================================================

// PublicTenantConfigResponse is the public-facing tenant configuration.
// This excludes admin-only fields and exposes only what clients need.
type PublicTenantConfigResponse struct {
	ID            string                  `json:"id"`
	Name          string                  `json:"name"`
	DisplayName   string                  `json:"display_name,omitempty"`
	RequireInvite bool                    `json:"require_invite"`
	OIDCGate      *PublicOIDCGateResponse `json:"oidc_gate,omitempty"`
}

// PublicOIDCProviderResponse is the public-facing OIDC provider config.
// Only includes fields needed by clients to initiate OIDC flows.
type PublicOIDCProviderResponse struct {
	DisplayName string `json:"display_name,omitempty"`
	Issuer      string `json:"issuer"`
	ClientID    string `json:"client_id"`
	Scopes      string `json:"scopes,omitempty"`
}

// PublicOIDCGateResponse is the public-facing OIDC gate configuration.
type PublicOIDCGateResponse struct {
	Mode           string                      `json:"mode"`
	RegistrationOP *PublicOIDCProviderResponse `json:"registration_op,omitempty"`
	LoginOP        *PublicOIDCProviderResponse `json:"login_op,omitempty"`
}

// GetTenantConfig returns the public configuration for a tenant.
// GET /tenant/:id/config
// This is a public endpoint that does not require authentication.
func (h *Handlers) GetTenantConfig(c *gin.Context) {
	tenantID := domain.TenantID(c.Param("id"))

	// Validate tenant ID format
	if err := domain.ValidateTenantID(tenantID); err != nil {
		c.JSON(400, gin.H{"error": "Invalid tenant ID"})
		return
	}

	tenant, err := h.services.Tenant.GetByID(c.Request.Context(), tenantID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(404, gin.H{"error": "Tenant not found"})
			return
		}
		h.logger.Error("Failed to get tenant", zap.Error(err), zap.String("tenant_id", string(tenantID)))
		c.JSON(500, gin.H{"error": "Failed to get tenant"})
		return
	}

	// Don't expose disabled tenants
	if !tenant.Enabled {
		c.JSON(404, gin.H{"error": "Tenant not found"})
		return
	}

	response := &PublicTenantConfigResponse{
		ID:            string(tenant.ID),
		Name:          tenant.Name,
		DisplayName:   tenant.DisplayName,
		RequireInvite: tenant.RequireInvite,
	}

	// Include OIDC gate config if enabled
	if tenant.OIDCGate.IsEnabled() {
		response.OIDCGate = publicOIDCGateToResponse(&tenant.OIDCGate)
	}

	c.JSON(200, response)
}

// publicOIDCGateToResponse converts domain OIDCGateConfig to public response
func publicOIDCGateToResponse(g *domain.OIDCGateConfig) *PublicOIDCGateResponse {
	if g == nil {
		return nil
	}
	resp := &PublicOIDCGateResponse{
		Mode: string(g.Mode),
	}
	if g.RegistrationOP != nil {
		resp.RegistrationOP = &PublicOIDCProviderResponse{
			DisplayName: g.RegistrationOP.DisplayName,
			Issuer:      g.RegistrationOP.Issuer,
			ClientID:    g.RegistrationOP.ClientID,
			Scopes:      g.RegistrationOP.Scopes,
		}
	}
	if g.LoginOP != nil {
		resp.LoginOP = &PublicOIDCProviderResponse{
			DisplayName: g.LoginOP.DisplayName,
			Issuer:      g.LoginOP.Issuer,
			ClientID:    g.LoginOP.ClientID,
			Scopes:      g.LoginOP.Scopes,
		}
	}
	return resp
}
