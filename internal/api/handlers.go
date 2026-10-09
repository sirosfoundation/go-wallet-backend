package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	tokenauthclaims "github.com/sirosfoundation/go-tokenauth/claims"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/embed"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/legacytoken"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
	"github.com/sirosfoundation/go-wallet-backend/pkg/taggedbinary"
)

// Handlers aggregates all HTTP handlers
type Handlers struct {
	services      *service.Services
	store         storage.Store
	cfg           *config.Config
	logger        *zap.Logger
	roles         []string
	metadataCache *issuerMetadataCache
	httpClient    *http.Client

	// imageEmbedder inlines remote images referenced by an issuer's own
	// metadata as data: URIs before the response is handed to a client. It
	// does not change WHAT the issuer says about its credentials - only how
	// the assets it points at are delivered. See embedIssuerMetadataImages.
	imageEmbedder *embed.ImageEmbedder
}

// NewHandlers creates a new Handlers instance
func NewHandlers(services *service.Services, cfg *config.Config, logger *zap.Logger, roles []string) *Handlers {
	return &Handlers{
		services:      services,
		cfg:           cfg,
		logger:        logger.Named("handlers"),
		roles:         roles,
		metadataCache: newIssuerMetadataCache(),
		httpClient:    cfg.HTTPClient.NewHTTPClient(0),
		imageEmbedder: newIssuerMetadataImageEmbedder(cfg, logger),
	}
}

// NewHandlersWithStore creates a new Handlers instance with store for health checks
func NewHandlersWithStore(services *service.Services, store storage.Store, cfg *config.Config, logger *zap.Logger, roles []string) *Handlers {
	return &Handlers{
		services:      services,
		store:         store,
		cfg:           cfg,
		logger:        logger.Named("handlers"),
		roles:         roles,
		metadataCache: newIssuerMetadataCache(),
		httpClient:    cfg.HTTPClient.NewHTTPClient(0),
		imageEmbedder: newIssuerMetadataImageEmbedder(cfg, logger),
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

	// SECURITY: the tenant that actually governs this registration is
	// whichever tenant BeginRegistration recorded on the challenge - not
	// necessarily this request's current tenant context. Without this, a
	// caller could begin under tenant A and finish the very same challenge
	// under tenant B: the bind_identity check below would then run against
	// B's policy (and B's OIDC issuer) while the registration is still
	// written under A regardless of what B required, or vice versa. This
	// mirrors StartWebAuthnRegistration's tenant source and the /auth/passkey
	// path's RegisterFinish fix (issue #374); see #395.
	tenantIDForCheck, _ := h.getTenantID(c)
	req.ExpectedTenantID = string(tenantIDForCheck)

	// SECURITY: Check if identity binding is required for this tenant
	// This must be validated BEFORE checking oidcResult to prevent bypass
	tenantVal, tenantExists := c.Get("tenant")
	var tenant *domain.Tenant
	if tenantExists {
		tenant, _ = tenantVal.(*domain.Tenant)
	}

	// If bind_identity is configured, we MUST have both tenant and OIDC result
	if tenant != nil && tenant.OIDCGate.BindIdentity {
		// bind_identity requires registration mode - enforce binding
		oidcResult, hasResult := middleware.GetOIDCGateResultGin(c)
		if !hasResult {
			h.logger.Error("bind_identity enabled but no OIDC result in context",
				zap.String("tenant_id", string(tenant.ID)))
			c.JSON(500, gin.H{"error": "OIDC gate state inconsistent"})
			return
		}

		// SECURITY: Verify issuer matches tenant's configured RegistrationOP
		regOP := tenant.OIDCGate.GetRegistrationOP()
		if regOP == nil {
			h.logger.Error("bind_identity enabled but no RegistrationOP configured",
				zap.String("tenant_id", string(tenant.ID)))
			c.JSON(500, gin.H{"error": "OIDC gate misconfigured"})
			return
		}
		if oidcResult.Issuer != regOP.Issuer {
			h.logger.Warn("OIDC issuer mismatch during registration binding",
				zap.String("tenant_id", string(tenant.ID)),
				zap.String("expected_issuer", regOP.Issuer),
				zap.String("actual_issuer", oidcResult.Issuer))
			c.JSON(401, gin.H{
				"error": "OIDC issuer mismatch",
				"code":  "oidc_issuer_mismatch",
			})
			return
		}

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
		case errors.Is(err, service.ErrTenantMismatch):
			c.JSON(403, gin.H{"error": "tenant mismatch"})
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
	// Note: For login, we can't get tenant ID from request - it's determined
	// from the credential. Builds Issuer/Subject/Email/Audience/Claims the
	// same way internal/as.PasskeyHandlers.LoginFinish does - shared to
	// avoid duplicating this tenant-aware binding construction between the
	// two login paths (see middleware.BuildLoginOIDCGateBinding's doc
	// comment, and #386/#408/#409).
	if binding := middleware.BuildLoginOIDCGateBinding(c); binding != nil {
		req.OIDCGateBinding = binding
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
		case errors.Is(err, service.ErrWalletInstanceRevoked):
			c.JSON(403, lifecycleRefusalBody(err))
		case errors.Is(err, service.ErrTenantAccessDenied):
			c.JSON(403, gin.H{"error": "Tenant user must use tenant-scoped login endpoint"})
		case errors.Is(err, service.ErrIdentityNotBound):
			c.JSON(403, gin.H{"error": "No enterprise identity bound for this wallet"})
		case errors.Is(err, service.ErrIdentityBindingMismatch):
			c.JSON(403, gin.H{"error": "Enterprise identity does not match registered identity"})
		case errors.Is(err, service.ErrOIDCGateRequired):
			c.JSON(401, gin.H{
				"error": "OIDC gate authentication required",
				"code":  "oidc_gate_required",
			})
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
		case errors.Is(err, service.ErrRefreshDisabled):
			// Config-driven, expected state (JWT.RefreshDays <= 0) - not a
			// server malfunction, so it must not surface as any 5xx (a 503
			// still reads as a server failure to callers/monitoring -
			// Copilot review on #400, second round). The route itself is
			// now only mounted when refresh tokens are enabled
			// (internal/server/providers.go), so this case is unreachable
			// via HTTP in practice; it's kept as defense in depth for any
			// other caller of RefreshAccessToken, mapped the same way a
			// missing route would answer.
			c.JSON(404, gin.H{"error": "Token refresh is disabled"})
		default:
			c.JSON(500, gin.H{"error": "Failed to refresh token"})
		}
		return
	}

	c.JSON(200, resp)
}

// Storage handlers - Credentials

// getHolderDID retrieves the canonical holder DID for the authenticated
// caller. It is always derived from user_id via domain.HolderDID, never
// trusted from the token's own "did" claim: legacy HMAC tokens carry both
// "did" and "user_id" (with did == domain.HolderDID(user_id) - see
// UserService.generateToken / WebAuthnService.generateToken), but AS-issued
// tokens (internal/as/token.go) carry only "sub"/user_id and no "did" claim
// at all. Preferring "did" when present used to give the same physical user
// two different holder identities depending on which token type
// authenticated the request, making their previously stored credentials
// invisible under the other (#384). Deriving from user_id alone, always,
// keeps both token types resolving to the same identity - and reproduces
// the exact value legacy tokens' own "did" claim already carried, so
// existing stored credentials stay reachable.
func (h *Handlers) getHolderDID(c *gin.Context) (string, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return "", false
	}
	return domain.HolderDID(userID.(string)), true
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
			if abortIfTokenRevoked(c, err) {
				return
			}
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
		if abortIfTokenRevoked(c, err) {
			return
		}
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

	if err := h.services.Credential.Delete(c.Request.Context(), tenantID, holderDID, credentialID); err != nil {
		if abortIfTokenRevoked(c, err) {
			return
		}
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
		if abortIfTokenRevoked(c, err) {
			return
		}
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

// SecurityPropertiesRequest carries WSCD security metadata from native SDKs.
// These become top-level KA JWT claims per Annex C §C.3.1.
type SecurityPropertiesRequest struct {
	KeyStorage         []string    `json:"key_storage"`
	UserAuthentication []string    `json:"user_authentication"`
	Certification      interface{} `json:"certification,omitempty"`
}

func (s *SecurityPropertiesRequest) toService() *service.SecurityProperties {
	if s == nil {
		return nil
	}
	return &service.SecurityProperties{
		KeyStorage:         s.KeyStorage,
		UserAuthentication: s.UserAuthentication,
		Certification:      s.Certification,
	}
}

// GenerateKeyAttestation generates a key attestation JWT
func (h *Handlers) GenerateKeyAttestation(c *gin.Context) {
	var req struct {
		JWKS       []map[string]interface{} `json:"jwks"`
		OpenID4VCI struct {
			Nonce            string `json:"nonce"`
			CredentialIssuer string `json:"credential_issuer,omitempty"`
		} `json:"openid4vci"`
		SecurityProperties *SecurityPropertiesRequest `json:"security_properties,omitempty"`
		WalletInstanceID   string                     `json:"wallet_instance_id,omitempty"`
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

	if len(req.JWKS) > service.MaxJWKSPerRequest {
		c.JSON(400, gin.H{
			"error":   "INVALID_JWKS",
			"message": fmt.Sprintf("too many JWKs: %d exceeds maximum of %d", len(req.JWKS), service.MaxJWKSPerRequest),
		})
		return
	}

	// Validate that each JWK entry is non-nil and contains required fields
	for i, jwk := range req.JWKS {
		if jwk == nil {
			c.JSON(400, gin.H{
				"error":   "INVALID_JWKS",
				"message": fmt.Sprintf("jwks[%d] is null", i),
			})
			return
		}
		if _, ok := jwk["kty"]; !ok {
			c.JSON(400, gin.H{
				"error":   "INVALID_JWKS",
				"message": fmt.Sprintf("jwks[%d] is missing 'kty' field", i),
			})
			return
		}
	}

	if req.OpenID4VCI.Nonce == "" {
		c.JSON(400, gin.H{
			"error":   "INVALID_OPENID4VCI_NONCE_VALUE",
			"message": "'openid4vci.nonce' JSON body parameter is missing or not type of 'string'",
		})
		return
	}

	kaTenantID, _ := h.getTenantID(c)
	keyAttestation, err := h.services.WalletProvider.GenerateKeyAttestation(
		service.WithKeyAttestationTenant(c.Request.Context(), kaTenantID),
		req.JWKS,
		req.OpenID4VCI.Nonce,
		req.SecurityProperties.toService(),
		req.WalletInstanceID,
		req.OpenID4VCI.CredentialIssuer,
	)
	if err != nil {
		if abortIfTokenRevoked(c, err) {
			return
		}
		if errors.Is(err, service.ErrKeyAttestationInstanceRefused) {
			c.JSON(403, gin.H{"error": "FORBIDDEN", "message": "wallet instance not usable by this caller"})
			return
		}
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
		if abortIfTokenRevoked(c, err) {
			return
		}
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

// maxConfiguredASTokenTTL returns the longest lifetime the AS is configured
// to issue an access token for, across DefaultTokenTTL and every
// per-audience override in AudienceTTLs - used by Logout to size a
// blacklist entry for an AS-issued token whose actual expiry isn't exposed
// by go-tokenauth's validation result. Falls back to DefaultTokenTTL alone
// (2m by default - see config.ASConfig.SetDefaults) if AS isn't configured
// at all, which is harmless: an AS-disabled deployment never reaches this
// code path (see Logout's tokenauth_result branch).
func maxConfiguredASTokenTTL(cfg *config.Config) time.Duration {
	longest := cfg.AS.DefaultTokenTTL
	for _, ttl := range cfg.AS.AudienceTTLs {
		if ttl > longest {
			longest = ttl
		}
	}
	return longest
}

// ttlForTokenAuthResult returns the lifetime to size a logout blacklist
// entry for, given the mode go-tokenauth validated the token as. Its own
// Validator "auto-detects new-style vs legacy" (see TokenAuthMiddleware's
// doc comment), so tokenauth_result is populated for both kinds of token,
// not just AS-issued ones, and each has its own, very different, configured
// lifetime - see maxConfiguredASTokenTTL's doc comment and #391 review,
// round 3.
func ttlForTokenAuthResult(cfg *config.Config, result *tokenauthclaims.Result) time.Duration {
	if result.Mode == tokenauthclaims.ModeLegacy {
		return time.Duration(cfg.JWT.ExpiryHours) * time.Hour
	}
	return maxConfiguredASTokenTTL(cfg)
}

// familyRetention returns how long a Logout-triggered RevokeFamily entry
// must be kept (see TokenBlacklist.RevokeFamily's own doc comment for why
// it, unlike RevokeUser, is swept once this elapses): long enough that no
// access or refresh token which could still legitimately carry the revoked
// sid can possibly still be unexpired. Every token minted for a given sid
// (WebAuthnService.generateToken/generateRefreshToken/RefreshAccessToken)
// is minted no later than the moment of revocation itself - IsFamilyRevoked
// is checked before minting any further token for that sid.
//
// Uses the MAX of both configured lifetimes, not just the refresh token's
// (Copilot review on #414): nothing in config.Config.Validate enforces
// JWT.RefreshDays outliving JWT.ExpiryHours, so an unusual but valid
// configuration (e.g. a short-lived refresh token paired with a
// long-lived access token) would otherwise let the marker expire while an
// access token from an earlier rotation - its own jti never individually
// blacklisted - was still unexpired and usable again.
func familyRetention(cfg *config.Config) time.Duration {
	return cfg.JWT.FamilyRetention()
}

// Logout invalidates the current session by blacklisting the JWT and, when
// it carries one, revoking its whole refresh-token family (#402) - so a
// refresh token issued alongside it (or produced by any rotation of it)
// stops working immediately too, rather than remaining valid until it
// naturally expires or is itself used.
//
// If the family revocation fails the handler fails closed with a 500 (the
// refresh token is still usable, so a clean logout must not be reported).
// The access-token jti is blacklisted only AFTER the family revocation
// succeeds, so a failed attempt leaves the token usable (the auth
// middleware still accepts it) and the client can simply retry.
func (h *Handlers) Logout(c *gin.Context) {
	// When authenticated via go-tokenauth (pkg/middleware.TokenAuthMiddleware
	// - the path taken whenever AS is enabled), the raw token may be
	// ES256/EdDSA-signed and the legacy HMAC re-parse below silently fails
	// to extract its claims, so the jti never reaches the blacklist at all
	// (#391 review). TokenAuthMiddleware already validated the token and
	// left the result in context; use its jti directly instead of
	// re-parsing.
	if v, exists := c.Get("tokenauth_result"); exists {
		if result, ok := v.(*tokenauthclaims.Result); ok && result != nil {
			// Refresh-token family revocation (#402), legacy-mode tokens
			// only: go-tokenauth "auto-detects new-style vs legacy" (see
			// TokenAuthMiddleware's doc comment), so a WebAuthnService-
			// issued legacy HMAC token can be authenticated through this
			// tokenauth_result path instead of the legacy branch below
			// whenever the AS is enabled - without this, a session logged
			// out through that deployment mode would never actually have
			// its refresh-token family revoked. New-style AS-issued tokens
			// (ModeSession) have no sid/refresh-token-family concept in
			// this codebase, so only ModeLegacy is handled here.
			if result.Mode == tokenauthclaims.ModeLegacy && h.services.TokenBlacklist != nil {
				rawToken, _ := c.Get("token")
				rawTokenStr, _ := rawToken.(string)
				sid, sidErr := legacytoken.ParseSID(h.cfg.JWT.Secret, rawTokenStr)
				if sidErr != nil {
					// Fail closed: without the sid the refresh-token family
					// cannot be revoked, so do not report a clean logout.
					h.logger.Error("Logout: cannot determine refresh-token family", zap.Error(sidErr))
					c.JSON(500, gin.H{"error": "Failed to revoke session"})
					return
				}
				if sid != "" {
					expiry := time.Now().Add(familyRetention(h.cfg) + time.Hour)
					if err := h.services.TokenBlacklist.RevokeFamily(c.Request.Context(), sid, expiry); err != nil {
						// Fail closed, like the sid-parse failure above: the
						// refresh token is still usable, so do not report a
						// clean logout. The client may retry (idempotent).
						h.logger.Error("Logout: failed to revoke refresh-token family",
							zap.String("sid", sid), zap.Error(err))
						c.JSON(500, gin.H{"error": "Failed to revoke session"})
						return
					}
					h.logger.Info("User logged out, refresh-token family revoked",
						zap.String("sid", sid),
					)
				}
			}

			// Blacklist the access-token jti only AFTER the family has been
			// revoked: if revocation failed above we returned 500 without
			// touching the jti, so the same token still passes the auth
			// middleware and the client can retry.
			if result.JTI != "" && h.services.TokenBlacklist != nil {
				expiry := time.Now().Add(ttlForTokenAuthResult(h.cfg, result) + time.Minute)
				if err := h.services.TokenBlacklist.Add(c.Request.Context(), result.JTI, expiry); err != nil {
					h.logger.Warn("Failed to blacklist token", zap.Error(err))
				} else {
					h.logger.Info("User logged out, token blacklisted",
						zap.String("jti", result.JTI),
					)
				}
			}

			c.JSON(200, gin.H{"message": "Logged out successfully"})
			return
		}
	}

	// Legacy HMAC path: get the token from context (set by auth middleware)
	tokenString, exists := c.Get("token")
	if !exists {
		// No token? Already logged out effectively
		c.Status(200)
		return
	}

	// Parse the token to get claims (we need jti, exp, and sid)
	token, _ := jwt.Parse(tokenString.(string), func(token *jwt.Token) (interface{}, error) {
		return []byte(h.cfg.JWT.Secret), nil
	})

	if token != nil && token.Claims != nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Refresh-token family revocation (#402) - see this function's
			// own doc comment.
			if sid, _ := claims["sid"].(string); sid != "" && h.services.TokenBlacklist != nil {
				familyExpiry := time.Now().Add(familyRetention(h.cfg) + time.Hour)
				if err := h.services.TokenBlacklist.RevokeFamily(c.Request.Context(), sid, familyExpiry); err != nil {
					// Fail closed: see the tokenauth path above.
					h.logger.Error("Logout: failed to revoke refresh-token family",
						zap.String("sid", sid), zap.Error(err))
					c.JSON(500, gin.H{"error": "Failed to revoke session"})
					return
				}
				h.logger.Info("User logged out, refresh-token family revoked",
					zap.String("sid", sid),
				)
			}

			// Blacklist the jti only after the family revocation succeeded -
			// see the tokenauth path above.
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

	// Use the same canonical holder DID resolution as every other credential
	// operation (see getHolderDID) - not the raw user_id - so this actually
	// finds and deletes the credentials/presentations that were stored under
	// it (#384).
	holderDID, _ := h.getHolderDID(c)

	if err := h.services.User.DeleteUser(
		c.Request.Context(),
		domain.UserIDFromString(userID.(string)),
		holderDID,
	); err != nil {
		if abortIfTokenRevoked(c, err) {
			return
		}
		if errors.Is(err, service.ErrUserNotFound) {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}
		if errors.Is(err, service.ErrDeletionCleanupPending) {
			// The account is gone and the caller's token is refused from now
			// on; the remainder is for an operator. 202: what was asked happened.
			h.logger.Error("Account deleted but cleanup incomplete", zap.Error(err))
			c.JSON(http.StatusAccepted, gin.H{
				"error":   errCodeDeletionCleanupPending,
				"result":  "DELETED",
				"message": "the account was deleted; some wallet data written while it was being deleted could not be removed yet and will be cleared by an operator. It is refused to every token and cannot be read; do not repeat the request",
			})
			return
		}
		if errors.Is(err, service.ErrDeletionOperatorRequired) {
			// Tokens are already refused for good, so a repeat cannot pass the
			// gate; an operator must finish the deletion. 202: under way.
			h.logger.Error("Account deletion stalled after token revocation, operator required", zap.Error(err))
			c.JSON(http.StatusAccepted, gin.H{
				"error":   errCodeDeletionOperatorRequired,
				"result":  "PENDING",
				"message": "the account's tokens have been revoked and the deletion has begun, but part of it could not be completed and only an operator can finish it; do not repeat the request",
			})
			return
		}
		if errors.Is(err, service.ErrDeletionIncomplete) {
			// The account stays on purpose so the caller can repeat the request.
			h.logger.Error("Account deletion incomplete", zap.Error(err))
			c.JSON(409, gin.H{
				"error":   errCodeDeletionIncomplete,
				"message": "part of the account data could not be removed; the account still exists, repeat the request to finish it",
			})
			return
		}
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
		if abortIfTokenRevoked(c, err) {
			return
		}
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
		if abortIfTokenRevoked(c, err) {
			return
		}
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
		if abortIfTokenRevoked(c, err) {
			return
		}
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
		if abortIfTokenRevoked(c, err) {
			return
		}
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
// GET /api/v1/tenants/:id/config
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
			DisplayName: g.RegistrationOP.EffectiveDisplayName(),
			Issuer:      g.RegistrationOP.Issuer,
			ClientID:    g.RegistrationOP.ClientID,
			Scopes:      g.RegistrationOP.EffectiveScopes(),
		}
	}
	if g.LoginOP != nil {
		resp.LoginOP = &PublicOIDCProviderResponse{
			DisplayName: g.LoginOP.EffectiveDisplayName(),
			Issuer:      g.LoginOP.Issuer,
			ClientID:    g.LoginOP.ClientID,
			Scopes:      g.LoginOP.EffectiveScopes(),
		}
	}
	return resp
}

// lifecycleRefusalBody is the 403 body of a SID-AUTH-06 login refusal: the
// error code and message plus a `scope` saying whether the wallet still exists.
// The AS passkey handler shares the mapping.
func lifecycleRefusalBody(err error) gin.H {
	d := service.LifecycleRefusalDetails(err)
	return gin.H{"error": d.Code, "scope": d.Scope, "message": d.Message}
}

// abortIfTokenRevoked answers 401 when a write refused the request's bearer
// token because the cut-off advanced after the middleware admitted it
// (tokengate.RefuseLoaded), and reports whether it answered.
// storage.ErrStaleWrite is the same refusal from the store's fence, not a server error.
func abortIfTokenRevoked(c *gin.Context, err error) bool {
	if !errors.Is(err, tokengate.ErrRevoked) && !errors.Is(err, storage.ErrStaleWrite) {
		return false
	}
	c.JSON(401, gin.H{"error": "Token has been revoked"})
	return true
}
