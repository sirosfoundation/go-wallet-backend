package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"go.uber.org/zap"
)

// IssuerMetadataRequest is the request body for POST /issuer-metadata
type IssuerMetadataRequest struct {
	// EntityIdentifier is the issuer or verifier identifier (URL).
	// For issuers: the credential_issuer value (e.g., "https://issuer.example.com")
	// For verifiers: the verifier URL
	EntityIdentifier string `json:"entity_identifier" binding:"required"`

	// Role specifies what role to evaluate trust for.
	// Must be "issuer" or "verifier".
	Role string `json:"role" binding:"required,oneof=issuer verifier"`

	// CredentialType is an optional credential type to evaluate trust for.
	// For mDOC: the docType (e.g., "eu.europa.ec.eudi.pid.1")
	// For SD-JWT: the vct (e.g., "urn:eu.europa.ec.eudi:pid:1")
	CredentialType string `json:"credential_type,omitempty"`
}

// IssuerMetadataResponse is the response from POST /issuer-metadata
type IssuerMetadataResponse struct {
	// Discovered metadata (if any)
	IssuerMetadata   json.RawMessage `json:"issuer_metadata,omitempty"`
	VerifierMetadata json.RawMessage `json:"verifier_metadata,omitempty"`

	// Trust evaluation result
	Trusted        bool              `json:"trusted"`
	TrustStatus    domain.TrustStatus `json:"trust_status"`
	Reason         string            `json:"reason"`
	TrustFramework string            `json:"trust_framework,omitempty"`

	// Trusted certificates (PEM format, if discovery found any and they're trusted)
	TrustedCertificates []string `json:"trusted_certificates,omitempty"`

	// Discovery details
	DiscoveryStatus string `json:"discovery_status"` // "success", "partial", "failed"
	DiscoveryError  string `json:"discovery_error,omitempty"`

	// Issuer persistence (if saved to CredentialIssuer)
	IssuerID *int64 `json:"issuer_id,omitempty"`
}

// OpenID4VCIIssuerMetadata represents the credential issuer metadata from
// .well-known/openid-credential-issuer
type OpenID4VCIIssuerMetadata struct {
	CredentialIssuer                  string          `json:"credential_issuer"`
	AuthorizationServers              []string        `json:"authorization_servers,omitempty"`
	CredentialEndpoint                string          `json:"credential_endpoint"`
	DeferredCredentialEndpoint        string          `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint              string          `json:"notification_endpoint,omitempty"`
	CredentialResponseEncryption      json.RawMessage `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance           json.RawMessage `json:"batch_credential_issuance,omitempty"`
	SignedMetadata                    string          `json:"signed_metadata,omitempty"`
	Display                           json.RawMessage `json:"display,omitempty"`
	CredentialConfigurationsSupported json.RawMessage `json:"credential_configurations_supported,omitempty"`
	// IACA certificates URL for mDOC
	MdocIacasURI string `json:"mdoc_iacas_uri,omitempty"`
}

// MdocIacasResponse represents the response from mdoc_iacas_uri
type MdocIacasResponse struct {
	Iacas []struct {
		Certificate string `json:"certificate"` // Base64-encoded DER
	} `json:"iacas"`
}

// IssuerMetadataHandler handles issuer metadata discovery and trust evaluation.
// It is separate from the main Handler to allow for optional configuration.
// Can operate in two modes:
// 1. With TrustService and database storage (full per-tenant trust)
// 2. Standalone with default trust endpoint (simpler registry mode)
type IssuerMetadataHandler struct {
	trustService         *service.TrustService
	issuerStore          storage.IssuerStore
	tenantStore          storage.TenantStore
	defaultTrustEndpoint string
	defaultTrustTTL      time.Duration
	logger               *zap.Logger
}

// IssuerMetadataConfig configures the IssuerMetadataHandler
type IssuerMetadataConfig struct {
	// DefaultTrustEndpoint is used when tenant has no specific trust endpoint configured
	// or when running in standalone registry mode
	DefaultTrustEndpoint string

	// DefaultTrustTTL is the default trust cache TTL (default: 24 hours)
	DefaultTrustTTL time.Duration
}

// NewIssuerMetadataHandler creates a new IssuerMetadataHandler
func NewIssuerMetadataHandler(
	trustService *service.TrustService,
	issuerStore storage.IssuerStore,
	tenantStore storage.TenantStore,
	config *IssuerMetadataConfig,
	logger *zap.Logger,
) *IssuerMetadataHandler {
	defaultEndpoint := ""
	defaultTTL := 24 * time.Hour
	if config != nil {
		defaultEndpoint = config.DefaultTrustEndpoint
		if config.DefaultTrustTTL > 0 {
			defaultTTL = config.DefaultTrustTTL
		}
	}
	return &IssuerMetadataHandler{
		trustService:         trustService,
		issuerStore:          issuerStore,
		tenantStore:          tenantStore,
		defaultTrustEndpoint: defaultEndpoint,
		defaultTrustTTL:      defaultTTL,
		logger:               logger.Named("issuer-metadata"),
	}
}

// NewStandaloneIssuerMetadataHandler creates an IssuerMetadataHandler for standalone registry mode
// (no database storage, just metadata discovery and optional trust evaluation)
func NewStandaloneIssuerMetadataHandler(config *IssuerMetadataConfig, logger *zap.Logger) *IssuerMetadataHandler {
	return NewIssuerMetadataHandler(nil, nil, nil, config, logger)
}

// GetIssuerMetadata handles POST /issuer-metadata
// This endpoint discovers entity metadata, evaluates trust, and persists the result.
func (h *IssuerMetadataHandler) GetIssuerMetadata(c *gin.Context) {
	var req IssuerMetadataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get tenant from context (assumes tenant middleware sets this)
	tenantID := domain.TenantID(c.GetString("tenant_id"))
	if tenantID == "" {
		tenantID = domain.DefaultTenantID
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	resp := &IssuerMetadataResponse{
		DiscoveryStatus: "failed",
		Trusted:         false,
		TrustStatus:     domain.TrustStatusUnknown,
	}

	switch req.Role {
	case "issuer":
		h.handleIssuer(ctx, tenantID, req, resp)
	case "verifier":
		h.handleVerifier(ctx, tenantID, req, resp)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// handleIssuer handles issuer metadata discovery, trust evaluation, and persistence
func (h *IssuerMetadataHandler) handleIssuer(ctx context.Context, tenantID domain.TenantID, req IssuerMetadataRequest, resp *IssuerMetadataResponse) {
	// Step 1: Check if we already have this issuer with valid trust cache
	existing, err := h.issuerStore.GetByIdentifier(ctx, tenantID, req.EntityIdentifier)
	if err == nil && existing != nil && h.isTrustValid(ctx, tenantID, existing) {
		// Return cached result
		resp.Trusted = existing.TrustStatus == domain.TrustStatusTrusted
		resp.TrustStatus = existing.TrustStatus
		resp.TrustFramework = existing.TrustFramework
		resp.Reason = "cached trust evaluation"
		resp.DiscoveryStatus = "cached"
		resp.IssuerID = &existing.ID
		return
	}

	// Step 2: Discover issuer metadata
	metadata, err := h.fetchIssuerMetadata(ctx, req.EntityIdentifier)
	if err != nil {
		resp.DiscoveryError = fmt.Sprintf("failed to fetch issuer metadata: %v", err)
		resp.Reason = "discovery failed"
		// Still try to persist with unknown trust status
		h.persistIssuer(ctx, tenantID, req.EntityIdentifier, existing, resp)
		return
	}

	// Store discovered metadata
	metadataJSON, _ := json.Marshal(metadata)
	resp.IssuerMetadata = metadataJSON
	resp.DiscoveryStatus = "success"

	// Step 3: Fetch IACA certificates if available
	var certificates []string
	if metadata.MdocIacasURI != "" {
		certs, err := h.fetchIACACertificates(ctx, metadata.MdocIacasURI)
		if err != nil {
			h.logger.Warn("failed to fetch IACA certificates",
				zap.String("uri", metadata.MdocIacasURI),
				zap.Error(err))
			resp.DiscoveryStatus = "partial"
		} else {
			certificates = certs
		}
	}

	// Step 4: Evaluate trust
	h.evaluateTrust(ctx, tenantID, req, certificates, resp)

	// Step 5: Persist issuer with trust status
	h.persistIssuer(ctx, tenantID, req.EntityIdentifier, existing, resp)
}

// handleVerifier handles verifier metadata discovery and trust evaluation
func (h *IssuerMetadataHandler) handleVerifier(ctx context.Context, tenantID domain.TenantID, req IssuerMetadataRequest, resp *IssuerMetadataResponse) {
	// TODO: Implement verifier metadata discovery (OpenID4VP)
	// For now, just evaluate trust based on the identifier
	h.evaluateVerifierTrust(ctx, tenantID, req, resp)
}

// isTrustValid checks if the cached trust evaluation is still valid
func (h *IssuerMetadataHandler) isTrustValid(ctx context.Context, tenantID domain.TenantID, issuer *domain.CredentialIssuer) bool {
	if issuer.TrustEvaluatedAt == nil {
		return false
	}

	// Get tenant's trust TTL configuration
	ttl := 86400 * time.Second // Default 24 hours
	if h.tenantStore != nil {
		tenant, err := h.tenantStore.GetByID(ctx, tenantID)
		if err == nil && tenant.TrustConfig.TrustTTL > 0 {
			ttl = time.Duration(tenant.TrustConfig.TrustTTL) * time.Second
		}
	}

	return time.Since(*issuer.TrustEvaluatedAt) < ttl
}

// persistIssuer creates or updates the CredentialIssuer record
func (h *IssuerMetadataHandler) persistIssuer(ctx context.Context, tenantID domain.TenantID, identifier string, existing *domain.CredentialIssuer, resp *IssuerMetadataResponse) {
	if h.issuerStore == nil {
		return
	}

	now := time.Now()

	if existing != nil {
		// Update existing issuer
		existing.TrustStatus = resp.TrustStatus
		existing.TrustFramework = resp.TrustFramework
		existing.TrustEvaluatedAt = &now

		if err := h.issuerStore.Update(ctx, existing); err != nil {
			h.logger.Error("failed to update issuer trust",
				zap.String("identifier", identifier),
				zap.Error(err))
		} else {
			resp.IssuerID = &existing.ID
		}
	} else {
		// Create new issuer
		issuer := &domain.CredentialIssuer{
			TenantID:                   tenantID,
			CredentialIssuerIdentifier: identifier,
			Visible:                    true,
			TrustStatus:                resp.TrustStatus,
			TrustFramework:             resp.TrustFramework,
			TrustEvaluatedAt:           &now,
		}

		if err := h.issuerStore.Create(ctx, issuer); err != nil {
			h.logger.Error("failed to create issuer",
				zap.String("identifier", identifier),
				zap.Error(err))
		} else {
			resp.IssuerID = &issuer.ID
		}
	}
}

// fetchIssuerMetadata fetches OpenID4VCI issuer metadata
func (h *IssuerMetadataHandler) fetchIssuerMetadata(ctx context.Context, issuerURL string) (*OpenID4VCIIssuerMetadata, error) {
	// Construct well-known URL
	wellKnownURL := issuerURL + "/.well-known/openid-credential-issuer"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("metadata request returned %d: %s", httpResp.StatusCode, string(body))
	}

	var metadata OpenID4VCIIssuerMetadata
	if err := json.NewDecoder(httpResp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decoding metadata: %w", err)
	}

	return &metadata, nil
}

// fetchIACACertificates fetches IACA certificates from mdoc_iacas_uri
func (h *IssuerMetadataHandler) fetchIACACertificates(ctx context.Context, iacasURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, iacasURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching IACA certificates: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("IACA request returned %d: %s", httpResp.StatusCode, string(body))
	}

	var iacasResp MdocIacasResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&iacasResp); err != nil {
		return nil, fmt.Errorf("decoding IACA response: %w", err)
	}

	// Convert to PEM format
	var pemCerts []string
	for _, iaca := range iacasResp.Iacas {
		pem := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", iaca.Certificate)
		pemCerts = append(pemCerts, pem)
	}

	return pemCerts, nil
}

// evaluateTrust evaluates trust for an issuer using the configured trust evaluator
func (h *IssuerMetadataHandler) evaluateTrust(ctx context.Context, tenantID domain.TenantID, req IssuerMetadataRequest, certificates []string, resp *IssuerMetadataResponse) {
	// Check if trust service is available
	if h.trustService == nil {
		// No trust service configured - mark as unknown but allow
		resp.Trusted = true
		resp.TrustStatus = domain.TrustStatusUnknown
		resp.Reason = "no trust evaluation configured (default allow)"
		resp.TrustedCertificates = certificates
		return
	}

	// TODO: Get tenant-specific trust endpoint and create per-tenant evaluator
	// For now, use the shared trust service

	// Use trust service to evaluate
	trustResp, err := h.trustService.EvaluateIssuer(ctx, req.EntityIdentifier, req.CredentialType, certificates)
	if err != nil {
		h.logger.Error("trust evaluation failed",
			zap.String("entity", req.EntityIdentifier),
			zap.String("tenant", string(tenantID)),
			zap.Error(err))
		resp.Trusted = false
		resp.TrustStatus = domain.TrustStatusUnknown
		resp.Reason = fmt.Sprintf("trust evaluation error: %v", err)
		return
	}

	resp.Trusted = trustResp.Trusted
	if trustResp.Trusted {
		resp.TrustStatus = domain.TrustStatusTrusted
	} else {
		resp.TrustStatus = domain.TrustStatusUntrusted
	}
	resp.Reason = trustResp.Reason
	resp.TrustFramework = trustResp.TrustFramework

	// Only include certificates if trusted
	if trustResp.Trusted {
		resp.TrustedCertificates = certificates
	}
}

// evaluateVerifierTrust evaluates trust for a verifier
func (h *IssuerMetadataHandler) evaluateVerifierTrust(ctx context.Context, tenantID domain.TenantID, req IssuerMetadataRequest, resp *IssuerMetadataResponse) {
	// Check if trust service is available
	if h.trustService == nil {
		// No trust service configured - mark as unknown but allow
		resp.Trusted = true
		resp.TrustStatus = domain.TrustStatusUnknown
		resp.Reason = "no trust evaluation configured (default allow)"
		resp.DiscoveryStatus = "skipped"
		return
	}

	// Use trust service to evaluate
	trustResp, err := h.trustService.EvaluateVerifier(ctx, req.EntityIdentifier, req.CredentialType)
	if err != nil {
		h.logger.Error("trust evaluation failed",
			zap.String("entity", req.EntityIdentifier),
			zap.String("tenant", string(tenantID)),
			zap.Error(err))
		resp.Trusted = false
		resp.TrustStatus = domain.TrustStatusUnknown
		resp.Reason = fmt.Sprintf("trust evaluation error: %v", err)
		resp.DiscoveryStatus = "skipped"
		return
	}

	resp.Trusted = trustResp.Trusted
	if trustResp.Trusted {
		resp.TrustStatus = domain.TrustStatusTrusted
	} else {
		resp.TrustStatus = domain.TrustStatusUntrusted
	}
	resp.Reason = trustResp.Reason
	resp.TrustFramework = trustResp.TrustFramework
	resp.DiscoveryStatus = "success"
}
