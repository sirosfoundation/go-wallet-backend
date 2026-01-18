package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// DiscoverAndTrustRequest is the request body for POST /api/discover-and-trust
type DiscoverAndTrustRequest struct {
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

// DiscoverAndTrustResponse is the response from POST /api/discover-and-trust
type DiscoverAndTrustResponse struct {
	// Discovered metadata (if any)
	IssuerMetadata  json.RawMessage `json:"issuer_metadata,omitempty"`
	VerifierMetadata json.RawMessage `json:"verifier_metadata,omitempty"`

	// Trust evaluation result
	Trusted bool   `json:"trusted"`
	Reason  string `json:"reason"`

	// Trusted certificates (PEM format, if discovery found any and they're trusted)
	TrustedCertificates []string `json:"trusted_certificates,omitempty"`

	// Trust framework that authorized this entity (e.g., "eudi", "openid_federation")
	TrustFramework string `json:"trust_framework,omitempty"`

	// Discovery details
	DiscoveryStatus string `json:"discovery_status"` // "success", "partial", "failed"
	DiscoveryError  string `json:"discovery_error,omitempty"`
}

// OpenID4VCIIssuerMetadata represents the credential issuer metadata from
// .well-known/openid-credential-issuer
type OpenID4VCIIssuerMetadata struct {
	CredentialIssuer              string          `json:"credential_issuer"`
	AuthorizationServers          []string        `json:"authorization_servers,omitempty"`
	CredentialEndpoint            string          `json:"credential_endpoint"`
	DeferredCredentialEndpoint    string          `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint          string          `json:"notification_endpoint,omitempty"`
	CredentialResponseEncryption  json.RawMessage `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance       json.RawMessage `json:"batch_credential_issuance,omitempty"`
	SignedMetadata                string          `json:"signed_metadata,omitempty"`
	Display                       json.RawMessage `json:"display,omitempty"`
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

// DiscoverAndTrust handles POST /api/discover-and-trust
// This endpoint combines entity discovery with trust evaluation.
// Available when the backend reports api_version >= 2.
func (h *Handlers) DiscoverAndTrust(c *gin.Context) {
	var req DiscoverAndTrustRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	resp := &DiscoverAndTrustResponse{
		DiscoveryStatus: "failed",
		Trusted:         false,
	}

	switch req.Role {
	case "issuer":
		h.discoverAndTrustIssuer(ctx, req, resp)
	case "verifier":
		h.discoverAndTrustVerifier(ctx, req, resp)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// discoverAndTrustIssuer handles issuer discovery and trust evaluation
func (h *Handlers) discoverAndTrustIssuer(ctx context.Context, req DiscoverAndTrustRequest, resp *DiscoverAndTrustResponse) {
	// Step 1: Discover issuer metadata
	metadata, err := h.fetchIssuerMetadata(ctx, req.EntityIdentifier)
	if err != nil {
		resp.DiscoveryError = fmt.Sprintf("failed to fetch issuer metadata: %v", err)
		resp.Reason = "discovery failed"
		return
	}

	// Store discovered metadata
	metadataJSON, _ := json.Marshal(metadata)
	resp.IssuerMetadata = metadataJSON
	resp.DiscoveryStatus = "success"

	// Step 2: Fetch IACA certificates if available
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

	// Step 3: Evaluate trust
	h.evaluateIssuerTrust(ctx, req, certificates, resp)
}

// discoverAndTrustVerifier handles verifier discovery and trust evaluation
func (h *Handlers) discoverAndTrustVerifier(ctx context.Context, req DiscoverAndTrustRequest, resp *DiscoverAndTrustResponse) {
	// TODO: Implement verifier metadata discovery (OpenID4VP)
	// For now, just evaluate trust based on the identifier
	h.evaluateVerifierTrust(ctx, req, resp)
}

// fetchIssuerMetadata fetches OpenID4VCI issuer metadata
func (h *Handlers) fetchIssuerMetadata(ctx context.Context, issuerURL string) (*OpenID4VCIIssuerMetadata, error) {
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
	defer httpResp.Body.Close()

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
func (h *Handlers) fetchIACACertificates(ctx context.Context, iacasURL string) ([]string, error) {
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
	defer httpResp.Body.Close()

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

// evaluateIssuerTrust evaluates trust for an issuer using the configured trust evaluator
func (h *Handlers) evaluateIssuerTrust(ctx context.Context, req DiscoverAndTrustRequest, certificates []string, resp *DiscoverAndTrustResponse) {
	// Check if trust service is available
	if h.services.Trust == nil {
		// No trust service configured - fall back to allowing all discovered issuers
		// This maintains backward compatibility
		resp.Trusted = true
		resp.Reason = "no trust evaluation configured (default allow)"
		resp.TrustedCertificates = certificates
		return
	}

	// Use trust service to evaluate
	trustResp, err := h.services.Trust.EvaluateIssuer(ctx, req.EntityIdentifier, req.CredentialType, certificates)
	if err != nil {
		h.logger.Error("trust evaluation failed",
			zap.String("entity", req.EntityIdentifier),
			zap.Error(err))
		resp.Trusted = false
		resp.Reason = fmt.Sprintf("trust evaluation error: %v", err)
		return
	}

	resp.Trusted = trustResp.Trusted
	resp.Reason = trustResp.Reason
	resp.TrustFramework = trustResp.TrustFramework

	// Only include certificates if trusted
	if trustResp.Trusted {
		resp.TrustedCertificates = certificates
	}
}

// evaluateVerifierTrust evaluates trust for a verifier using the configured trust evaluator
func (h *Handlers) evaluateVerifierTrust(ctx context.Context, req DiscoverAndTrustRequest, resp *DiscoverAndTrustResponse) {
	// Check if trust service is available
	if h.services.Trust == nil {
		// No trust service configured - fall back to allowing all verifiers
		// This maintains backward compatibility
		resp.Trusted = true
		resp.Reason = "no trust evaluation configured (default allow)"
		resp.DiscoveryStatus = "skipped"
		return
	}

	// Use trust service to evaluate
	trustResp, err := h.services.Trust.EvaluateVerifier(ctx, req.EntityIdentifier, req.CredentialType)
	if err != nil {
		h.logger.Error("trust evaluation failed",
			zap.String("entity", req.EntityIdentifier),
			zap.Error(err))
		resp.Trusted = false
		resp.Reason = fmt.Sprintf("trust evaluation error: %v", err)
		resp.DiscoveryStatus = "skipped"
		return
	}

	resp.Trusted = trustResp.Trusted
	resp.Reason = trustResp.Reason
	resp.TrustFramework = trustResp.TrustFramework
	resp.DiscoveryStatus = "success"
}
