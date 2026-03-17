// Package metadata provides entity metadata discovery services for OpenID4VC protocols.
// These services fetch and parse metadata from credential issuers and verifiers,
// to be used internally by WebSocket flow handlers.
package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IssuerMetadata represents the credential issuer metadata from
// .well-known/openid-credential-issuer (OpenID4VCI)
type IssuerMetadata struct {
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

// IACACertificate represents an IACA certificate from mdoc_iacas_uri
type IACACertificate struct {
	Certificate string `json:"certificate"` // Base64-encoded DER
}

// IACAsResponse represents the response from mdoc_iacas_uri
type IACAsResponse struct {
	Iacas []IACACertificate `json:"iacas"`
}

// IssuerDiscoveryResult contains the result of issuer metadata discovery
type IssuerDiscoveryResult struct {
	Metadata     *IssuerMetadata
	Certificates []string // PEM-encoded certificates from IACA
	Error        error
	Partial      bool // true if some discovery failed (e.g., IACA fetch)
}

// DiscoverIssuer fetches OpenID4VCI issuer metadata and optional IACA certificates.
// This is used internally by WebSocket flow handlers during credential issuance.
func DiscoverIssuer(ctx context.Context, issuerURL string) *IssuerDiscoveryResult {
	result := &IssuerDiscoveryResult{}

	// Fetch issuer metadata from well-known endpoint
	metadata, err := fetchIssuerMetadata(ctx, issuerURL)
	if err != nil {
		result.Error = fmt.Errorf("fetching issuer metadata: %w", err)
		return result
	}
	result.Metadata = metadata

	// Fetch IACA certificates if available (mDOC)
	if metadata.MdocIacasURI != "" {
		certs, err := fetchIACACertificates(ctx, metadata.MdocIacasURI)
		if err != nil {
			// Partial success - metadata OK but IACA failed
			result.Partial = true
			result.Error = fmt.Errorf("fetching IACA certificates: %w", err)
		} else {
			result.Certificates = certs
		}
	}

	return result
}

// fetchIssuerMetadata fetches OpenID4VCI issuer metadata from well-known endpoint
func fetchIssuerMetadata(ctx context.Context, issuerURL string) (*IssuerMetadata, error) {
	wellKnownURL := issuerURL + "/.well-known/openid-credential-issuer"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SIROS-Wallet/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var metadata IssuerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &metadata, nil
}

// fetchIACACertificates fetches IACA certificates from mdoc_iacas_uri
func fetchIACACertificates(ctx context.Context, iacasURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, iacasURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SIROS-Wallet/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var iacasResp IACAsResponse
	if err := json.NewDecoder(resp.Body).Decode(&iacasResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Convert to PEM format
	var pemCerts []string
	for _, iaca := range iacasResp.Iacas {
		pem := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", iaca.Certificate)
		pemCerts = append(pemCerts, pem)
	}

	return pemCerts, nil
}
