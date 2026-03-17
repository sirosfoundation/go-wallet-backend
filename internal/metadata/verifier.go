package metadata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// VerifierMetadata represents OpenID4VP verifier (client) metadata.
// This can come from inline client_metadata or client_metadata_uri in the authorization request.
type VerifierMetadata struct {
	// Client identifier (verifier URL)
	ClientID string `json:"client_id"`

	// Client name for display
	ClientName string `json:"client_name,omitempty"`

	// Logo URI for display
	LogoURI string `json:"logo_uri,omitempty"`

	// Policy and terms URIs
	PolicyURI string `json:"policy_uri,omitempty"`
	TosURI    string `json:"tos_uri,omitempty"`

	// Redirect URIs the verifier is allowed to use
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// Response types the verifier supports
	ResponseTypes []string `json:"response_types,omitempty"`

	// Presentation definition formats the verifier accepts
	VPFormats json.RawMessage `json:"vp_formats,omitempty"`

	// JWKs for verifying verifier signatures
	JWKS    json.RawMessage `json:"jwks,omitempty"`
	JWKsURI string          `json:"jwks_uri,omitempty"`

	// X.509 certificate chain (for trust evaluation)
	X5C []string `json:"x5c,omitempty"`

	// Contacts
	Contacts []string `json:"contacts,omitempty"`
}

// VerifierDiscoveryResult contains the result of verifier metadata discovery
type VerifierDiscoveryResult struct {
	Metadata     *VerifierMetadata
	Certificates []string // PEM-encoded certificates from x5c or JWKS
	Error        error
}

// DiscoverVerifier fetches verifier metadata from client_metadata_uri.
// This is used internally by WebSocket flow handlers during credential presentation.
func DiscoverVerifier(ctx context.Context, clientMetadataURI string) *VerifierDiscoveryResult {
	result := &VerifierDiscoveryResult{}

	metadata, err := fetchVerifierMetadata(ctx, clientMetadataURI)
	if err != nil {
		result.Error = fmt.Errorf("fetching verifier metadata: %w", err)
		return result
	}
	result.Metadata = metadata

	// Extract certificates for trust evaluation
	if len(metadata.X5C) > 0 {
		result.Certificates = convertToPEM(metadata.X5C)
	}

	return result
}

// ParseInlineVerifierMetadata parses verifier metadata provided inline in the authorization request.
// This is used when client_metadata is provided directly instead of client_metadata_uri.
func ParseInlineVerifierMetadata(clientMetadata json.RawMessage) *VerifierDiscoveryResult {
	result := &VerifierDiscoveryResult{}

	var metadata VerifierMetadata
	if err := json.Unmarshal(clientMetadata, &metadata); err != nil {
		result.Error = fmt.Errorf("parsing client_metadata: %w", err)
		return result
	}
	result.Metadata = &metadata

	// Extract certificates for trust evaluation
	if len(metadata.X5C) > 0 {
		result.Certificates = convertToPEM(metadata.X5C)
	}

	return result
}

// fetchVerifierMetadata fetches verifier metadata from client_metadata_uri
func fetchVerifierMetadata(ctx context.Context, metadataURI string) (*VerifierMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURI, nil)
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

	var metadata VerifierMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &metadata, nil
}

// convertToPEM converts base64-encoded DER certificates to PEM format
func convertToPEM(certs []string) []string {
	pem := make([]string, len(certs))
	for i, cert := range certs {
		pem[i] = fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", cert)
	}
	return pem
}
