package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DiscoveryDocument represents an OpenID Connect discovery document
type DiscoveryDocument struct {
	Issuer                  string   `json:"issuer"`
	AuthorizationEndpoint   string   `json:"authorization_endpoint"`
	TokenEndpoint           string   `json:"token_endpoint"`
	UserinfoEndpoint        string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                 string   `json:"jwks_uri"`
	ScopesSupported         []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported  []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported   []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValues []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

// fetchDiscovery fetches the OIDC discovery document from the issuer
func (v *Validator) fetchDiscovery(ctx context.Context) (*DiscoveryDocument, error) {
	// Build the well-known URL
	issuer := strings.TrimSuffix(v.config.Issuer, "/")
	discoveryURL := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery response: %w", err)
	}

	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse discovery document: %w", err)
	}

	// Validate issuer matches
	if doc.Issuer != v.config.Issuer && doc.Issuer != issuer {
		return nil, fmt.Errorf("issuer mismatch: expected %s, got %s", v.config.Issuer, doc.Issuer)
	}

	// Validate required fields
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document missing jwks_uri")
	}

	v.logger.Debug("fetched discovery document",
		zap.String("issuer", doc.Issuer),
		zap.String("jwks_uri", doc.JWKSURI))

	return &doc, nil
}

// DiscoverProvider fetches the OIDC configuration for a given issuer.
// If httpClient is nil, a default client with 10s timeout is used.
// This is a standalone function for use outside the Validator.
func DiscoverProvider(ctx context.Context, issuer string, httpClient *http.Client) (*DiscoveryDocument, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	discoveryURL := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second, // Apply reasonable timeout to avoid indefinite hangs
		}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery response: %w", err)
	}

	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse discovery document: %w", err)
	}

	return &doc, nil
}
