// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// RegistryClient provides access to the VCTM registry.
type RegistryClient struct {
	cfg        *config.Config
	logger     *zap.Logger
	httpClient *http.Client
}

// NewRegistryClient creates a new registry client.
func NewRegistryClient(cfg *config.Config, logger *zap.Logger) *RegistryClient {
	return &RegistryClient{
		cfg:    cfg,
		logger: logger.Named("registry_client"),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// registryURL returns the registry URL from config.
func (rc *RegistryClient) registryURL() string {
	if rc.cfg.Trust.RegistryURL != "" {
		return rc.cfg.Trust.RegistryURL
	}
	return "http://localhost:8082" // Default
}

// VCTMetadata represents the type metadata returned by the registry.
type VCTMetadata struct {
	VCT         string          `json:"vct"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Display     json.RawMessage `json:"display,omitempty"`
	Claims      json.RawMessage `json:"claims,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// FetchTypeMetadata fetches VCTM for the given VCT identifier.
// Returns nil, nil if the VCT is not found (no error).
func (rc *RegistryClient) FetchTypeMetadata(ctx context.Context, vct string) (*VCTMetadata, error) {
	if vct == "" {
		return nil, nil
	}

	// Build URL
	reqURL := fmt.Sprintf("%s/type-metadata?vct=%s", rc.registryURL(), url.QueryEscape(vct))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		rc.logger.Debug("Registry fetch failed", zap.String("vct", vct), zap.Error(err))
		return nil, nil // Don't fail the whole flow if registry is unavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // VCT not in registry
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		rc.logger.Debug("Registry error", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		return nil, nil
	}

	var metadata VCTMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse registry response: %w", err)
	}

	return &metadata, nil
}

// FetchTypeMetadataJSON fetches VCTM and returns it as JSON raw message.
// Returns nil if not found or on error (to not fail the flow).
func (rc *RegistryClient) FetchTypeMetadataJSON(ctx context.Context, vct string) json.RawMessage {
	metadata, err := rc.FetchTypeMetadata(ctx, vct)
	if err != nil {
		rc.logger.Debug("Failed to fetch VCTM", zap.String("vct", vct), zap.Error(err))
		return nil
	}
	if metadata == nil {
		return nil
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		rc.logger.Debug("Failed to marshal VCTM", zap.String("vct", vct), zap.Error(err))
		return nil
	}

	return data
}
