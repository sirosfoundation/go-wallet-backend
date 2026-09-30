// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"bytes"
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
	// baseURL, when set, overrides the configured registry URL (in-process
	// registry, see SetHandler).
	baseURL string
}

// inProcessRegistryBase is the base URL used for an in-process registry: the
// host is never resolved, the handler serves the request directly.
const inProcessRegistryBase = "http://registry.internal/registry"

// SetHandler makes the client call a registry served in the same process by
// handler (which serves the registry routes under /registry) instead of going
// over the network. This bypasses the outbound SSRF/scheme guards, which
// would otherwise reject the loopback address of a co-located registry.
func (rc *RegistryClient) SetHandler(h http.Handler) {
	rc.baseURL = inProcessRegistryBase
	rc.httpClient = &http.Client{Timeout: 10 * time.Second, Transport: handlerTransport{h}}
}

// handlerTransport is an http.RoundTripper that serves requests directly from
// an http.Handler.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := &bufferedResponse{header: http.Header{}, code: http.StatusOK}
	t.h.ServeHTTP(rec, req)
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", rec.code, http.StatusText(rec.code)),
		StatusCode:    rec.code,
		Header:        rec.header,
		Body:          io.NopCloser(&rec.body),
		ContentLength: int64(rec.body.Len()),
		Request:       req,
	}, nil
}

type bufferedResponse struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header         { return b.header }
func (b *bufferedResponse) WriteHeader(code int)        { b.code = code }
func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// NewRegistryClient creates a new registry client.
func NewRegistryClient(cfg *config.Config, logger *zap.Logger) *RegistryClient {
	return &RegistryClient{
		cfg:        cfg,
		logger:     logger.Named("registry_client"),
		httpClient: cfg.HTTPClient.NewHTTPClient(10 * time.Second),
	}
}

// registryURL returns the registry URL from config.
func (rc *RegistryClient) registryURL() string {
	if rc.baseURL != "" {
		return rc.baseURL
	}
	if rc.cfg.Trust.RegistryURL != "" {
		return rc.cfg.Trust.RegistryURL
	}
	return fmt.Sprintf("http://localhost:%d", rc.cfg.Server.RegistryPort)
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
// If the context contains a tenant ID (via ContextWithTenant), it is sent as X-Tenant-ID header.
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

	// Add X-Tenant-ID from context for adaptive routing
	if tenantID := TenantFromContext(ctx); tenantID != "" {
		req.Header.Set("X-Tenant-ID", tenantID)
	}

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		rc.logger.Debug("Registry fetch failed", zap.String("vct", vct), zap.Error(err))
		return nil, nil // Don't fail the whole flow if registry is unavailable
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // VCT not in registry
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
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
