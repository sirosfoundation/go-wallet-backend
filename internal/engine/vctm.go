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

// VCTMHandler handles VCTM (Verifiable Credential Type Metadata) lookup flows
type VCTMHandler struct {
	BaseHandler
	httpClient  *http.Client
	registryURL string
}

// NewVCTMHandler creates a new VCTM flow handler
func NewVCTMHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient) (FlowHandler, error) {
	// Get registry URL from config, or use default
	registryURL := cfg.Trust.RegistryURL
	if registryURL == "" {
		registryURL = fmt.Sprintf("http://localhost:%d", cfg.Server.RegistryPort)
	}

	return &VCTMHandler{
		BaseHandler: BaseHandler{
			Flow:     flow,
			Config:   cfg,
			Logger:   logger,
			TrustSvc: trustSvc,
			Registry: registry,
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		registryURL: registryURL,
	}, nil
}

// TypeMetadata represents VCTM type metadata
type TypeMetadata struct {
	VCT         string          `json:"vct"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Display     json.RawMessage `json:"display,omitempty"`
	Claims      json.RawMessage `json:"claims,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// Execute runs the VCTM lookup flow
func (h *VCTMHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	ctx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	defer cancel()

	if msg.VCT == "" {
		_ = h.Error("", ErrCodeInvalidMessage, "VCT parameter is required")
		return fmt.Errorf("VCT parameter required")
	}

	// Lookup type metadata
	metadata, err := h.lookupVCT(ctx, msg.VCT)
	if err != nil {
		_ = h.Error("", ErrCodeMetadataFetchErr, err.Error())
		return err
	}

	// Convert to JSON for response
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	// Complete with metadata
	completeMsg := FlowCompleteMessage{
		Message: Message{
			Type:      TypeFlowComplete,
			FlowID:    h.Flow.ID,
			Timestamp: Now(),
		},
		TypeMetadata: metadataJSON,
	}

	return h.Flow.Session.Send(&completeMsg)
}

func (h *VCTMHandler) lookupVCT(ctx context.Context, vct string) (*TypeMetadata, error) {
	// Build registry lookup URL
	lookupURL := h.registryURL + "/vctm/" + url.PathEscape(vct)

	req, err := http.NewRequestWithContext(ctx, "GET", lookupURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		// Try direct VCT URL as fallback
		return h.lookupVCTDirect(ctx, vct)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		// Try direct VCT URL
		return h.lookupVCTDirect(ctx, vct)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry returned status %d: %s", resp.StatusCode, string(body))
	}

	var metadata TypeMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	return &metadata, nil
}

func (h *VCTMHandler) lookupVCTDirect(ctx context.Context, vct string) (*TypeMetadata, error) {
	// VCT is a URL - try fetching directly
	req, err := http.NewRequestWithContext(ctx, "GET", vct, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid VCT URL: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch VCT: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("VCT fetch returned status %d: %s", resp.StatusCode, string(body))
	}

	var metadata TypeMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse VCT metadata: %w", err)
	}

	// Ensure VCT is set
	if metadata.VCT == "" {
		metadata.VCT = vct
	}

	return &metadata, nil
}
