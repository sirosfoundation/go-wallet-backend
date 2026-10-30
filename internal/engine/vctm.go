package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// VCTMHandler handles VCTM (Verifiable Credential Type Metadata) lookup flows.
//
// Registry lookups go through the Manager-supplied RegistryClient, so they use
// the same transport as every other registry user: the in-process handler in
// combined mode, HTTP to the configured registry otherwise. httpClient is only
// for the fallback fetch of a VCT that is itself a URL (an external,
// user-visible fetch, not a registry call).
type VCTMHandler struct {
	BaseHandler
	httpClient *http.Client
}

// NewVCTMHandler creates a new VCTM flow handler
func NewVCTMHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
	if registry == nil {
		registry = NewRegistryClient(cfg, logger)
	}
	return &VCTMHandler{
		BaseHandler: BaseHandler{
			Flow:     flow,
			Config:   cfg,
			Logger:   logger,
			TrustSvc: trustSvc,
			Registry: registry,
		},
		httpClient: cfg.HTTPClient.NewHTTPClient(10 * time.Second),
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
		_ = h.Error("", ErrCodeInvalidMessage, ErrCodeInvalidMessage.UserFacingMessage())
		return fmt.Errorf("VCT parameter required")
	}

	// Lookup type metadata
	metadata, err := h.lookupVCT(ctx, msg.VCT)
	if err != nil {
		h.Logger.Debug("VCT lookup failed", zap.Error(err))
		_ = h.Error("", ErrCodeMetadataFetchErr, ErrCodeMetadataFetchErr.UserFacingMessage())
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

// maxVCTMBytes bounds the type metadata document a lookup reads.
const maxVCTMBytes = 1 << 20

// errVCTMUnknown is returned by lookupVCTDocument when the registry answered
// that it has no entry for the vct and the vct is not a URL to try instead: the
// lookup knows the type is unknown (as opposed to unreachable or failing).
var errVCTMUnknown = errors.New("vctm: unknown type")

// lookupVCT is the type metadata of a vct, as the VCTM flow delivers it.
func (h *VCTMHandler) lookupVCT(ctx context.Context, vct string) (*TypeMetadata, error) {
	doc, err := h.lookupVCTDocument(ctx, vct)
	if err != nil {
		return nil, err
	}
	var metadata TypeMetadata
	if err := json.Unmarshal(doc, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}
	// Ensure VCT is set
	if metadata.VCT == "" {
		metadata.VCT = vct
	}
	return &metadata, nil
}

// lookupVCTDocument is the type metadata document of a vct, unparsed: the
// registry first; when it has no entry or cannot be reached and the vct is an
// absolute URL, that URL (WMP Core 5.8.1). Any other outcome of the registry
// lookup is a failure that does not fall through to the URL. The fetch of a URL
// goes through httpClient, whose address and scheme policy (loopback, private,
// link-local and metadata addresses and non-HTTPS refused unless configured for
// local development, redirects included) is the engine's for every fetch of a
// counterparty's URL. The result is at most maxVCTMBytes. errVCTMUnknown means
// the registry has no entry and there is no URL to try.
func (h *VCTMHandler) lookupVCTDocument(ctx context.Context, vct string) ([]byte, error) {
	resp, err := h.Registry.GetVCTM(ctx, vct)
	if err != nil {
		// The registry cannot be reached: try the vct as a URL.
		return h.lookupVCTDirect(ctx, vct)
	}
	defer resp.Body.Close() //nolint:errcheck

	switch resp.StatusCode {
	case http.StatusNotFound:
		if !isAbsoluteURL(vct) {
			return nil, errVCTMUnknown
		}
		return h.lookupVCTDirect(ctx, vct)
	case http.StatusOK:
		return readVCTMDocument(resp.Body)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	return nil, fmt.Errorf("registry returned status %d: %s", resp.StatusCode, string(body))
}

// isAbsoluteURL reports whether s is a URL with a scheme and a host: something
// that can be fetched (a urn: identifier is not).
func isAbsoluteURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// readVCTMDocument reads a type metadata document, at most maxVCTMBytes.
func readVCTMDocument(r io.Reader) ([]byte, error) {
	doc, err := io.ReadAll(io.LimitReader(r, maxVCTMBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}
	if len(doc) > maxVCTMBytes {
		return nil, fmt.Errorf("metadata exceeds %d bytes", maxVCTMBytes)
	}
	return doc, nil
}

func (h *VCTMHandler) lookupVCTDirect(ctx context.Context, vct string) ([]byte, error) {
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		return nil, fmt.Errorf("VCT fetch returned status %d: %s", resp.StatusCode, string(body))
	}
	return readVCTMDocument(resp.Body)
}
