package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RegistryIndex represents the upstream vctm-registry.json structure (legacy format)
type RegistryIndex struct {
	Schema      string               `json:"$schema"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	URL         string               `json:"url"`
	Version     string               `json:"version"`
	Credentials []RegistryCredential `json:"credentials"`
	BuildTime   string               `json:"buildTime"`
}

// RegistryCredential represents a credential entry in the registry index (legacy format)
type RegistryCredential struct {
	VCT          string                      `json:"vct"`
	Name         string                      `json:"name"`
	Description  string                      `json:"description,omitempty"`
	Organization string                      `json:"organization,omitempty"`
	Formats      map[string]CredentialFormat `json:"formats"`
	Metadata     CredentialMetadata          `json:"metadata,omitempty"`
	Source       CredentialSource            `json:"source,omitempty"`
}

// CredentialFormat represents format-specific URLs
type CredentialFormat struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

// CredentialMetadata contains URLs to metadata documents
type CredentialMetadata struct {
	HTML string `json:"html,omitempty"`
	JSON string `json:"json,omitempty"`
}

// CredentialSource contains repository information
type CredentialSource struct {
	Repository string `json:"repository,omitempty"`
	Branch     string `json:"branch,omitempty"`
}

// TS11SchemasResponse represents the paginated response from /api/v1/schemas.json
type TS11SchemasResponse struct {
	Schemas  []TS11SchemaMeta `json:"schemas"`
	Total    int              `json:"total,omitempty"`
	Page     int              `json:"page,omitempty"`
	PageSize int              `json:"pageSize,omitempty"`
	// Next is the URL of the next page; empty when there are no more pages
	Next string `json:"next,omitempty"`
}

// TS11SchemaMeta represents a single schema entry in the TS11 API
type TS11SchemaMeta struct {
	ID                 string          `json:"id"`
	Version            string          `json:"version"`
	AttestationLoS     string          `json:"attestationLoS"`
	BindingType        string          `json:"bindingType"`
	SupportedFormats   []string        `json:"supportedFormats"`
	SchemaURIs         []TS11SchemaURI `json:"schemaURIs"`
	RulebookURI        string          `json:"rulebookURI"`
	TrustedAuthorities []string        `json:"trustedAuthorities,omitempty"`
}

// TS11SchemaURI represents a format-specific URI within a TS11 schema
type TS11SchemaURI struct {
	FormatIdentifier string `json:"formatIdentifier"`
	URI              string `json:"uri"`
}

// Fetcher handles fetching VCTMs from the upstream registry
type Fetcher struct {
	config *Config
	store  *Store
	client *http.Client
	logger *zap.Logger

	// stopCh signals the polling goroutine to stop
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewFetcher creates a new registry fetcher.
// httpClient should be a centralized HTTP client with proxy/TLS settings applied.
// If nil, a default client is used (suitable for testing only - production code
// should always pass a configured client via HTTPClientConfig).
func NewFetcher(config *Config, store *Store, logger *zap.Logger, httpClient *http.Client) *Fetcher {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: config.Source.Timeout,
		}
	}
	return &Fetcher{
		config: config,
		store:  store,
		client: httpClient,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start begins the polling loop
func (f *Fetcher) Start(ctx context.Context) error {
	// Do an initial fetch
	if err := f.Fetch(ctx); err != nil {
		f.logger.Warn("initial fetch failed, will retry on next poll", zap.Error(err))
	}

	// Start the polling goroutine
	go f.pollLoop(ctx)

	return nil
}

// Stop stops the polling loop (safe to call multiple times)
func (f *Fetcher) Stop() {
	f.stopOnce.Do(func() {
		close(f.stopCh)
	})
}

// pollLoop runs the periodic fetch
func (f *Fetcher) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(f.config.Source.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-f.stopCh:
			return
		case <-ticker.C:
			if err := f.Fetch(ctx); err != nil {
				f.logger.Error("fetch failed", zap.Error(err))
			}
		}
	}
}

// Fetch fetches all configured sources and merges the results into the store.
// Sources are fetched in order; entries from later sources overwrite earlier ones.
func (f *Fetcher) Fetch(ctx context.Context) error {
	// Use the normalized sources list (populated by Validate); fall back to the
	// legacy single Source field when Validate has not been called (e.g., in tests).
	sources := f.config.Sources
	if len(sources) == 0 && f.config.Source.URL != "" {
		sources = []SourceConfig{f.config.Source}
	}
	if len(sources) == 0 {
		return fmt.Errorf("no registry sources configured")
	}

	// Accumulate entries across all sources; later sources overwrite earlier ones.
	entries := make(map[string]*VCTMEntry)

	for _, src := range sources {
		srcEntries, err := f.fetchFromSource(ctx, src)
		if err != nil {
			f.logger.Warn("failed to fetch from source",
				zap.String("url", src.URL),
				zap.Error(err))
			continue
		}
		for k, v := range srcEntries {
			entries[k] = v
		}
	}

	// Build a combined source URL for the store metadata.
	urls := make([]string, 0, len(sources))
	for _, src := range sources {
		urls = append(urls, src.URL)
	}

	f.store.Update(entries, strings.Join(urls, ", "))

	// Persist to disk
	if err := f.store.Save(); err != nil {
		f.logger.Error("failed to save cache", zap.Error(err))
		// Don't return error as the in-memory store is still valid
	}

	return nil
}

// fetchFromSource fetches entries from a single source URL, auto-detecting whether
// the endpoint returns the legacy vctm-registry.json format or the TS11 schemas.json format.
func (f *Fetcher) fetchFromSource(ctx context.Context, source SourceConfig) (map[string]*VCTMEntry, error) {
	f.logger.Info("fetching registry source", zap.String("url", source.URL))

	body, err := f.fetchRaw(ctx, source.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch source: %w", err)
	}

	// Auto-detect format based on top-level JSON keys.
	// TS11 /api/v1/schemas.json has a "schemas" array.
	// Legacy vctm-registry.json has a "credentials" array.
	var detector struct {
		Schemas     json.RawMessage `json:"schemas"`
		Credentials json.RawMessage `json:"credentials"`
	}
	if err := json.Unmarshal(body, &detector); err != nil {
		// Not valid JSON at the top level – fall through to legacy processing
		// which will surface the parse error with a clear message.
		f.logger.Debug("format auto-detection failed, falling back to legacy parser",
			zap.String("url", source.URL), zap.Error(err))
		return f.processLegacyResponse(ctx, source, body)
	}

	if detector.Schemas != nil {
		return f.processTS11Response(ctx, source, body)
	}
	return f.processLegacyResponse(ctx, source, body)
}

// processTS11Response processes a TS11-format /api/v1/schemas.json response,
// including following pagination via the "next" field.
func (f *Fetcher) processTS11Response(ctx context.Context, source SourceConfig, body []byte) (map[string]*VCTMEntry, error) {
	entries := make(map[string]*VCTMEntry)
	var fetchedCount, filteredCount, errorCount int

	currentBody := body
	for {
		var page TS11SchemasResponse
		if err := json.Unmarshal(currentBody, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TS11 schemas response: %w", err)
		}

		for _, schema := range page.Schemas {
			// Derive the VCT from the dc+sd-jwt schemaURI (the VCTM URL is the VCT).
			var vctmURI string
			for _, su := range schema.SchemaURIs {
				if su.FormatIdentifier == "dc+sd-jwt" {
					vctmURI = su.URI
					break
				}
			}
			// Fall back to the first schemaURI if no dc+sd-jwt entry is present.
			if vctmURI == "" && len(schema.SchemaURIs) > 0 {
				vctmURI = schema.SchemaURIs[0].URI
			}
			if vctmURI == "" {
				f.logger.Warn("TS11 schema has no schemaURIs, skipping", zap.String("id", schema.ID))
				errorCount++
				continue
			}

			// The VCT identifier is the VCTM document URI itself.
			vct := vctmURI

			if !f.config.Filter.Matches(vct) {
				filteredCount++
				f.logger.Debug("filtered out credential", zap.String("vct", vct))
				continue
			}

			entry, err := f.fetchTS11VCTM(ctx, schema, vct, vctmURI)
			if err != nil {
				errorCount++
				f.logger.Warn("failed to fetch TS11 VCTM",
					zap.String("vct", vct),
					zap.Error(err))
				continue
			}

			entries[vct] = entry
			fetchedCount++
		}

		// Follow pagination if a next-page URL is provided.
		if page.Next == "" {
			break
		}
		nextBody, err := f.fetchRaw(ctx, page.Next)
		if err != nil {
			f.logger.Warn("failed to fetch next page of schemas",
				zap.String("url", page.Next),
				zap.Error(err))
			break
		}
		currentBody = nextBody
	}

	f.logger.Info("TS11 fetch complete",
		zap.String("url", source.URL),
		zap.Int("fetched", fetchedCount),
		zap.Int("filtered", filteredCount),
		zap.Int("errors", errorCount))

	return entries, nil
}

// fetchTS11VCTM fetches the VCTM document for a TS11 schema and constructs a VCTMEntry.
// The name and description are extracted from the fetched VCTM document because the
// TS11 SchemaMeta does not carry a human-readable name.
func (f *Fetcher) fetchTS11VCTM(ctx context.Context, schema TS11SchemaMeta, vct, vctmURI string) (*VCTMEntry, error) {
	f.logger.Debug("fetching TS11 VCTM", zap.String("vct", vct), zap.String("url", vctmURI))

	body, err := f.fetchRaw(ctx, vctmURI)
	if err != nil {
		return nil, err
	}

	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON in VCTM response")
	}

	// Extract the human-readable name and description from the VCTM document itself.
	var vctmDoc struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	if err := json.Unmarshal(body, &vctmDoc); err != nil {
		f.logger.Debug("could not extract name/description from VCTM document",
			zap.String("vct", vct), zap.Error(err))
	}

	return &VCTMEntry{
		VCT:              vct,
		Name:             vctmDoc.Name,
		Description:      vctmDoc.Description,
		Metadata:         json.RawMessage(body),
		AttestationLoS:   schema.AttestationLoS,
		BindingType:      schema.BindingType,
		RulebookURI:      schema.RulebookURI,
		SupportedFormats: schema.SupportedFormats,
		FetchedAt:        time.Now(),
	}, nil
}

// processLegacyResponse processes a legacy vctm-registry.json response.
func (f *Fetcher) processLegacyResponse(ctx context.Context, source SourceConfig, body []byte) (map[string]*VCTMEntry, error) {
	var index RegistryIndex
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal legacy registry index: %w", err)
	}

	f.logger.Info("fetched legacy registry index",
		zap.String("url", source.URL),
		zap.Int("credentials", len(index.Credentials)),
		zap.String("build_time", index.BuildTime))

	entries := make(map[string]*VCTMEntry)
	var fetchedCount, filteredCount, errorCount int

	for _, cred := range index.Credentials {
		if !f.config.Filter.Matches(cred.VCT) {
			filteredCount++
			f.logger.Debug("filtered out credential", zap.String("vct", cred.VCT))
			continue
		}

		entry, err := f.fetchVCTM(ctx, &cred)
		if err != nil {
			errorCount++
			f.logger.Warn("failed to fetch VCTM",
				zap.String("vct", cred.VCT),
				zap.Error(err))
			continue
		}

		entries[cred.VCT] = entry
		fetchedCount++
	}

	f.logger.Info("legacy fetch complete",
		zap.String("url", source.URL),
		zap.Int("fetched", fetchedCount),
		zap.Int("filtered", filteredCount),
		zap.Int("errors", errorCount))

	return entries, nil
}

// fetchRaw performs a GET request and returns the response body.
// A 10 MB read limit is applied to prevent excessive memory use.
func (f *Fetcher) fetchRaw(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-wallet-registry/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10 MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// fetchIndex fetches and parses the legacy registry index.
// Kept for backward compatibility with existing tests.
func (f *Fetcher) fetchIndex(ctx context.Context) (*RegistryIndex, error) {
	body, err := f.fetchRaw(ctx, f.config.Source.URL)
	if err != nil {
		return nil, err
	}

	var index RegistryIndex
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	return &index, nil
}

// fetchVCTM fetches the VCTM document for a legacy credential entry.
func (f *Fetcher) fetchVCTM(ctx context.Context, cred *RegistryCredential) (*VCTMEntry, error) {
	// Find the VCTM format URL
	var vctmURL string
	if format, ok := cred.Formats["vctm"]; ok && format.URL != "" {
		vctmURL = format.URL
	} else if cred.Metadata.JSON != "" {
		vctmURL = cred.Metadata.JSON
	} else {
		// No VCTM URL available, create entry without metadata
		return &VCTMEntry{
			VCT:          cred.VCT,
			Name:         cred.Name,
			Description:  cred.Description,
			Organization: cred.Organization,
			Source: &VCTMSource{
				Repository: cred.Source.Repository,
				Branch:     cred.Source.Branch,
			},
			FetchedAt: time.Now(),
		}, nil
	}

	f.logger.Debug("fetching VCTM", zap.String("vct", cred.VCT), zap.String("url", vctmURL))

	body, err := f.fetchRaw(ctx, vctmURL)
	if err != nil {
		return nil, err
	}

	// Validate it's valid JSON
	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON in VCTM response")
	}

	return &VCTMEntry{
		VCT:          cred.VCT,
		Name:         cred.Name,
		Description:  cred.Description,
		Organization: cred.Organization,
		Metadata:     json.RawMessage(body),
		Source: &VCTMSource{
			Repository: cred.Source.Repository,
			Branch:     cred.Source.Branch,
		},
		FetchedAt: time.Now(),
	}, nil
}
