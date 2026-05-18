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

// RegistryResponse represents the /api/v1/registry.json response which includes
// ALL credentials (both TS11-compliant and non-TS11). Each entry has minimal
// metadata (id, version, supportedFormats, attestationLoS, bindingType) without
// schemaURIs. The TS11 detail endpoint /api/v1/schemas/{id}.json provides full
// metadata for TS11-compliant entries; for non-TS11 entries, VCTMs are resolved
// from the credential's known URLs in the registry.
type RegistryResponse struct {
	Total       int                 `json:"total"`
	Credentials []RegistryListEntry `json:"credentials"`
}

// RegistryListEntry is a single entry from /api/v1/registry.json.
type RegistryListEntry struct {
	ID               string   `json:"id"`
	Version          string   `json:"version"`
	SupportedFormats []string `json:"supportedFormats"`
	AttestationLoS   string   `json:"attestationLoS,omitempty"`
	BindingType      string   `json:"bindingType,omitempty"`
	// SchemaURIs may be present in future versions; handle gracefully.
	SchemaURIs []TS11SchemaURI `json:"schemaURIs,omitempty"`
}

// TS11SchemasResponse represents the paginated response from /api/v1/schemas.json.
// It supports two wire formats:
//   - Legacy: {"schemas": [...], "next": "...", "total": N, "page": N, "pageSize": N}
//   - Current: {"data": [...], "total": N, "limit": N, "offset": N}
type TS11SchemasResponse struct {
	// Schemas is the legacy key for the schema array.
	Schemas []TS11SchemaMeta `json:"schemas"`
	// Data is the current key for the schema array (paginated TS11 API).
	Data []TS11SchemaMeta `json:"data"`

	Total    int `json:"total,omitempty"`
	Page     int `json:"page,omitempty"`
	PageSize int `json:"pageSize,omitempty"`
	Limit    int `json:"limit,omitempty"`
	Offset   int `json:"offset,omitempty"`
	// Next is the URL of the next page; empty when there are no more pages (legacy pagination).
	Next string `json:"next,omitempty"`
}

// Entries returns whichever schema array is populated (Data takes precedence over Schemas).
func (r *TS11SchemasResponse) Entries() []TS11SchemaMeta {
	if len(r.Data) > 0 {
		return r.Data
	}
	return r.Schemas
}

// HasMorePages returns true if there are additional pages to fetch.
func (r *TS11SchemasResponse) HasMorePages() bool {
	// Legacy: "next" URL
	if r.Next != "" {
		return true
	}
	// Current: offset+limit < total
	if r.Limit > 0 && r.Offset+len(r.Entries()) < r.Total {
		return true
	}
	return false
}

// NextPageURL returns the URL for the next page. For legacy format it returns
// the "next" field directly. For the current format it constructs the URL by
// incrementing the offset. baseURL is the original source URL.
func (r *TS11SchemasResponse) NextPageURL(baseURL string) string {
	if r.Next != "" {
		return r.Next
	}
	// Build offset-based next URL
	nextOffset := r.Offset + len(r.Entries())
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	// Strip any existing offset param from baseURL
	clean := baseURL
	if idx := strings.Index(clean, "offset="); idx > 0 {
		// Remove offset=N (and preceding & or ?)
		end := strings.IndexByte(clean[idx:], '&')
		if end == -1 {
			clean = clean[:idx-1] // remove the preceding ? or &
		} else {
			clean = clean[:idx] + clean[idx+end+1:]
		}
		if !strings.Contains(clean, "?") {
			sep = "?"
		} else {
			sep = "&"
		}
	}
	return fmt.Sprintf("%s%soffset=%d", clean, sep, nextOffset)
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
// If all sources fail, the store is left unchanged and an error is returned.
func (f *Fetcher) Fetch(ctx context.Context) error {
	// Use the normalized sources list (populated by Validate); fall back to the
	// legacy single Source field when Validate has not been called (e.g., in tests).
	sources := f.config.Sources
	if len(sources) == 0 && f.config.Source.URL != "" {
		sources = []RemoteSourceConfig{{URL: f.config.Source.URL, Timeout: f.config.Source.Timeout}}
	}
	if len(sources) == 0 {
		return fmt.Errorf("no registry sources configured")
	}

	// Accumulate entries across all sources; later sources overwrite earlier ones.
	entries := make(map[string]*VCTMEntry)
	var successCount int

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
		successCount++
	}

	if successCount == 0 {
		return fmt.Errorf("all %d registry source(s) failed; store not updated", len(sources))
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

// fetchFromSource fetches entries from a single source, using the configured Mode to
// determine which endpoint to hit. Format auto-detection is applied to the response.
// If source.Timeout is non-zero it is applied as a context deadline for the entire
// source fetch (index + all VCTM documents).
func (f *Fetcher) fetchFromSource(ctx context.Context, source RemoteSourceConfig) (map[string]*VCTMEntry, error) {
	if source.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, source.Timeout)
		defer cancel()
	}

	fetchURL := source.resolveURL()
	f.logger.Info("fetching registry source", zap.String("url", fetchURL), zap.String("mode", string(source.Mode)))

	body, err := f.fetchRaw(ctx, fetchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch source: %w", err)
	}

	// Auto-detect format based on top-level JSON keys.
	// Current TS11: {"data": [...], "total": N, "limit": N, "offset": N}
	// Legacy TS11:  {"schemas": [...], "next": "...", ...}
	// Registry:     {"credentials": [...], "total": N} (all credentials, minimal metadata)
	// Legacy index: {"credentials": [...], "name": ..., ...} (vctm-registry.json)
	var detector struct {
		Data        json.RawMessage `json:"data"`
		Schemas     json.RawMessage `json:"schemas"`
		Credentials json.RawMessage `json:"credentials"`
		Name        string          `json:"name"`  // present in legacy vctm-registry.json
		Total       *int            `json:"total"` // present in new registry.json
	}
	if err := json.Unmarshal(body, &detector); err != nil {
		f.logger.Debug("format auto-detection failed, falling back to legacy parser",
			zap.String("url", fetchURL), zap.Error(err))
		return f.processLegacyResponse(ctx, source, body)
	}

	if detector.Data != nil || detector.Schemas != nil {
		return f.processTS11Response(ctx, source, body)
	}
	if detector.Credentials != nil && detector.Total != nil && detector.Name == "" {
		// Registry format: {"credentials": [...], "total": N} without legacy fields
		return f.processRegistryResponse(ctx, source, body)
	}
	return f.processLegacyResponse(ctx, source, body)
}

// resolveURL determines the actual fetch URL based on the Mode setting.
// If the URL already points to a specific JSON file, it is used as-is.
// Otherwise, the appropriate endpoint path is appended based on Mode.
func (s *RemoteSourceConfig) resolveURL() string {
	u := s.URL
	// If the URL already ends with a known endpoint file, use it directly.
	if strings.HasSuffix(u, ".json") {
		return u
	}
	// Strip trailing slash for consistent joining.
	u = strings.TrimRight(u, "/")
	switch s.Mode {
	case APIModeRegistry:
		return u + "/api/v1/registry.json"
	default:
		return u + "/api/v1/schemas.json"
	}
}

// processTS11Response processes a TS11-format /api/v1/schemas.json response,
// including following pagination via offset/limit or legacy "next" field.
func (f *Fetcher) processTS11Response(ctx context.Context, source RemoteSourceConfig, body []byte) (map[string]*VCTMEntry, error) {
	entries := make(map[string]*VCTMEntry)
	var fetchedCount, filteredCount, errorCount int

	// Use the resolved endpoint URL for pagination (not the raw base URL)
	resolvedURL := source.resolveURL()
	currentBody := body
	for {
		var page TS11SchemasResponse
		if err := json.Unmarshal(currentBody, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TS11 schemas response: %w", err)
		}

		for _, schema := range page.Entries() {
			// Determine which schemaURI to use as the VCTM fetch URL.
			// Prefer the dc+sd-jwt entry; fall back to the first URI.
			var vctmURI string
			for _, su := range schema.SchemaURIs {
				if su.FormatIdentifier == "dc+sd-jwt" {
					vctmURI = su.URI
					break
				}
			}
			if vctmURI == "" && len(schema.SchemaURIs) > 0 {
				vctmURI = schema.SchemaURIs[0].URI
			}
			if vctmURI == "" {
				f.logger.Warn("TS11 schema has no schemaURIs, skipping", zap.String("id", schema.ID))
				errorCount++
				continue
			}

			// NOTE: we do not pre-derive the VCT from the schemaURI.
			// The authoritative VCT identifier lives inside the fetched VCTM
			// document itself ("vct" field) and may be a URN (e.g.
			// "urn:eudi:diploma:1") rather than the HTTP URL of the document.
			// We must fetch first, then apply the filter on the real VCT.
			entry, err := f.fetchTS11VCTM(ctx, schema, vctmURI)
			if err != nil {
				errorCount++
				f.logger.Warn("failed to fetch TS11 VCTM",
					zap.String("schema_id", schema.ID),
					zap.String("url", vctmURI),
					zap.Error(err))
				continue
			}

			if !f.config.Filter.Matches(entry.VCT) {
				filteredCount++
				f.logger.Debug("filtered out credential", zap.String("vct", entry.VCT))
				continue
			}

			entries[entry.VCT] = entry
			fetchedCount++
		}

		// Follow pagination if more pages are available.
		if !page.HasMorePages() {
			break
		}
		nextURL := page.NextPageURL(resolvedURL)
		nextBody, err := f.fetchRaw(ctx, nextURL)
		if err != nil {
			f.logger.Warn("failed to fetch next page of schemas",
				zap.String("url", nextURL),
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
// The authoritative VCT identifier, name, and description are all extracted from the
// fetched VCTM document.  The VCT field in the document takes precedence over the
// schemaURI used to fetch it, because the VCT may be a URN (e.g. "urn:eudi:diploma:1")
// rather than an HTTP URL.  If the document does not contain a "vct" field, vctmURI is
// used as the fallback identifier.
func (f *Fetcher) fetchTS11VCTM(ctx context.Context, schema TS11SchemaMeta, vctmURI string) (*VCTMEntry, error) {
	f.logger.Debug("fetching TS11 VCTM", zap.String("url", vctmURI))

	body, err := f.fetchRaw(ctx, vctmURI)
	if err != nil {
		return nil, err
	}

	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid JSON in VCTM response")
	}

	// Extract the authoritative VCT identifier, name, and description from the
	// VCTM document itself.
	var vctmDoc struct {
		VCT         string `json:"vct"`
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
	}
	if err := json.Unmarshal(body, &vctmDoc); err != nil {
		f.logger.Debug("could not extract fields from VCTM document",
			zap.String("url", vctmURI), zap.Error(err))
	}

	// Fall back to the schemaURI when the document does not carry a "vct" field.
	vct := vctmDoc.VCT
	if vct == "" {
		f.logger.Debug("VCTM document has no 'vct' field, falling back to schemaURI",
			zap.String("url", vctmURI))
		vct = vctmURI
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
func (f *Fetcher) processLegacyResponse(ctx context.Context, source RemoteSourceConfig, body []byte) (map[string]*VCTMEntry, error) {
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

// processRegistryResponse processes a /api/v1/registry.json response which
// contains ALL credentials (TS11 and non-TS11) with minimal metadata.
// For each entry, it attempts to fetch the full TS11 detail from
// /api/v1/schemas/{id}.json. If that fails (non-TS11 entry), a stub entry
// is created with the available metadata.
func (f *Fetcher) processRegistryResponse(ctx context.Context, source RemoteSourceConfig, body []byte) (map[string]*VCTMEntry, error) {
	var resp RegistryResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal registry response: %w", err)
	}

	f.logger.Info("fetched registry index",
		zap.String("url", source.resolveURL()),
		zap.Int("credentials", len(resp.Credentials)))

	entries := make(map[string]*VCTMEntry)
	var fetchedCount, detailCount, stubCount, filteredCount, errorCount int

	// Derive the base URL for fetching individual schema details.
	baseURL := strings.TrimRight(source.URL, "/")
	if strings.HasSuffix(baseURL, ".json") {
		// Strip the file name to get the base path
		if idx := strings.LastIndex(baseURL, "/"); idx > 0 {
			baseURL = baseURL[:idx]
		}
	}
	// Remove /api/v1/registry.json path if present to get the registry root
	baseURL = strings.TrimSuffix(baseURL, "/api/v1")

	for _, cred := range resp.Credentials {
		// Try to fetch TS11 detail for this credential (includes schemaURIs).
		detailURL := baseURL + "/api/v1/schemas/" + cred.ID + ".json"
		detailBody, err := f.fetchRaw(ctx, detailURL)
		if err == nil {
			// Successfully fetched detail — process as TS11 schema with VCTM fetch.
			var schema TS11SchemaMeta
			if jsonErr := json.Unmarshal(detailBody, &schema); jsonErr == nil && len(schema.SchemaURIs) > 0 {
				// Pick the VCTM URI
				var vctmURI string
				for _, su := range schema.SchemaURIs {
					if su.FormatIdentifier == "dc+sd-jwt" {
						vctmURI = su.URI
						break
					}
				}
				if vctmURI == "" {
					vctmURI = schema.SchemaURIs[0].URI
				}

				entry, fetchErr := f.fetchTS11VCTM(ctx, schema, vctmURI)
				if fetchErr == nil {
					if !f.config.Filter.Matches(entry.VCT) {
						filteredCount++
						continue
					}
					entries[entry.VCT] = entry
					fetchedCount++
					detailCount++
					continue
				}
				f.logger.Debug("failed to fetch VCTM from detail", zap.String("id", cred.ID), zap.Error(fetchErr))
			}
		}

		// Detail not available (non-TS11) or VCTM fetch failed.
		// Create a stub entry with the metadata we have from the registry list.
		// Use the schema ID as a placeholder VCT (the real VCT is unknown without VCTM).
		vct := cred.ID
		if !f.config.Filter.Matches(vct) {
			filteredCount++
			continue
		}

		entries[vct] = &VCTMEntry{
			VCT:              vct,
			AttestationLoS:   cred.AttestationLoS,
			BindingType:      cred.BindingType,
			SupportedFormats: cred.SupportedFormats,
			FetchedAt:        time.Now(),
		}
		fetchedCount++
		stubCount++
	}

	f.logger.Info("registry fetch complete",
		zap.String("url", source.resolveURL()),
		zap.Int("fetched", fetchedCount),
		zap.Int("detail", detailCount),
		zap.Int("stubs", stubCount),
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
