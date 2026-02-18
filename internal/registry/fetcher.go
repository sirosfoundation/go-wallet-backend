package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// RegistryIndex represents the upstream vctm-registry.json structure
type RegistryIndex struct {
	Schema      string               `json:"$schema"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	URL         string               `json:"url"`
	Version     string               `json:"version"`
	Credentials []RegistryCredential `json:"credentials"`
	BuildTime   string               `json:"buildTime"`
}

// RegistryCredential represents a credential entry in the registry index
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

// Fetcher handles fetching VCTMs from the upstream registry
type Fetcher struct {
	config *Config
	store  *Store
	client *http.Client
	logger *zap.Logger

	// stopCh signals the polling goroutine to stop
	stopCh chan struct{}
}

// NewFetcher creates a new registry fetcher
func NewFetcher(config *Config, store *Store, logger *zap.Logger) *Fetcher {
	return &Fetcher{
		config: config,
		store:  store,
		client: &http.Client{
			Timeout: config.Source.Timeout,
		},
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

// Stop stops the polling loop
func (f *Fetcher) Stop() {
	close(f.stopCh)
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

// Fetch fetches the registry index and all VCTM files
func (f *Fetcher) Fetch(ctx context.Context) error {
	f.logger.Info("fetching registry index", zap.String("url", f.config.Source.URL))

	// Fetch the registry index
	index, err := f.fetchIndex(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch registry index: %w", err)
	}

	f.logger.Info("fetched registry index",
		zap.Int("credentials", len(index.Credentials)),
		zap.String("build_time", index.BuildTime))

	// Fetch individual VCTMs and build entries map
	entries := make(map[string]*VCTMEntry)
	var fetchedCount, filteredCount, errorCount int

	for _, cred := range index.Credentials {
		// Apply filter
		if !f.config.Filter.Matches(cred.VCT) {
			filteredCount++
			f.logger.Debug("filtered out credential", zap.String("vct", cred.VCT))
			continue
		}

		// Fetch the VCTM
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

	f.logger.Info("fetch complete",
		zap.Int("fetched", fetchedCount),
		zap.Int("filtered", filteredCount),
		zap.Int("errors", errorCount))

	// Update the store
	f.store.Update(entries, f.config.Source.URL)

	// Persist to disk
	if err := f.store.Save(); err != nil {
		f.logger.Error("failed to save cache", zap.Error(err))
		// Don't return error as the in-memory store is still valid
	}

	return nil
}

// fetchIndex fetches and parses the registry index
func (f *Fetcher) fetchIndex(ctx context.Context) (*RegistryIndex, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.config.Source.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-wallet-registry/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var index RegistryIndex
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, fmt.Errorf("failed to unmarshal index: %w", err)
	}

	return &index, nil
}

// fetchVCTM fetches the VCTM document for a credential
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vctmURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "go-wallet-registry/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
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
