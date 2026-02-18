package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// VCTMEntry represents a single VCTM (Verifiable Credential Type Metadata) entry
type VCTMEntry struct {
	// VCT is the unique identifier (URL) for this credential type
	VCT string `json:"vct"`

	// Name is the human-readable name of the credential type
	Name string `json:"name"`

	// Description is a human-readable description
	Description string `json:"description,omitempty"`

	// Organization that maintains this credential type
	Organization string `json:"organization,omitempty"`

	// Metadata is the full VCTM document content (the actual type metadata)
	Metadata json.RawMessage `json:"metadata,omitempty"`

	// Source information
	Source *VCTMSource `json:"source,omitempty"`

	// FetchedAt is when this entry was last fetched
	FetchedAt time.Time `json:"fetched_at"`

	// IsDynamic indicates if this entry was fetched on-demand (not from registry)
	IsDynamic bool `json:"is_dynamic,omitempty"`

	// ExpiresAt is when this entry should be considered stale
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// ETag is the HTTP ETag header value for conditional requests
	ETag string `json:"etag,omitempty"`

	// LastModified is the HTTP Last-Modified header value for conditional requests
	LastModified string `json:"last_modified,omitempty"`
}

// IsExpired returns true if this entry has expired based on its ExpiresAt time
func (e *VCTMEntry) IsExpired() bool {
	if e.ExpiresAt.IsZero() {
		return false // Static entries don't expire
	}
	return time.Now().After(e.ExpiresAt)
}

// VCTMSource contains source information for a VCTM entry
type VCTMSource struct {
	Repository string `json:"repository,omitempty"`
	Branch     string `json:"branch,omitempty"`
}

// CacheData represents the structure of the disk cache file
type CacheData struct {
	// Version of the cache format
	Version string `json:"version"`

	// LastUpdated is when the cache was last updated
	LastUpdated time.Time `json:"last_updated"`

	// SourceURL is the upstream registry URL this cache was built from
	SourceURL string `json:"source_url"`

	// Entries is the map of VCT ID to VCTM entry
	Entries map[string]*VCTMEntry `json:"entries"`
}

// Store provides thread-safe storage for VCTM entries with disk persistence
type Store struct {
	mu sync.RWMutex

	// entries maps VCT ID to VCTM entry
	entries map[string]*VCTMEntry

	// cachePath is the path to the disk cache file
	cachePath string

	// lastUpdated is when the store was last updated
	lastUpdated time.Time

	// sourceURL is the upstream registry URL
	sourceURL string
}

// NewStore creates a new VCTM store
func NewStore(cachePath string) *Store {
	return &Store{
		entries:   make(map[string]*VCTMEntry),
		cachePath: cachePath,
	}
}

// Load loads the store from the disk cache
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.cachePath)
	if os.IsNotExist(err) {
		// No cache file exists yet, that's fine
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read cache file: %w", err)
	}

	var cache CacheData
	if err := json.Unmarshal(data, &cache); err != nil {
		return fmt.Errorf("failed to unmarshal cache: %w", err)
	}

	// Check cache version
	if cache.Version != "1" {
		return fmt.Errorf("unsupported cache version: %s", cache.Version)
	}

	s.entries = cache.Entries
	if s.entries == nil {
		s.entries = make(map[string]*VCTMEntry)
	}
	s.lastUpdated = cache.LastUpdated
	s.sourceURL = cache.SourceURL

	return nil
}

// Save persists the store to the disk cache
func (s *Store) Save() error {
	s.mu.RLock()
	cache := CacheData{
		Version:     "1",
		LastUpdated: s.lastUpdated,
		SourceURL:   s.sourceURL,
		Entries:     s.entries,
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %w", err)
	}

	// Ensure the directory exists
	dir := filepath.Dir(s.cachePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Write atomically using a temp file
	tmpPath := s.cachePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp cache file: %w", err)
	}

	if err := os.Rename(tmpPath, s.cachePath); err != nil {
		_ = os.Remove(tmpPath) // Clean up on failure
		return fmt.Errorf("failed to rename cache file: %w", err)
	}

	return nil
}

// Get retrieves a VCTM entry by VCT ID
func (s *Store) Get(vctID string) (*VCTMEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.entries[vctID]
	return entry, ok
}

// Put adds or updates a VCTM entry
func (s *Store) Put(entry *VCTMEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[entry.VCT] = entry
}

// Set adds or updates a VCTM entry by explicit key
func (s *Store) Set(vctID string, entry *VCTMEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[vctID] = entry
}

// Delete removes a VCTM entry by VCT ID
func (s *Store) Delete(vctID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, vctID)
}

// Update atomically replaces all entries and updates metadata
func (s *Store) Update(entries map[string]*VCTMEntry, sourceURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries = entries
	s.sourceURL = sourceURL
	s.lastUpdated = time.Now()
}

// List returns all VCTM entries
func (s *Store) List() []*VCTMEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*VCTMEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		result = append(result, entry)
	}
	return result
}

// Count returns the number of entries in the store
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.entries)
}

// LastUpdated returns when the store was last updated
func (s *Store) LastUpdated() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.lastUpdated
}

// SourceURL returns the upstream registry URL
func (s *Store) SourceURL() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.sourceURL
}

// VCTIDs returns all VCT IDs in the store
func (s *Store) VCTIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.entries))
	for id := range s.entries {
		ids = append(ids, id)
	}
	return ids
}
