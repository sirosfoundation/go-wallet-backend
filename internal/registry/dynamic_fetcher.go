package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DynamicFetcher fetches VCTMs on-demand from arbitrary URLs
type DynamicFetcher struct {
	client *http.Client
	config *DynamicCacheConfig
	logger *zap.Logger
}

// NewDynamicFetcher creates a new dynamic fetcher
func NewDynamicFetcher(config *DynamicCacheConfig, logger *zap.Logger) *DynamicFetcher {
	return &DynamicFetcher{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		config: config,
		logger: logger,
	}
}

// FetchResult contains the result of a dynamic fetch
type FetchResult struct {
	// Entry is the fetched VCTM entry (nil if not modified)
	Entry *VCTMEntry

	// NotModified is true if the server returned 304 Not Modified
	NotModified bool
}

// Fetch fetches a VCTM from a URL
// If existingEntry is provided, conditional request headers (If-None-Match, If-Modified-Since) are used
func (f *DynamicFetcher) Fetch(ctx context.Context, vctURL string, existingEntry *VCTMEntry) (*FetchResult, error) {
	if !f.config.Enabled {
		return nil, fmt.Errorf("dynamic fetching is disabled")
	}

	// Validate the URL
	parsedURL, err := url.Parse(vctURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTPS
	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS URLs are allowed")
	}

	// Check if host is allowed
	if !f.config.IsHostAllowed(parsedURL.Host) {
		return nil, fmt.Errorf("host %q is not in the allowed hosts list", parsedURL.Host)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vctURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add standard headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SIROS-Registry/1.0")

	// Add conditional request headers if we have an existing entry
	if existingEntry != nil {
		if existingEntry.ETag != "" {
			req.Header.Set("If-None-Match", existingEntry.ETag)
		}
		if existingEntry.LastModified != "" {
			req.Header.Set("If-Modified-Since", existingEntry.LastModified)
		}
	}

	f.logger.Debug("fetching VCTM",
		zap.String("url", vctURL),
		zap.Bool("conditional", existingEntry != nil),
	)

	// Execute request
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		f.logger.Debug("VCTM not modified", zap.String("url", vctURL))
		return &FetchResult{NotModified: true}, nil
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Validate JSON
	var metadata map[string]interface{}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}

	// Calculate cache TTL
	expiresAt := f.calculateExpiresAt(resp.Header)

	// Build entry
	entry := &VCTMEntry{
		VCT:          vctURL,
		Name:         extractStringField(metadata, "name", vctURL),
		Description:  extractStringField(metadata, "description", ""),
		Organization: extractStringField(metadata, "organization", ""),
		Metadata:     body,
		FetchedAt:    time.Now(),
		IsDynamic:    true,
		ExpiresAt:    expiresAt,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}

	f.logger.Debug("fetched VCTM",
		zap.String("url", vctURL),
		zap.String("name", entry.Name),
		zap.Time("expires_at", entry.ExpiresAt),
	)

	return &FetchResult{Entry: entry}, nil
}

// calculateExpiresAt determines when the cached entry should expire
// based on HTTP cache headers and configuration constraints
func (f *DynamicFetcher) calculateExpiresAt(headers http.Header) time.Time {
	now := time.Now()
	ttl := f.config.DefaultTTL

	// Try to parse Cache-Control max-age
	if cacheControl := headers.Get("Cache-Control"); cacheControl != "" {
		if maxAge := parseCacheControlMaxAge(cacheControl); maxAge > 0 {
			ttl = maxAge
		}
	} else if expiresHeader := headers.Get("Expires"); expiresHeader != "" {
		// Fall back to Expires header
		if expires, err := http.ParseTime(expiresHeader); err == nil {
			ttl = time.Until(expires)
		}
	}

	// Apply TTL constraints
	if ttl < f.config.MinTTL {
		ttl = f.config.MinTTL
	}
	if ttl > f.config.MaxTTL {
		ttl = f.config.MaxTTL
	}

	return now.Add(ttl)
}

// parseCacheControlMaxAge extracts the max-age value from a Cache-Control header
func parseCacheControlMaxAge(cacheControl string) time.Duration {
	// Look for max-age directive
	for _, directive := range strings.Split(cacheControl, ",") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "max-age=") {
			value := strings.TrimPrefix(directive, "max-age=")
			if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 0
}

// extractStringField extracts a string field from a map with a default value
func extractStringField(m map[string]interface{}, key, defaultValue string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultValue
}

// IsURL checks if a string looks like a URL that could be fetched
func IsURL(s string) bool {
	if !strings.HasPrefix(s, "https://") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Host != ""
}
