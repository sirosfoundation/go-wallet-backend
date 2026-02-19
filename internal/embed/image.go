// Package embed provides utilities for embedding external resources as data URIs.
// It is designed to be used by multiple services (VCTM registry, issuer metadata, etc.)
// to eliminate recursive fetching by clients.
package embed

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Config contains configuration for image embedding
type Config struct {
	// Enabled controls whether image embedding is active
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// MaxImageSize is the maximum size in bytes for images to embed
	// Images larger than this will be left as URLs
	MaxImageSize int64 `yaml:"max_image_size" envconfig:"MAX_IMAGE_SIZE"`

	// Timeout for fetching individual images
	Timeout time.Duration `yaml:"timeout" envconfig:"TIMEOUT"`

	// ConcurrentFetches is the maximum number of concurrent image fetches
	ConcurrentFetches int `yaml:"concurrent_fetches" envconfig:"CONCURRENT_FETCHES"`
}

// DefaultConfig returns default configuration for image embedding
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		MaxImageSize:      1024 * 1024, // 1MB default
		Timeout:           10 * time.Second,
		ConcurrentFetches: 5,
	}
}

// URLExtractor is a function that extracts image URLs from a JSON document.
// Different document types (VCTM, issuer metadata) may have different structures.
type URLExtractor func(doc map[string]interface{}) []string

// URLReplacer is a function that replaces URLs with data URIs in a JSON document.
// It should modify the document in place.
type URLReplacer func(doc map[string]interface{}, dataURLs map[string]string)

// ImageEmbedder handles embedding of image URLs as data URIs in JSON documents
type ImageEmbedder struct {
	config    *Config
	client    *http.Client
	logger    *zap.Logger
	extractor URLExtractor
	replacer  URLReplacer
}

// Option configures an ImageEmbedder
type Option func(*ImageEmbedder)

// WithExtractor sets a custom URL extractor function
func WithExtractor(extractor URLExtractor) Option {
	return func(e *ImageEmbedder) {
		e.extractor = extractor
	}
}

// WithReplacer sets a custom URL replacer function
func WithReplacer(replacer URLReplacer) Option {
	return func(e *ImageEmbedder) {
		e.replacer = replacer
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) Option {
	return func(e *ImageEmbedder) {
		e.client = client
	}
}

// NewImageEmbedder creates a new image embedder with the given configuration.
// By default, it uses extractors and replacers suitable for VCTM documents.
// Use WithExtractor and WithReplacer options for other document types.
func NewImageEmbedder(config *Config, logger *zap.Logger, opts ...Option) *ImageEmbedder {
	if config == nil {
		defaultConfig := DefaultConfig()
		config = &defaultConfig
	}

	e := &ImageEmbedder{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		logger:    logger,
		extractor: DefaultURLExtractor,
		replacer:  DefaultURLReplacer,
	}

	for _, opt := range opts {
		opt(e)
	}

	return e
}

// EmbedImages processes a JSON document and embeds all image URLs as data URIs.
// Returns the modified JSON document.
func (e *ImageEmbedder) EmbedImages(ctx context.Context, data []byte) ([]byte, error) {
	if !e.config.Enabled {
		return data, nil
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return data, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Collect all image URLs using the configured extractor
	urls := e.extractor(doc)
	if len(urls) == 0 {
		return data, nil
	}

	// Fetch all images concurrently
	dataURLs := e.fetchImages(ctx, urls)

	// Replace URLs with data URIs using the configured replacer
	e.replacer(doc, dataURLs)

	// Serialize back to JSON
	result, err := json.Marshal(doc)
	if err != nil {
		return data, fmt.Errorf("failed to serialize JSON: %w", err)
	}

	return result, nil
}

// DefaultURLExtractor extracts image URLs from documents following OpenID4VCI patterns.
// It looks for "uri" fields in logo, background_image, and svg_templates structures.
// This works for both VCTM documents and OpenID4VCI issuer/credential metadata.
func DefaultURLExtractor(doc map[string]interface{}) []string {
	var urls []string
	seen := make(map[string]bool)

	var collect func(v interface{})
	collect = func(v interface{}) {
		switch val := v.(type) {
		case map[string]interface{}:
			// Check for "uri" field in logo, background_image, svg_templates, etc.
			if uri, ok := val["uri"].(string); ok && IsImageURL(uri) && !seen[uri] {
				urls = append(urls, uri)
				seen[uri] = true
			}
			// Recurse into all fields
			for _, child := range val {
				collect(child)
			}
		case []interface{}:
			for _, item := range val {
				collect(item)
			}
		}
	}

	collect(doc)
	return urls
}

// DefaultURLReplacer replaces image URLs with data URIs in documents.
// It looks for "uri" fields and replaces them with the corresponding data URI.
func DefaultURLReplacer(doc map[string]interface{}, dataURLs map[string]string) {
	var replace func(v interface{})
	replace = func(v interface{}) {
		switch val := v.(type) {
		case map[string]interface{}:
			// Check for "uri" field
			if uri, ok := val["uri"].(string); ok {
				if dataURL, found := dataURLs[uri]; found {
					val["uri"] = dataURL
					// Remove integrity hash since data URIs are self-contained
					delete(val, "uri#integrity")
				}
			}
			// Recurse into all fields
			for _, child := range val {
				replace(child)
			}
		case []interface{}:
			for _, item := range val {
				replace(item)
			}
		}
	}

	replace(doc)
}

// fetchImages fetches all images concurrently and returns a map of URL to data URI
func (e *ImageEmbedder) fetchImages(ctx context.Context, urls []string) map[string]string {
	result := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore for limiting concurrent fetches; ensure capacity is at least 1
	maxConcurrent := e.config.ConcurrentFetches
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	sem := make(chan struct{}, maxConcurrent)

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			dataURL, err := e.fetchAndEncode(ctx, url)
			if err != nil {
				e.logger.Debug("failed to fetch image",
					zap.String("url", url),
					zap.Error(err),
				)
				return
			}

			mu.Lock()
			result[url] = dataURL
			mu.Unlock()

			e.logger.Debug("embedded image",
				zap.String("url", url),
				zap.Int("size", len(dataURL)),
			)
		}(url)
	}

	wg.Wait()
	return result
}

// fetchAndEncode fetches a single image and returns it as a data URI
func (e *ImageEmbedder) fetchAndEncode(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Check content length if available
	if resp.ContentLength > e.config.MaxImageSize {
		return "", fmt.Errorf("image too large: %d bytes", resp.ContentLength)
	}

	// Read the image data with a size limit
	limitedReader := io.LimitReader(resp.Body, e.config.MaxImageSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("failed to read: %w", err)
	}

	if int64(len(data)) > e.config.MaxImageSize {
		return "", fmt.Errorf("image too large: %d bytes", len(data))
	}

	// Determine MIME type
	mimeType := resp.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = DetectMimeType(url, data)
	}
	// Clean up MIME type (remove charset etc.)
	if idx := strings.Index(mimeType, ";"); idx > 0 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}

	// Validate content-type is an image to prevent embedding non-image content
	if !strings.HasPrefix(mimeType, "image/") && mimeType != "application/octet-stream" {
		return "", fmt.Errorf("invalid content-type: %s (expected image/*)", mimeType)
	}

	// Encode as data URI
	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, encoded), nil
}

// IsImageURL checks if a URL points to an image resource
func IsImageURL(url string) bool {
	// Skip if already a data URI
	if strings.HasPrefix(url, "data:") {
		return false
	}

	// Must be HTTPS URL (HTTP is not allowed for security reasons)
	if !strings.HasPrefix(url, "https://") {
		return false
	}

	// Check common image extensions
	lower := strings.ToLower(url)
	// Remove query string for extension check
	if idx := strings.Index(lower, "?"); idx > 0 {
		lower = lower[:idx]
	}

	imageExtensions := []string{".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp"}
	for _, ext := range imageExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}

	// Accept any HTTP URL that might serve an image
	// The actual MIME type will be verified during fetch
	return true
}

// DetectMimeType attempts to detect the MIME type of image data
func DetectMimeType(url string, data []byte) string {
	// First, check file extension
	lower := strings.ToLower(url)
	if idx := strings.Index(lower, "?"); idx > 0 {
		lower = lower[:idx]
	}

	switch {
	case strings.HasSuffix(lower, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(lower, ".png"):
		return "image/png"
	case strings.HasSuffix(lower, ".jpg"), strings.HasSuffix(lower, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(lower, ".gif"):
		return "image/gif"
	case strings.HasSuffix(lower, ".webp"):
		return "image/webp"
	case strings.HasSuffix(lower, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(lower, ".bmp"):
		return "image/bmp"
	}

	// Fall back to content detection by magic bytes
	if len(data) >= 4 {
		// PNG signature
		if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
			return "image/png"
		}
		// JPEG signature
		if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
			return "image/jpeg"
		}
		// GIF signature
		if data[0] == 0x47 && data[1] == 0x49 && data[2] == 0x46 {
			return "image/gif"
		}
		// WebP signature
		if len(data) >= 12 && data[0] == 'R' && data[1] == 'I' && data[2] == 'F' && data[3] == 'F' &&
			data[8] == 'W' && data[9] == 'E' && data[10] == 'B' && data[11] == 'P' {
			return "image/webp"
		}
		// SVG (check for XML/SVG start)
		if data[0] == '<' {
			str := string(data[:min(len(data), 256)])
			if strings.Contains(str, "<svg") || strings.Contains(str, "<?xml") {
				return "image/svg+xml"
			}
		}
	}

	// Default to octet-stream
	return "application/octet-stream"
}
