package registry

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

// ImageEmbedConfig contains configuration for image embedding
type ImageEmbedConfig struct {
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

// DefaultImageEmbedConfig returns default configuration for image embedding
func DefaultImageEmbedConfig() ImageEmbedConfig {
	return ImageEmbedConfig{
		Enabled:           true,
		MaxImageSize:      1024 * 1024, // 1MB default
		Timeout:           10 * time.Second,
		ConcurrentFetches: 5,
	}
}

// ImageEmbedder handles embedding of image URLs as data URIs in VCTM documents
type ImageEmbedder struct {
	config *ImageEmbedConfig
	client *http.Client
	logger *zap.Logger
}

// NewImageEmbedder creates a new image embedder
func NewImageEmbedder(config *ImageEmbedConfig, logger *zap.Logger) *ImageEmbedder {
	if config == nil {
		defaultConfig := DefaultImageEmbedConfig()
		config = &defaultConfig
	}
	return &ImageEmbedder{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		logger: logger,
	}
}

// EmbedImages processes a VCTM JSON document and embeds all image URLs as data URIs
// Returns the modified JSON document
func (e *ImageEmbedder) EmbedImages(ctx context.Context, vctmData []byte) ([]byte, error) {
	if !e.config.Enabled {
		return vctmData, nil
	}

	var vctm map[string]interface{}
	if err := json.Unmarshal(vctmData, &vctm); err != nil {
		return vctmData, fmt.Errorf("failed to parse VCTM: %w", err)
	}

	// Collect all image URLs
	urls := e.collectImageURLs(vctm)
	if len(urls) == 0 {
		return vctmData, nil
	}

	// Fetch all images concurrently
	dataURLs := e.fetchImages(ctx, urls)

	// Replace URLs with data URIs in the document
	e.replaceURLs(vctm, dataURLs)

	// Serialize back to JSON
	result, err := json.Marshal(vctm)
	if err != nil {
		return vctmData, fmt.Errorf("failed to serialize VCTM: %w", err)
	}

	return result, nil
}

// collectImageURLs finds all image URLs in a VCTM document
func (e *ImageEmbedder) collectImageURLs(vctm map[string]interface{}) []string {
	var urls []string
	seen := make(map[string]bool)

	var collect func(v interface{})
	collect = func(v interface{}) {
		switch val := v.(type) {
		case map[string]interface{}:
			// Check for "uri" field in logo, background_image, or svg_templates
			if uri, ok := val["uri"].(string); ok && isImageURL(uri) && !seen[uri] {
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

	collect(vctm)
	return urls
}

// fetchImages fetches all images concurrently and returns a map of URL to data URI
func (e *ImageEmbedder) fetchImages(ctx context.Context, urls []string) map[string]string {
	result := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Semaphore for limiting concurrent fetches
	sem := make(chan struct{}, e.config.ConcurrentFetches)

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
		mimeType = detectMimeType(url, data)
	}
	// Clean up MIME type (remove charset etc.)
	if idx := strings.Index(mimeType, ";"); idx > 0 {
		mimeType = strings.TrimSpace(mimeType[:idx])
	}

	// Encode as data URI
	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, encoded), nil
}

// replaceURLs replaces image URLs with data URIs in the VCTM document
func (e *ImageEmbedder) replaceURLs(vctm map[string]interface{}, dataURLs map[string]string) {
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

	replace(vctm)
}

// isImageURL checks if a URL points to an image resource
func isImageURL(url string) bool {
	// Skip if already a data URI
	if strings.HasPrefix(url, "data:") {
		return false
	}

	// Must be HTTP(S) URL
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
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

// detectMimeType attempts to detect the MIME type of image data
func detectMimeType(url string, data []byte) string {
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
