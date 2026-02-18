package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestImageEmbedder_EmbedImages(t *testing.T) {
	logger := zap.NewNop()

	// Create a test server that serves images
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logo.png":
			// 1x1 transparent PNG
			data, _ := base64.StdEncoding.DecodeString(
				"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(data)
		case "/background.jpg":
			// 1x1 white JPEG (minimal)
			data, _ := base64.StdEncoding.DecodeString(
				"/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAn/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBEQACEQMRAD8AlQAB/9k=")
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(data)
		case "/template.svg":
			w.Header().Set("Content-Type", "image/svg+xml")
			_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect fill="red" width="100" height="100"/></svg>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tests := []struct {
		name     string
		input    string
		wantURLs int // number of URLs that should be converted to data URIs
	}{
		{
			name: "embed logo in display",
			input: `{
				"vct": "test",
				"display": [{
					"locale": "en",
					"name": "Test",
					"logo": {
						"uri": "` + ts.URL + `/logo.png",
						"alt_text": "Logo"
					}
				}]
			}`,
			wantURLs: 1,
		},
		{
			name: "embed multiple images",
			input: `{
				"vct": "test",
				"display": [{
					"locale": "en",
					"name": "Test",
					"rendering": {
						"simple": {
							"logo": {"uri": "` + ts.URL + `/logo.png"},
							"background_image": {"uri": "` + ts.URL + `/background.jpg"}
						},
						"svg_templates": [
							{"uri": "` + ts.URL + `/template.svg"}
						]
					}
				}]
			}`,
			wantURLs: 3,
		},
		{
			name: "skip already embedded data URIs",
			input: `{
				"vct": "test",
				"display": [{
					"logo": {"uri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}
				}]
			}`,
			wantURLs: 0, // should not try to embed data URIs
		},
		{
			name: "handle missing images gracefully",
			input: `{
				"vct": "test",
				"display": [{
					"logo": {"uri": "` + ts.URL + `/nonexistent.png"}
				}]
			}`,
			wantURLs: 0, // should leave URL unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ImageEmbedConfig{
				Enabled:           true,
				MaxImageSize:      1024 * 1024,
				Timeout:           5 * time.Second,
				ConcurrentFetches: 2,
			}
			embedder := NewImageEmbedder(config, logger)

			result, err := embedder.EmbedImages(context.Background(), []byte(tt.input))
			if err != nil {
				t.Fatalf("EmbedImages() error = %v", err)
			}

			// Count embedded data URIs
			var out map[string]interface{}
			if err := json.Unmarshal(result, &out); err != nil {
				t.Fatalf("Failed to parse result: %v", err)
			}

			embedded := countDataURIs(out)
			if tt.wantURLs > 0 && embedded != tt.wantURLs {
				t.Errorf("EmbedImages() embedded %d URLs, want %d", embedded, tt.wantURLs)
			}

			// Verify data URIs are valid base64
			validateDataURIs(t, out)
		})
	}
}

func TestImageEmbedder_Disabled(t *testing.T) {
	logger := zap.NewNop()
	config := &ImageEmbedConfig{
		Enabled: false,
	}
	embedder := NewImageEmbedder(config, logger)

	input := `{"vct": "test", "display": [{"logo": {"uri": "https://example.com/logo.png"}}]}`
	result, err := embedder.EmbedImages(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("EmbedImages() error = %v", err)
	}

	// Should return unchanged input when disabled
	if string(result) != input {
		t.Errorf("EmbedImages() modified input when disabled")
	}
}

func TestImageEmbedder_MaxSize(t *testing.T) {
	logger := zap.NewNop()

	// Server that returns a "large" image
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		// Write 2KB of data
		_, _ = w.Write(make([]byte, 2048))
	}))
	defer ts.Close()

	config := &ImageEmbedConfig{
		Enabled:           true,
		MaxImageSize:      1024, // 1KB max
		Timeout:           5 * time.Second,
		ConcurrentFetches: 1,
	}
	embedder := NewImageEmbedder(config, logger)

	input := `{"vct": "test", "display": [{"logo": {"uri": "` + ts.URL + `/large.png"}}]}`
	result, err := embedder.EmbedImages(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("EmbedImages() error = %v", err)
	}

	// Should leave URL unchanged since image is too large
	if strings.Contains(string(result), "data:") {
		t.Errorf("EmbedImages() embedded oversized image")
	}
}

func TestDetectMimeType(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		data     []byte
		wantMime string
	}{
		{
			name:     "PNG by extension",
			url:      "https://example.com/logo.png",
			data:     nil,
			wantMime: "image/png",
		},
		{
			name:     "JPEG by extension",
			url:      "https://example.com/photo.jpg",
			data:     nil,
			wantMime: "image/jpeg",
		},
		{
			name:     "SVG by extension",
			url:      "https://example.com/icon.svg",
			data:     nil,
			wantMime: "image/svg+xml",
		},
		{
			name:     "PNG by magic bytes",
			url:      "https://example.com/image",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			wantMime: "image/png",
		},
		{
			name:     "JPEG by magic bytes",
			url:      "https://example.com/image",
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0},
			wantMime: "image/jpeg",
		},
		{
			name:     "GIF by magic bytes",
			url:      "https://example.com/image",
			data:     []byte{0x47, 0x49, 0x46, 0x38},
			wantMime: "image/gif",
		},
		{
			name:     "URL with query string",
			url:      "https://example.com/logo.png?v=123",
			data:     nil,
			wantMime: "image/png",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectMimeType(tt.url, tt.data)
			if got != tt.wantMime {
				t.Errorf("detectMimeType() = %q, want %q", got, tt.wantMime)
			}
		})
	}
}

func TestIsImageURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.com/logo.png", true},
		{"http://example.com/image.jpg", true},
		{"https://example.com/icon.svg", true},
		{"https://example.com/api/image", true},       // might be an image
		{"data:image/png;base64,iVBORw0KGgo=", false}, // already data URI
		{"file:///path/to/image.png", false},          // not HTTP
		{"/relative/path.png", false},                 // not absolute URL
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isImageURL(tt.url)
			if got != tt.want {
				t.Errorf("isImageURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// countDataURIs counts the number of data: URIs in a JSON structure
func countDataURIs(v interface{}) int {
	count := 0
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch val := v.(type) {
		case map[string]interface{}:
			if uri, ok := val["uri"].(string); ok && strings.HasPrefix(uri, "data:") {
				count++
			}
			for _, child := range val {
				walk(child)
			}
		case []interface{}:
			for _, item := range val {
				walk(item)
			}
		}
	}
	walk(v)
	return count
}

// validateDataURIs checks that all data URIs are valid base64
func validateDataURIs(t *testing.T, v interface{}) {
	t.Helper()
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch val := v.(type) {
		case map[string]interface{}:
			if uri, ok := val["uri"].(string); ok && strings.HasPrefix(uri, "data:") {
				// Parse data URI: data:mime;base64,data
				parts := strings.SplitN(uri, ",", 2)
				if len(parts) != 2 {
					t.Errorf("Invalid data URI format: %s", uri[:min(len(uri), 50)])
					return
				}
				if !strings.Contains(parts[0], "base64") {
					t.Errorf("Data URI missing base64 encoding: %s", uri[:min(len(uri), 50)])
					return
				}
				_, err := base64.StdEncoding.DecodeString(parts[1])
				if err != nil {
					t.Errorf("Invalid base64 in data URI: %v", err)
				}
			}
			for _, child := range val {
				walk(child)
			}
		case []interface{}:
			for _, item := range val {
				walk(item)
			}
		}
	}
	walk(v)
}
