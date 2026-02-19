package embed

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestImageEmbedder_EmbedImages(t *testing.T) {
	logger := zap.NewNop()

	// Create a TLS test server that serves images (embedder requires HTTPS)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		wantData bool // Should data: URI be present
		wantOrig bool // Should original URL be present
	}{
		{
			name:     "embed_logo_in_display",
			input:    `{"vct": "test", "display": [{"logo": {"uri": "` + ts.URL + `/logo.png"}}]}`,
			wantData: true,
			wantOrig: false,
		},
		{
			name:     "embed_multiple_images",
			input:    `{"display": [{"logo": {"uri": "` + ts.URL + `/logo.png"}, "background_image": {"uri": "` + ts.URL + `/background.jpg"}}]}`,
			wantData: true,
			wantOrig: false,
		},
		{
			name:     "skip_already_embedded_data_URIs",
			input:    `{"display": [{"logo": {"uri": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}}]}`,
			wantData: true,
			wantOrig: false,
		},
		{
			name:     "handle_missing_images_gracefully",
			input:    `{"display": [{"logo": {"uri": "` + ts.URL + `/nonexistent.png"}}]}`,
			wantData: false,
			wantOrig: true, // Original URL should remain when fetch fails
		},
	}

	config := &Config{
		Enabled:           true,
		MaxImageSize:      1024 * 1024,
		Timeout:           5 * time.Second,
		ConcurrentFetches: 2,
	}
	// Use TLS client from test server to allow HTTPS connections
	embedder := NewImageEmbedder(config, logger, WithHTTPClient(ts.Client()))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := embedder.EmbedImages(context.Background(), []byte(tt.input))
			if err != nil {
				t.Fatalf("EmbedImages() error = %v", err)
			}

			resultStr := string(result)
			hasDataURI := strings.Contains(resultStr, "data:image/")
			hasOrigURL := strings.Contains(resultStr, ts.URL)

			if tt.wantData && !hasDataURI {
				t.Errorf("Expected data URI in result, got: %s", resultStr)
			}
			if tt.wantOrig && !hasOrigURL {
				t.Errorf("Expected original URL to remain in result, got: %s", resultStr)
			}
			if !tt.wantOrig && hasOrigURL && !strings.Contains(tt.input, "nonexistent") {
				t.Errorf("Expected original URL to be replaced, got: %s", resultStr)
			}
		})
	}
}

func TestImageEmbedder_Disabled(t *testing.T) {
	logger := zap.NewNop()

	config := &Config{
		Enabled: false,
	}
	embedder := NewImageEmbedder(config, logger)

	input := `{"display": [{"logo": {"uri": "https://example.com/logo.png"}}]}`
	result, err := embedder.EmbedImages(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("EmbedImages() error = %v", err)
	}

	if string(result) != input {
		t.Errorf("Expected input to be unchanged when disabled, got: %s", result)
	}
}

func TestImageEmbedder_MaxSize(t *testing.T) {
	logger := zap.NewNop()

	// TLS server that returns a "large" image
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		// Write 2KB of data
		_, _ = w.Write(make([]byte, 2048))
	}))
	defer ts.Close()

	config := &Config{
		Enabled:           true,
		MaxImageSize:      1024, // 1KB max
		Timeout:           5 * time.Second,
		ConcurrentFetches: 1,
	}
	embedder := NewImageEmbedder(config, logger, WithHTTPClient(ts.Client()))

	input := `{"vct": "test", "display": [{"logo": {"uri": "` + ts.URL + `/large.png"}}]}`
	result, err := embedder.EmbedImages(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("EmbedImages() error = %v", err)
	}

	// Original URL should remain since image was too large
	if !strings.Contains(string(result), ts.URL) {
		t.Errorf("Expected original URL to remain for too-large image, got: %s", result)
	}
}

func TestImageEmbedder_CustomExtractor(t *testing.T) {
	logger := zap.NewNop()

	// Custom extractor that only extracts from "icon" fields
	customExtractor := func(doc map[string]interface{}) []string {
		var urls []string
		if icon, ok := doc["icon"].(string); ok && IsImageURL(icon) {
			urls = append(urls, icon)
		}
		return urls
	}

	// Custom replacer that replaces "icon" fields
	customReplacer := func(doc map[string]interface{}, dataURLs map[string]string) {
		if icon, ok := doc["icon"].(string); ok {
			if dataURL, found := dataURLs[icon]; found {
				doc["icon"] = dataURL
			}
		}
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := base64.StdEncoding.DecodeString(
			"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(data)
	}))
	defer ts.Close()

	config := &Config{
		Enabled:           true,
		MaxImageSize:      1024 * 1024,
		Timeout:           5 * time.Second,
		ConcurrentFetches: 2,
	}
	embedder := NewImageEmbedder(config, logger,
		WithExtractor(customExtractor),
		WithReplacer(customReplacer),
		WithHTTPClient(ts.Client()),
	)

	input := `{"icon": "` + ts.URL + `/test.png", "logo": {"uri": "` + ts.URL + `/other.png"}}`
	result, err := embedder.EmbedImages(context.Background(), []byte(input))
	if err != nil {
		t.Fatalf("EmbedImages() error = %v", err)
	}

	resultStr := string(result)
	// Icon should be embedded
	if !strings.Contains(resultStr, `"icon":"data:image/png;base64,`) {
		t.Errorf("Expected icon to be embedded, got: %s", resultStr)
	}
	// Logo should NOT be embedded (custom extractor ignores it)
	if !strings.Contains(resultStr, `"logo":{"uri":"`) {
		t.Errorf("Expected logo to remain unchanged, got: %s", resultStr)
	}
}

func TestDetectMimeType(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		data     []byte
		expected string
	}{
		{
			name:     "PNG_by_extension",
			url:      "https://example.com/image.png",
			data:     []byte{},
			expected: "image/png",
		},
		{
			name:     "JPEG_by_extension",
			url:      "https://example.com/photo.jpg",
			data:     []byte{},
			expected: "image/jpeg",
		},
		{
			name:     "SVG_by_extension",
			url:      "https://example.com/icon.svg",
			data:     []byte{},
			expected: "image/svg+xml",
		},
		{
			name:     "PNG_by_magic_bytes",
			url:      "https://example.com/image",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			expected: "image/png",
		},
		{
			name:     "JPEG_by_magic_bytes",
			url:      "https://example.com/image",
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0},
			expected: "image/jpeg",
		},
		{
			name:     "GIF_by_magic_bytes",
			url:      "https://example.com/image",
			data:     []byte{0x47, 0x49, 0x46, 0x38},
			expected: "image/gif",
		},
		{
			name:     "URL_with_query_string",
			url:      "https://example.com/image.png?v=123",
			data:     []byte{},
			expected: "image/png",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectMimeType(tt.url, tt.data)
			if result != tt.expected {
				t.Errorf("DetectMimeType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsImageURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com/logo.png", true},
		{"http://example.com/image.jpg", false}, // HTTP not allowed (HTTPS only)
		{"https://example.com/icon.svg", true},
		{"https://example.com/api/image", true},       // No extension but HTTPS
		{"data:image/png;base64,iVBORw0KGgo=", false}, // Already data URI
		{"file:///path/to/image.png", false},          // Not HTTPS
		{"/relative/path.png", false},                 // Not HTTPS
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := IsImageURL(tt.url)
			if result != tt.expected {
				t.Errorf("IsImageURL(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestDefaultURLExtractor(t *testing.T) {
	doc := map[string]interface{}{
		"vct": "test",
		"display": []interface{}{
			map[string]interface{}{
				"logo": map[string]interface{}{
					"uri": "https://example.com/logo.png",
				},
				"background_image": map[string]interface{}{
					"uri": "https://example.com/bg.jpg",
				},
			},
		},
		"rendering": map[string]interface{}{
			"svg_templates": []interface{}{
				map[string]interface{}{
					"uri": "https://example.com/template.svg",
				},
			},
		},
	}

	urls := DefaultURLExtractor(doc)

	if len(urls) != 3 {
		t.Errorf("Expected 3 URLs, got %d", len(urls))
	}

	expected := map[string]bool{
		"https://example.com/logo.png":     true,
		"https://example.com/bg.jpg":       true,
		"https://example.com/template.svg": true,
	}

	for _, url := range urls {
		if !expected[url] {
			t.Errorf("Unexpected URL extracted: %s", url)
		}
	}
}
