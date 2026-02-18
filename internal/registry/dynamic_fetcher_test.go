package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testDynamicLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func TestDynamicCacheConfig_Compile(t *testing.T) {
	tests := []struct {
		name      string
		config    DynamicCacheConfig
		wantError bool
	}{
		{
			name: "valid patterns",
			config: DynamicCacheConfig{
				Enabled:      true,
				AllowedHosts: []string{`example\.com`, `.*\.gov`},
			},
			wantError: false,
		},
		{
			name: "invalid pattern",
			config: DynamicCacheConfig{
				Enabled:      true,
				AllowedHosts: []string{`[invalid`},
			},
			wantError: true,
		},
		{
			name: "empty patterns",
			config: DynamicCacheConfig{
				Enabled:      true,
				AllowedHosts: []string{},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Compile()
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDynamicCacheConfig_IsHostAllowed(t *testing.T) {
	config := &DynamicCacheConfig{
		Enabled:      true,
		AllowedHosts: []string{`^example\.com$`, `\.gov$`},
	}
	require.NoError(t, config.Compile())

	tests := []struct {
		host    string
		allowed bool
	}{
		{"example.com", true},
		{"www.example.com", false}, // Pattern requires exact match (^ anchor)
		{"test.gov", true},
		{"dept.agency.gov", true},
		{"evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			assert.Equal(t, tt.allowed, config.IsHostAllowed(tt.host))
		})
	}
}

func TestDynamicCacheConfig_IsHostAllowed_Disabled(t *testing.T) {
	config := &DynamicCacheConfig{
		Enabled:      false,
		AllowedHosts: []string{`.*`},
	}
	require.NoError(t, config.Compile())

	assert.False(t, config.IsHostAllowed("example.com"))
}

func TestDynamicCacheConfig_IsHostAllowed_EmptyPatterns(t *testing.T) {
	config := &DynamicCacheConfig{
		Enabled:      true,
		AllowedHosts: []string{}, // Empty means allow all
	}
	require.NoError(t, config.Compile())

	assert.True(t, config.IsHostAllowed("example.com"))
	assert.True(t, config.IsHostAllowed("any.host"))
}

func TestNewDynamicFetcher(t *testing.T) {
	config := &DynamicCacheConfig{
		Enabled:    true,
		DefaultTTL: 1 * time.Hour,
		MaxTTL:     24 * time.Hour,
		MinTTL:     5 * time.Minute,
		Timeout:    30 * time.Second,
	}
	logger := testDynamicLogger()

	fetcher := NewDynamicFetcher(config, logger)

	require.NotNil(t, fetcher)
	assert.Equal(t, config, fetcher.config)
}

func TestDynamicFetcher_Fetch_Success(t *testing.T) {
	// Create a test server
	vctmData := map[string]interface{}{
		"vct":          "https://example.com/credential/v1",
		"name":         "Test Credential",
		"description":  "A test credential type",
		"organization": "Test Org",
	}
	vctmJSON, _ := json.Marshal(vctmData)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT")
		_, _ = w.Write(vctmJSON)
	}))
	defer server.Close()

	config := &DynamicCacheConfig{
		Enabled:      true,
		DefaultTTL:   1 * time.Hour,
		MaxTTL:       24 * time.Hour,
		MinTTL:       5 * time.Minute,
		Timeout:      30 * time.Second,
		AllowedHosts: []string{}, // Allow all for test
	}
	require.NoError(t, config.Compile())

	fetcher := NewDynamicFetcher(config, testDynamicLogger())
	// Use TLS client from test server
	fetcher.client = server.Client()

	result, err := fetcher.Fetch(context.Background(), server.URL, nil)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.NotModified)

	entry := result.Entry
	require.NotNil(t, entry)
	assert.Equal(t, server.URL, entry.VCT)
	assert.Equal(t, "Test Credential", entry.Name)
	assert.Equal(t, "A test credential type", entry.Description)
	assert.Equal(t, "Test Org", entry.Organization)
	assert.True(t, entry.IsDynamic)
	assert.Equal(t, `"abc123"`, entry.ETag)
	assert.Equal(t, "Wed, 01 Jan 2025 00:00:00 GMT", entry.LastModified)
	assert.False(t, entry.ExpiresAt.IsZero())
}

func TestDynamicFetcher_Fetch_304NotModified(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for conditional request headers
		if r.Header.Get("If-None-Match") == `"abc123"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := &DynamicCacheConfig{
		Enabled:      true,
		DefaultTTL:   1 * time.Hour,
		MaxTTL:       24 * time.Hour,
		MinTTL:       5 * time.Minute,
		Timeout:      30 * time.Second,
		AllowedHosts: []string{},
	}
	require.NoError(t, config.Compile())

	fetcher := NewDynamicFetcher(config, testDynamicLogger())
	fetcher.client = server.Client()

	existingEntry := &VCTMEntry{
		VCT:  server.URL,
		ETag: `"abc123"`,
	}

	result, err := fetcher.Fetch(context.Background(), server.URL, existingEntry)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.NotModified)
	assert.Nil(t, result.Entry)
}

func TestDynamicFetcher_Fetch_DisabledError(t *testing.T) {
	config := &DynamicCacheConfig{
		Enabled: false,
	}

	fetcher := NewDynamicFetcher(config, testDynamicLogger())

	_, err := fetcher.Fetch(context.Background(), "https://example.com", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestDynamicFetcher_Fetch_HTTPSOnly(t *testing.T) {
	config := &DynamicCacheConfig{
		Enabled:    true,
		DefaultTTL: 1 * time.Hour,
		MaxTTL:     24 * time.Hour,
		MinTTL:     5 * time.Minute,
		Timeout:    30 * time.Second,
	}

	fetcher := NewDynamicFetcher(config, testDynamicLogger())

	_, err := fetcher.Fetch(context.Background(), "http://example.com", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTPS")
}

func TestDynamicFetcher_Fetch_HostNotAllowed(t *testing.T) {
	// Create a TLS test server (for allowed host matching)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"vct":"test"}`))
	}))
	defer server.Close()

	config := &DynamicCacheConfig{
		Enabled:      true,
		DefaultTTL:   1 * time.Hour,
		MaxTTL:       24 * time.Hour,
		MinTTL:       5 * time.Minute,
		Timeout:      30 * time.Second,
		AllowedHosts: []string{`^trusted\.com$`}, // Only allow exact match of trusted.com
	}
	require.NoError(t, config.Compile())

	fetcher := NewDynamicFetcher(config, testDynamicLogger())
	fetcher.client = server.Client()

	// Try to fetch from the test server (which is 127.0.0.1, not trusted.com)
	_, err := fetcher.Fetch(context.Background(), server.URL, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in the allowed hosts")
}

func TestDynamicFetcher_Fetch_ServerError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := &DynamicCacheConfig{
		Enabled:      true,
		DefaultTTL:   1 * time.Hour,
		MaxTTL:       24 * time.Hour,
		MinTTL:       5 * time.Minute,
		Timeout:      30 * time.Second,
		AllowedHosts: []string{},
	}
	require.NoError(t, config.Compile())

	fetcher := NewDynamicFetcher(config, testDynamicLogger())
	fetcher.client = server.Client()

	_, err := fetcher.Fetch(context.Background(), server.URL, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestDynamicFetcher_Fetch_InvalidJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	config := &DynamicCacheConfig{
		Enabled:      true,
		DefaultTTL:   1 * time.Hour,
		MaxTTL:       24 * time.Hour,
		MinTTL:       5 * time.Minute,
		Timeout:      30 * time.Second,
		AllowedHosts: []string{},
	}
	require.NoError(t, config.Compile())

	fetcher := NewDynamicFetcher(config, testDynamicLogger())
	fetcher.client = server.Client()

	_, err := fetcher.Fetch(context.Background(), server.URL, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestParseCacheControlMaxAge(t *testing.T) {
	tests := []struct {
		cacheControl string
		expected     time.Duration
	}{
		{"max-age=3600", 1 * time.Hour},
		{"max-age=60", 1 * time.Minute},
		{"public, max-age=3600", 1 * time.Hour},
		{"max-age=3600, must-revalidate", 1 * time.Hour},
		{"no-cache", 0},
		{"no-store", 0},
		{"max-age=", 0},
		{"max-age=abc", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.cacheControl, func(t *testing.T) {
			got := parseCacheControlMaxAge(tt.cacheControl)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCalculateExpiresAt(t *testing.T) {
	config := &DynamicCacheConfig{
		Enabled:    true,
		DefaultTTL: 1 * time.Hour,
		MaxTTL:     24 * time.Hour,
		MinTTL:     5 * time.Minute,
		Timeout:    30 * time.Second,
	}

	fetcher := NewDynamicFetcher(config, testDynamicLogger())

	t.Run("default TTL when no headers", func(t *testing.T) {
		headers := http.Header{}
		expiresAt := fetcher.calculateExpiresAt(headers)
		expectedMin := time.Now().Add(config.DefaultTTL - time.Second)
		expectedMax := time.Now().Add(config.DefaultTTL + time.Second)
		assert.True(t, expiresAt.After(expectedMin))
		assert.True(t, expiresAt.Before(expectedMax))
	})

	t.Run("uses Cache-Control max-age", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Cache-Control", "max-age=7200") // 2 hours
		expiresAt := fetcher.calculateExpiresAt(headers)
		expectedMin := time.Now().Add(2*time.Hour - time.Second)
		expectedMax := time.Now().Add(2*time.Hour + time.Second)
		assert.True(t, expiresAt.After(expectedMin))
		assert.True(t, expiresAt.Before(expectedMax))
	})

	t.Run("caps at MaxTTL", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Cache-Control", "max-age=86400")  // 24 hours (at max)
		headers.Set("Cache-Control", "max-age=172800") // 48 hours (over max)
		expiresAt := fetcher.calculateExpiresAt(headers)
		expectedMin := time.Now().Add(config.MaxTTL - time.Second)
		expectedMax := time.Now().Add(config.MaxTTL + time.Second)
		assert.True(t, expiresAt.After(expectedMin))
		assert.True(t, expiresAt.Before(expectedMax))
	})

	t.Run("bumps to MinTTL if too short", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Cache-Control", "max-age=60") // 1 minute (under min of 5 min)
		expiresAt := fetcher.calculateExpiresAt(headers)
		expectedMin := time.Now().Add(config.MinTTL - time.Second)
		expectedMax := time.Now().Add(config.MinTTL + time.Second)
		assert.True(t, expiresAt.After(expectedMin))
		assert.True(t, expiresAt.Before(expectedMax))
	})
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"https://example.com/credential/v1", true},
		{"https://example.com", true},
		{"https://example.com/path?query=1", true},
		{"http://example.com", false}, // HTTP not allowed
		{"example.com", false},        // No scheme
		{"urn:example:credential", false},
		{"file:///etc/passwd", false},
		{"", false},
		{"not-a-url", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsURL(tt.input))
		})
	}
}

func TestVCTMEntry_IsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		entry := &VCTMEntry{
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		assert.False(t, entry.IsExpired())
	})

	t.Run("expired", func(t *testing.T) {
		entry := &VCTMEntry{
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		assert.True(t, entry.IsExpired())
	})

	t.Run("zero expiration (static entry)", func(t *testing.T) {
		entry := &VCTMEntry{
			ExpiresAt: time.Time{},
		}
		assert.False(t, entry.IsExpired())
	})
}

func TestExtractStringField(t *testing.T) {
	m := map[string]interface{}{
		"name":   "Test Name",
		"count":  42,
		"active": true,
	}

	assert.Equal(t, "Test Name", extractStringField(m, "name", "default"))
	assert.Equal(t, "default", extractStringField(m, "missing", "default"))
	assert.Equal(t, "default", extractStringField(m, "count", "default"))  // Non-string
	assert.Equal(t, "default", extractStringField(m, "active", "default")) // Non-string
}
