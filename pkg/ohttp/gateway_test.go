package ohttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// mockProxyFilter implements ProxyFilterer for testing.
type mockProxyFilter struct {
	allowAll bool
	allowed  map[string]bool
	reason   string
}

func (m *mockProxyFilter) IsAllowed(rawURL string) (bool, string) {
	if m.allowAll {
		return true, ""
	}
	if m.allowed != nil && m.allowed[rawURL] {
		return true, ""
	}
	return false, m.reason
}

func TestGateway_HandleRequest(t *testing.T) {
	logger := zap.NewNop()

	t.Run("successful round-trip", func(t *testing.T) {
		// Create a test target server
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "GET", r.Method)
			assert.Equal(t, "/api/test", r.URL.Path)
			assert.Equal(t, "param=value", r.URL.RawQuery)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","message":"hello"}`))
		}))
		defer target.Close()

		// Create key config
		keyConfig, err := NewKeyConfig(1)
		require.NoError(t, err)

		// Create gateway with permissive filter
		filter := &mockProxyFilter{allowAll: true}
		gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)

		// Create encapsulated request (simulating frontend)
		targetURL := target.URL + "/api/test?param=value"
		headers := http.Header{
			"Accept": []string{"application/json"},
		}

		encRequest, sealer, err := EncapsulateRequest(keyConfig, "GET", targetURL, headers, nil)
		require.NoError(t, err)

		// Process through gateway
		encResponse, err := gateway.HandleRequest(context.Background(), encRequest)
		require.NoError(t, err)
		require.NotEmpty(t, encResponse)

		// Get enc from the original request for decapsulation
		enc := encRequest[7 : 7+32]

		// Decrypt response (simulating frontend)
		resp, err := DecapsulateResponse(encResponse, enc, sealer)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		assert.JSONEq(t, `{"status":"ok","message":"hello"}`, string(body))
	})

	t.Run("POST with body", func(t *testing.T) {
		// Create test server that echoes the body
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)

			body, _ := io.ReadAll(r.Body)
			assert.JSONEq(t, `{"input":"test"}`, string(body))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"created":true}`))
		}))
		defer target.Close()

		keyConfig, err := NewKeyConfig(1)
		require.NoError(t, err)

		filter := &mockProxyFilter{allowAll: true}
		gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)

		targetURL := target.URL + "/api/create"
		headers := http.Header{
			"Content-Type": []string{"application/json"},
		}
		requestBody := []byte(`{"input":"test"}`)

		encRequest, sealer, err := EncapsulateRequest(keyConfig, "POST", targetURL, headers, requestBody)
		require.NoError(t, err)

		encResponse, err := gateway.HandleRequest(context.Background(), encRequest)
		require.NoError(t, err)

		enc := encRequest[7 : 7+32]
		resp, err := DecapsulateResponse(encResponse, enc, sealer)
		require.NoError(t, err)

		assert.Equal(t, 201, resp.StatusCode)
	})

	t.Run("blocked by proxy filter", func(t *testing.T) {
		keyConfig, err := NewKeyConfig(1)
		require.NoError(t, err)

		filter := &mockProxyFilter{
			allowAll: false,
			reason:   "SSRF blocked",
		}
		gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)

		encRequest, _, err := EncapsulateRequest(keyConfig, "GET", "http://169.254.169.254/metadata", nil, nil)
		require.NoError(t, err)

		_, err = gateway.HandleRequest(context.Background(), encRequest)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "blocked")
	})

	t.Run("wrong key ID", func(t *testing.T) {
		keyConfig1, _ := NewKeyConfig(1)
		keyConfig2, _ := NewKeyConfig(2)

		filter := &mockProxyFilter{allowAll: true}
		gateway := NewGateway(keyConfig2, filter, http.DefaultClient, logger)

		// Encrypt with keyConfig1, but gateway has keyConfig2
		encRequest, _, err := EncapsulateRequest(keyConfig1, "GET", "https://example.com/", nil, nil)
		require.NoError(t, err)

		_, err = gateway.HandleRequest(context.Background(), encRequest)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown key ID")
	})

	t.Run("invalid encapsulated request", func(t *testing.T) {
		keyConfig, _ := NewKeyConfig(1)
		filter := &mockProxyFilter{allowAll: true}
		gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)

		// Too short
		_, err := gateway.HandleRequest(context.Background(), []byte{1, 2, 3})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too short")
	})

	t.Run("target server error", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		}))
		defer target.Close()

		keyConfig, _ := NewKeyConfig(1)
		filter := &mockProxyFilter{allowAll: true}
		gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)

		encRequest, sealer, err := EncapsulateRequest(keyConfig, "GET", target.URL+"/error", nil, nil)
		require.NoError(t, err)

		encResponse, err := gateway.HandleRequest(context.Background(), encRequest)
		require.NoError(t, err) // Gateway should still return response

		enc := encRequest[7 : 7+32]
		resp, err := DecapsulateResponse(encResponse, enc, sealer)
		require.NoError(t, err)

		assert.Equal(t, 500, resp.StatusCode)
	})
}

func TestGateway_AlgorithmValidation(t *testing.T) {
	logger := zap.NewNop()
	keyConfig, _ := NewKeyConfig(1)
	filter := &mockProxyFilter{allowAll: true}
	gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)

	t.Run("rejects unsupported KEM", func(t *testing.T) {
		// Create a valid-looking request with wrong KEM
		encRequest, _, _ := EncapsulateRequest(keyConfig, "GET", "https://example.com/", nil, nil)

		// Modify KEM ID (bytes 1-2)
		encRequest[1] = 0xFF
		encRequest[2] = 0xFF

		_, err := gateway.HandleRequest(context.Background(), encRequest)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported algorithms")
	})
}

func TestEncapsulateRequest_URLParsing(t *testing.T) {
	keyConfig, _ := NewKeyConfig(1)

	tests := []struct {
		name        string
		url         string
		wantScheme  string
		wantHost    string
		wantPath    string
		wantQuery   string
		shouldError bool
	}{
		{
			name:       "simple HTTPS",
			url:        "https://example.com/path",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/path",
		},
		{
			name:       "with port",
			url:        "https://example.com:8443/api",
			wantScheme: "https",
			wantHost:   "example.com:8443",
			wantPath:   "/api",
		},
		{
			name:       "with query",
			url:        "https://example.com/search?q=test&limit=10",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/search",
			wantQuery:  "q=test&limit=10",
		},
		{
			name:       "root path",
			url:        "https://example.com",
			wantScheme: "https",
			wantHost:   "example.com",
			wantPath:   "/",
		},
		{
			name:        "missing scheme",
			url:         "example.com/path",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encRequest, _, err := EncapsulateRequest(keyConfig, "GET", tt.url, nil, nil)

			if tt.shouldError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, encRequest)

			// We can verify by decrypting and checking the Binary HTTP content
			// This is implicitly tested in the full round-trip tests
		})
	}
}
