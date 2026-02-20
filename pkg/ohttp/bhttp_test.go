package ohttp

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeVarint(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
	}{
		{"zero", 0},
		{"small 1-byte", 42},
		{"max 1-byte", 63},
		{"min 2-byte", 64},
		{"medium 2-byte", 1000},
		{"max 2-byte", 16383},
		{"min 4-byte", 16384},
		{"medium 4-byte", 1000000},
		{"max 4-byte", 1073741823},
		{"min 8-byte", 1073741824},
		{"large 8-byte", 1099511627776}, // 2^40
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeVarint(tt.value)

			// Verify correct length
			switch {
			case tt.value <= 63:
				assert.Len(t, encoded, 1, "should be 1 byte")
			case tt.value <= 16383:
				assert.Len(t, encoded, 2, "should be 2 bytes")
			case tt.value <= 1073741823:
				assert.Len(t, encoded, 4, "should be 4 bytes")
			default:
				assert.Len(t, encoded, 8, "should be 8 bytes")
			}

			// Verify round-trip
			decoded, err := readVarint(bytes.NewReader(encoded))
			require.NoError(t, err)
			assert.Equal(t, tt.value, decoded)
		})
	}
}

func TestBinaryHTTPRequestRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		scheme    string
		authority string
		path      string
		headers   http.Header
		body      []byte
	}{
		{
			name:      "simple GET",
			method:    "GET",
			scheme:    "https",
			authority: "example.com",
			path:      "/api/resource",
			headers:   nil,
			body:      nil,
		},
		{
			name:      "GET with query",
			method:    "GET",
			scheme:    "https",
			authority: "api.example.com:8443",
			path:      "/search?q=test&limit=10",
			headers: http.Header{
				"Accept": []string{"application/json"},
			},
			body: nil,
		},
		{
			name:      "POST with body",
			method:    "POST",
			scheme:    "https",
			authority: "example.com",
			path:      "/api/submit",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
				"Accept":       []string{"application/json"},
			},
			body: []byte(`{"name":"test","value":123}`),
		},
		{
			name:      "empty path",
			method:    "GET",
			scheme:    "https",
			authority: "example.com",
			path:      "/",
			headers:   nil,
			body:      nil,
		},
		{
			name:      "multiple headers",
			method:    "GET",
			scheme:    "https",
			authority: "example.com",
			path:      "/",
			headers: http.Header{
				"Accept":          []string{"application/json"},
				"Accept-Language": []string{"en-US"},
				"User-Agent":      []string{"test-client/1.0"},
				"X-Custom":        []string{"custom-value"},
			},
			body: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded, err := EncodeBinaryHTTPRequest(tt.method, tt.scheme, tt.authority, tt.path, tt.headers, tt.body)
			require.NoError(t, err)

			// Decode
			req, err := DecodeBinaryHTTPRequest(encoded)
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tt.method, req.Method)
			assert.Equal(t, tt.scheme, req.URL.Scheme)
			assert.Equal(t, tt.authority, req.URL.Host)

			// Parse expected path and query
			expectedPath := tt.path
			var expectedQuery string
			if idx := bytes.IndexByte([]byte(tt.path), '?'); idx >= 0 {
				expectedPath = tt.path[:idx]
				expectedQuery = tt.path[idx+1:]
			}
			assert.Equal(t, expectedPath, req.URL.Path)
			assert.Equal(t, expectedQuery, req.URL.RawQuery)

			// Verify headers (case-insensitive comparison)
			if tt.headers != nil {
				for name, values := range tt.headers {
					// Binary HTTP converts to lowercase
					reqValues := req.Header.Values(name)
					assert.Equal(t, len(values), len(reqValues), "header count mismatch for %s", name)
				}
			}

			// Verify body
			if tt.body != nil {
				body := make([]byte, len(tt.body))
				n, _ := req.Body.Read(body)
				assert.Equal(t, tt.body, body[:n])
			}
		})
	}
}

func TestBinaryHTTPResponseRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       []byte
	}{
		{
			name:       "200 OK no body",
			statusCode: 200,
			headers:    nil,
			body:       nil,
		},
		{
			name:       "200 OK with JSON",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body: []byte(`{"status":"ok","data":{"id":123}}`),
		},
		{
			name:       "404 Not Found",
			statusCode: 404,
			headers: http.Header{
				"Content-Type": []string{"text/plain"},
			},
			body: []byte("Not Found"),
		},
		{
			name:       "500 Internal Server Error",
			statusCode: 500,
			headers:    nil,
			body:       nil,
		},
		{
			name:       "multiple headers",
			statusCode: 200,
			headers: http.Header{
				"Content-Type":  []string{"application/json"},
				"Cache-Control": []string{"max-age=3600"},
				"X-Request-Id":  []string{"abc-123"},
			},
			body: []byte(`{}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create response
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
				Body:       nopCloser{bytes.NewReader(tt.body)},
			}

			// Encode
			encoded, err := EncodeBinaryHTTPResponse(resp)
			require.NoError(t, err)

			// Decode
			decoded, err := decodeBinaryHTTPResponse(encoded)
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tt.statusCode, decoded.StatusCode)

			// Verify headers
			if tt.headers != nil {
				for name := range tt.headers {
					assert.NotEmpty(t, decoded.Header.Get(name), "missing header %s", name)
				}
			}

			// Verify body
			if tt.body != nil {
				body := make([]byte, len(tt.body)+10)
				n, _ := decoded.Body.Read(body)
				assert.Equal(t, tt.body, body[:n])
			}
		})
	}
}

func TestDecodeBinaryHTTPRequest_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		error string
	}{
		{
			name:  "empty",
			data:  []byte{},
			error: "failed to read framing",
		},
		{
			name:  "invalid framing",
			data:  []byte{1}, // Only framing=0 supported
			error: "unsupported framing",
		},
		{
			name:  "truncated method",
			data:  []byte{0, 10}, // framing=0, method length=10, no data
			error: "failed to read method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeBinaryHTTPRequest(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.error)
		})
	}
}

// nopCloser wraps a reader to satisfy io.ReadCloser
type nopCloser struct {
	*bytes.Reader
}

func (nopCloser) Close() error { return nil }
