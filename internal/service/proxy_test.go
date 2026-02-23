package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewProxyService(t *testing.T) {
	cfg := &config.Config{}
	logger := zap.NewNop()

	svc := NewProxyService(cfg, logger)

	if svc == nil {
		t.Fatal("expected proxy service to not be nil")
	}
}

func TestIsBinaryRequest(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{"PNG", "https://example.com/image.png", true},
		{"JPG", "https://example.com/image.jpg", true},
		{"JPEG", "https://example.com/image.jpeg", true},
		{"GIF", "https://example.com/image.gif", true},
		{"WebP", "https://example.com/image.webp", true},
		{"BMP", "https://example.com/image.bmp", true},
		{"TIFF", "https://example.com/image.tiff", true},
		{"TIF", "https://example.com/image.tif", true},
		{"ICO", "https://example.com/favicon.ico", true},
		{"PNG with query", "https://example.com/image.png?size=large", true},
		{"HTML", "https://example.com/page.html", false},
		{"JSON", "https://example.com/api/data.json", false},
		{"no extension", "https://example.com/api/resource", false},
		{"uppercase PNG", "https://example.com/IMAGE.PNG", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBinaryRequest(tt.url)
			if result != tt.expected {
				t.Errorf("IsBinaryRequest(%q) = %v, want %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestProxyService_Execute_EmptyURL(t *testing.T) {
	cfg := &config.Config{}
	logger := zap.NewNop()
	svc := NewProxyService(cfg, logger)
	ctx := context.Background()

	_, _, err := svc.Execute(ctx, &ProxyRequest{URL: ""})
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestProxyService_Execute_Success(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"message": "success"}`))
	}))
	defer server.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	svc := NewProxyService(cfg, logger)
	ctx := context.Background()

	resp, _, err := svc.Execute(ctx, &ProxyRequest{
		URL:    server.URL,
		Method: "GET",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Status != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, resp.Status)
	}
}

func TestProxyService_Execute_WithHeaders(t *testing.T) {
	var receivedHeaders http.Header

	// Create a test server that captures headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	svc := NewProxyService(cfg, logger)
	ctx := context.Background()

	_, _, err := svc.Execute(ctx, &ProxyRequest{
		URL:    server.URL,
		Method: "GET",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Error("expected custom header to be set")
	}
}

// TestProxyService_StripsFingerprintingHeaders verifies privacy-sensitive headers are stripped
func TestProxyService_StripsFingerprintingHeaders(t *testing.T) {
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	svc := NewProxyService(cfg, logger)
	ctx := context.Background()

	_, _, err := svc.Execute(ctx, &ProxyRequest{
		URL:    server.URL,
		Method: "GET",
		Headers: map[string]string{
			"user-agent":         "Mozilla/5.0 (fingerprint)",
			"accept-language":    "en-US,en;q=0.9",
			"sec-ch-ua":          "\"Chromium\";v=\"100\"",
			"sec-ch-ua-platform": "Linux",
			"x-forwarded-for":    "192.168.1.1",
			"Authorization":      "Bearer token", // Should NOT be stripped
			"X-Custom-Header":    "custom",       // Should NOT be stripped
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Fingerprinting headers should be stripped
	if receivedHeaders.Get("Accept-Language") != "" {
		t.Error("Accept-Language should be stripped")
	}
	// Note: Accept-Encoding is automatically added by Go's http.Client for compression,
	// but client-provided values are stripped
	if receivedHeaders.Get("Sec-Ch-Ua") != "" {
		t.Error("Sec-CH-UA should be stripped")
	}
	if receivedHeaders.Get("Sec-Ch-Ua-Platform") != "" {
		t.Error("Sec-CH-UA-Platform should be stripped")
	}
	if receivedHeaders.Get("X-Forwarded-For") != "" {
		t.Error("X-Forwarded-For should be stripped")
	}

	// User-Agent should be replaced with generic value
	if receivedHeaders.Get("User-Agent") != "SIROS-Wallet/1.0" {
		t.Errorf("User-Agent should be SIROS-Wallet/1.0, got %s", receivedHeaders.Get("User-Agent"))
	}

	// Safe headers should still be passed
	if receivedHeaders.Get("Authorization") != "Bearer token" {
		t.Error("Authorization should NOT be stripped")
	}
	if receivedHeaders.Get("X-Custom-Header") != "custom" {
		t.Error("X-Custom-Header should NOT be stripped")
	}
}

func TestProxyService_Execute_POST_WithData(t *testing.T) {
	var receivedBody []byte

	// Create a test server that captures the body
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	svc := NewProxyService(cfg, logger)
	ctx := context.Background()

	_, _, err := svc.Execute(ctx, &ProxyRequest{
		URL:    server.URL,
		Method: "POST",
		Data:   map[string]string{"key": "value"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Error("expected body to be sent")
	}
}

func TestProxyService_Execute_DefaultMethod(t *testing.T) {
	var receivedMethod string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	svc := NewProxyService(cfg, logger)
	ctx := context.Background()

	// Don't specify method - should default to GET
	_, _, err := svc.Execute(ctx, &ProxyRequest{
		URL: server.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedMethod != "GET" {
		t.Errorf("expected method GET, got %s", receivedMethod)
	}
}

func TestProxyService_Execute_StringData(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	svc := NewProxyService(cfg, logger)
	ctx := context.Background()

	_, _, err := svc.Execute(ctx, &ProxyRequest{
		URL:    server.URL,
		Method: "POST",
		Data:   "raw string data",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(receivedBody) != "raw string data" {
		t.Errorf("expected body 'raw string data', got '%s'", string(receivedBody))
	}
}

func TestProxyService_Execute_ByteData(t *testing.T) {
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.Config{}
	logger := zap.NewNop()
	svc := NewProxyService(cfg, logger)
	ctx := context.Background()

	_, _, err := svc.Execute(ctx, &ProxyRequest{
		URL:    server.URL,
		Method: "POST",
		Data:   []byte("byte data"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(receivedBody) != "byte data" {
		t.Errorf("expected body 'byte data', got '%s'", string(receivedBody))
	}
}
