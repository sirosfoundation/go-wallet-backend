package ohttp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHandler_KeysHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	keyConfig, err := NewKeyConfig(42)
	require.NoError(t, err)

	filter := &mockProxyFilter{allowAll: true}
	gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)
	handler := NewHandler(gateway, logger)

	router := gin.New()
	router.GET("/.well-known/ohttp-keys", handler.KeysHandler)

	req := httptest.NewRequest("GET", "/.well-known/ohttp-keys", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, ContentTypeOHTTPKeys, w.Header().Get("Content-Type"))

	// Verify response can be parsed
	body := w.Body.Bytes()
	assert.Len(t, body, 43) // Expected key config size

	// Verify key ID is present
	assert.Equal(t, uint8(42), body[2])
}

func TestHandler_GatewayHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	// Create test target
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"gateway":"works"}`))
	}))
	defer target.Close()

	keyConfig, err := NewKeyConfig(1)
	require.NoError(t, err)

	filter := &mockProxyFilter{allowAll: true}
	gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)
	handler := NewHandler(gateway, logger)

	router := gin.New()
	router.POST("/ohttp/gateway", handler.GatewayHandler)

	t.Run("successful request", func(t *testing.T) {
		// Create encapsulated request
		encRequest, sealer, err := EncapsulateRequest(keyConfig, "GET", target.URL+"/test", nil, nil)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/ohttp/gateway", bytes.NewReader(encRequest))
		req.Header.Set("Content-Type", ContentTypeOHTTPRequest)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, ContentTypeOHTTPResponse, w.Header().Get("Content-Type"))

		// Decrypt response
		enc := encRequest[7 : 7+32]
		resp, err := DecapsulateResponse(w.Body.Bytes(), enc, sealer)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		assert.JSONEq(t, `{"gateway":"works"}`, string(body))
	})

	t.Run("wrong content type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/ohttp/gateway", bytes.NewReader([]byte("test")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("request too large", func(t *testing.T) {
		// Create handler with small max size
		smallHandler := NewHandler(gateway, logger, WithMaxRequestSize(10))

		smallRouter := gin.New()
		smallRouter.POST("/ohttp/gateway", smallHandler.GatewayHandler)

		// Send request larger than limit
		largeBody := bytes.Repeat([]byte("x"), 100)
		req := httptest.NewRequest("POST", "/ohttp/gateway", bytes.NewReader(largeBody))
		req.Header.Set("Content-Type", ContentTypeOHTTPRequest)
		w := httptest.NewRecorder()
		smallRouter.ServeHTTP(w, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})

	t.Run("invalid encapsulated request", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/ohttp/gateway", bytes.NewReader([]byte{1, 2, 3}))
		req.Header.Set("Content-Type", ContentTypeOHTTPRequest)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should return 502 for gateway errors (not 400)
		assert.Equal(t, http.StatusBadGateway, w.Code)
	})
}

func TestHandler_RelayHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"relay":"works"}`))
	}))
	defer target.Close()

	keyConfig, _ := NewKeyConfig(1)
	filter := &mockProxyFilter{allowAll: true}
	gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)
	handler := NewHandler(gateway, logger)

	// Setup with mock auth middleware
	mockAuth := func(c *gin.Context) {
		// Simulate authenticated user
		c.Set("userID", "test-user")
		c.Next()
	}

	router := gin.New()
	handler.RegisterRoutes(router, mockAuth, true)

	t.Run("relay with auth", func(t *testing.T) {
		encRequest, sealer, _ := EncapsulateRequest(keyConfig, "GET", target.URL, nil, nil)

		req := httptest.NewRequest("POST", "/api/relay", bytes.NewReader(encRequest))
		req.Header.Set("Content-Type", ContentTypeOHTTPRequest)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		enc := encRequest[7 : 7+32]
		resp, err := DecapsulateResponse(w.Body.Bytes(), enc, sealer)
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})
}

func TestHandler_RegisterRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	keyConfig, _ := NewKeyConfig(1)
	filter := &mockProxyFilter{allowAll: true}
	gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)
	handler := NewHandler(gateway, logger)

	t.Run("with integrated relay", func(t *testing.T) {
		router := gin.New()
		handler.RegisterRoutes(router, nil, true)

		// Check that all routes are registered
		routes := router.Routes()

		hasKeys := false
		hasGateway := false
		hasRelay := false

		for _, route := range routes {
			switch route.Path {
			case "/.well-known/ohttp-keys":
				hasKeys = true
				assert.Equal(t, "GET", route.Method)
			case "/ohttp/gateway":
				hasGateway = true
				assert.Equal(t, "POST", route.Method)
			case "/api/relay":
				hasRelay = true
				assert.Equal(t, "POST", route.Method)
			}
		}

		assert.True(t, hasKeys, "missing /.well-known/ohttp-keys")
		assert.True(t, hasGateway, "missing /ohttp/gateway")
		assert.True(t, hasRelay, "missing /api/relay")
	})

	t.Run("without integrated relay", func(t *testing.T) {
		router := gin.New()
		handler.RegisterRoutes(router, nil, false)

		routes := router.Routes()

		hasRelay := false
		for _, route := range routes {
			if route.Path == "/api/relay" {
				hasRelay = true
			}
		}

		assert.False(t, hasRelay, "/api/relay should not be registered")
	})
}

func TestHandler_ProxyFilterIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	keyConfig, _ := NewKeyConfig(1)

	// Filter that only allows specific URLs
	filter := &mockProxyFilter{
		allowed: map[string]bool{
			"https://allowed.example.com/api": true,
		},
		reason: "URL not in allowlist",
	}

	gateway := NewGateway(keyConfig, filter, http.DefaultClient, logger)
	handler := NewHandler(gateway, logger)

	router := gin.New()
	router.POST("/ohttp/gateway", handler.GatewayHandler)

	t.Run("blocks disallowed URL", func(t *testing.T) {
		encRequest, _, _ := EncapsulateRequest(keyConfig, "GET", "https://blocked.example.com/secret", nil, nil)

		req := httptest.NewRequest("POST", "/ohttp/gateway", bytes.NewReader(encRequest))
		req.Header.Set("Content-Type", ContentTypeOHTTPRequest)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Should return 502 (doesn't leak that it was blocked vs other error)
		assert.Equal(t, http.StatusBadGateway, w.Code)
	})
}
