package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/authz"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockAuthorizer implements authz.Authorizer for testing
type mockAuthorizer struct {
	allowAll bool
	err      error
}

func (m *mockAuthorizer) Authorize(ctx context.Context, req *authz.AuthorizationRequest) error {
	if m.err != nil {
		return m.err
	}
	if !m.allowAll {
		return authz.ErrUnauthorized
	}
	return nil
}

// mockTenantLookup implements TenantLookup for testing
type mockTenantLookup struct {
	tenants map[domain.TenantID]*domain.Tenant
	err     error
}

func (m *mockTenantLookup) GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.tenants == nil {
		return nil, nil
	}
	return m.tenants[id], nil
}

// setupAuthZENProxyHandler creates a test handler with a mock PDP
func setupAuthZENProxyHandler(t *testing.T, authorizer authz.Authorizer, pdpHandler http.Handler) (*AuthZENProxyHandler, *gin.Engine, *httptest.Server) {
	return setupAuthZENProxyHandlerWithTenants(t, authorizer, pdpHandler, nil)
}

// setupAuthZENProxyHandlerWithTenants creates a test handler with optional per-tenant config
func setupAuthZENProxyHandlerWithTenants(t *testing.T, authorizer authz.Authorizer, pdpHandler http.Handler, tenantLookup TenantLookup) (*AuthZENProxyHandler, *gin.Engine, *httptest.Server) {
	var pdpURL string
	var pdpServer *httptest.Server

	if pdpHandler != nil {
		pdpServer = httptest.NewServer(pdpHandler)
		pdpURL = pdpServer.URL
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpURL,
		Timeout:         30,
		AllowResolution: true,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, authorizer, tenantLookup, http.DefaultClient, logger)

	router := gin.New()

	// Mock auth middleware that sets tenant_id and user_id
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Set("user_id", "test-user")
		c.Next()
	})

	router.POST("/v1/evaluate", handler.Evaluate)
	router.POST("/v1/resolve", handler.Resolve)

	return handler, router, pdpServer
}

// ============================================================================
// /v1/evaluate Endpoint Tests
// ============================================================================

func TestEvaluate_Success(t *testing.T) {
	// Mock PDP that returns a positive decision
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Verify request body
		var req gotrust.EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode PDP request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := gotrust.EvaluationResponse{
			Decision: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, pdpHandler)
	defer pdpServer.Close()

	// AuthZEN requires subject.type to be "key"
	reqBody := gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   "https://issuer.example.com",
		},
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp gotrust.EvaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if !resp.Decision {
		t.Error("Expected decision=true")
	}
}

func TestEvaluate_Unauthorized_NoTenant(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled: true,
		PDPURL:  "http://pdp.example.com",
		Timeout: 30,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	router := gin.New()
	// No middleware to set tenant_id
	router.POST("/v1/evaluate", handler.Evaluate)

	reqBody := gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   "https://issuer.example.com",
		},
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestEvaluate_BadRequest_InvalidJSON(t *testing.T) {
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, nil)
	if pdpServer != nil {
		defer pdpServer.Close()
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestEvaluate_Forbidden_AuthorizationDenied(t *testing.T) {
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: false}, nil)
	if pdpServer != nil {
		defer pdpServer.Close()
	}

	reqBody := gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   "https://issuer.example.com",
		},
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestEvaluate_ServiceUnavailable_NoPDP(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled: true,
		PDPURL:  "", // No PDP configured
		Timeout: 30,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Set("user_id", "test-user")
		c.Next()
	})
	router.POST("/v1/evaluate", handler.Evaluate)

	reqBody := gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   "https://issuer.example.com",
		},
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestEvaluate_BadGateway_PDPError(t *testing.T) {
	// Mock PDP that returns an error
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, pdpHandler)
	defer pdpServer.Close()

	reqBody := gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   "https://issuer.example.com",
		},
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

// ============================================================================
// /v1/resolve Endpoint Tests
// ============================================================================

func TestResolve_Success(t *testing.T) {
	// Mock PDP that returns resolution data
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := gotrust.EvaluationResponse{
			Decision: true,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, pdpHandler)
	defer pdpServer.Close()

	reqBody := map[string]string{
		"subject_id": "did:web:example.com",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestResolve_BadRequest_MissingSubjectID(t *testing.T) {
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, nil)
	if pdpServer != nil {
		defer pdpServer.Close()
	}

	reqBody := map[string]string{} // Missing subject_id
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestResolve_Forbidden_AuthorizationDenied(t *testing.T) {
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: false}, nil)
	if pdpServer != nil {
		defer pdpServer.Close()
	}

	reqBody := map[string]string{
		"subject_id": "did:web:example.com",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestResolve_ServiceUnavailable_NoPDP(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          "", // No PDP configured
		Timeout:         30,
		AllowResolution: true,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Set("user_id", "test-user")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	reqBody := map[string]string{
		"subject_id": "did:web:example.com",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestResolve_Forbidden_ResolutionDisabled(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          "http://pdp.example.com",
		Timeout:         30,
		AllowResolution: false, // Resolution disabled
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	reqBody := map[string]string{"subject_id": "did:web:example.com"}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
	}
}

func TestResolve_Unauthorized_NoTenantID(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          "http://pdp.example.com",
		Timeout:         30,
		AllowResolution: true,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	router := gin.New()
	// No middleware setting tenant_id
	router.POST("/v1/resolve", handler.Resolve)

	reqBody := map[string]string{"subject_id": "did:web:example.com"}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestResolve_InternalError_BadTenantIDType(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          "http://pdp.example.com",
		Timeout:         30,
		AllowResolution: true,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", 12345) // Wrong type: int instead of string
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	reqBody := map[string]string{"subject_id": "did:web:example.com"}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestResolve_BadGateway_PDPError(t *testing.T) {
	// Create a mock PDP server that returns an error
	pdpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal error"}`))
	}))
	defer pdpServer.Close()

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	reqBody := map[string]string{"subject_id": "did:web:example.com"}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d", http.StatusBadGateway, w.Code)
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestGetActionName(t *testing.T) {
	tests := []struct {
		name string
		req  *gotrust.EvaluationRequest
		want string
	}{
		{
			name: "with action",
			req: &gotrust.EvaluationRequest{
				Action: &gotrust.Action{Name: "evaluate_trust"},
			},
			want: "evaluate_trust",
		},
		{
			name: "without action",
			req:  &gotrust.EvaluationRequest{},
			want: "",
		},
		{
			name: "nil action",
			req: &gotrust.EvaluationRequest{
				Action: nil,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getActionName(tt.req); got != tt.want {
				t.Errorf("getActionName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetPDPURL(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled: true,
		PDPURL:  "https://pdp.example.com",
		Timeout: 30,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	// Returns the global URL when no per-tenant config is available
	ctx := context.Background()
	url, err := handler.getPDPURL(ctx, "any-tenant")
	if err != nil {
		t.Fatalf("getPDPURL() unexpected error: %v", err)
	}
	if url != cfg.PDPURL {
		t.Errorf("getPDPURL() = %q, want %q", url, cfg.PDPURL)
	}
}

func TestNewAuthZENProxyHandler(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled: true,
		PDPURL:  "https://pdp.example.com",
		Timeout: 30,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	if handler == nil {
		t.Fatal("Expected handler to not be nil")
	}

	if handler.cfg != cfg {
		t.Error("cfg not set correctly")
	}

	if handler.clients == nil {
		t.Error("clients map should be initialized")
	}
}

// ============================================================================
// Client Caching Tests
// ============================================================================

func TestGetClient_Caching(t *testing.T) {
	cfg := &config.AuthZENProxyConfig{
		Enabled: true,
		PDPURL:  "https://pdp.example.com",
		Timeout: 30,
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)

	// First call creates client
	client1, err := handler.getClient("https://pdp1.example.com")
	if err != nil {
		t.Fatalf("getClient() error = %v", err)
	}

	// Second call returns cached client
	client2, err := handler.getClient("https://pdp1.example.com")
	if err != nil {
		t.Fatalf("getClient() error = %v", err)
	}

	if client1 != client2 {
		t.Error("Expected cached client to be returned")
	}

	// Different URL returns different client
	client3, err := handler.getClient("https://pdp2.example.com")
	if err != nil {
		t.Fatalf("getClient() error = %v", err)
	}

	if client1 == client3 {
		t.Error("Expected different client for different URL")
	}
}

// ============================================================================
// Per-Tenant PDP URL Tests
// ============================================================================

func TestGetPDPURL_PerTenantConfig(t *testing.T) {
	globalPDPURL := "https://global-pdp.example.com"
	tenantPDPURL := "https://tenant-pdp.example.com"

	cfg := &config.AuthZENProxyConfig{
		Enabled: true,
		PDPURL:  globalPDPURL,
		Timeout: 30,
	}

	// Create tenant with custom PDP URL
	tenantLookup := &mockTenantLookup{
		tenants: map[domain.TenantID]*domain.Tenant{
			"tenant-with-pdp": {
				ID:   "tenant-with-pdp",
				Name: "Tenant With Custom PDP",
				TrustConfig: domain.TrustConfig{
					PDPURL: tenantPDPURL,
				},
			},
			"tenant-without-pdp": {
				ID:   "tenant-without-pdp",
				Name: "Tenant Without Custom PDP",
				// No PDPURL - should use global
			},
		},
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, tenantLookup, http.DefaultClient, logger)

	ctx := context.Background()

	t.Run("tenant with custom PDP uses tenant URL", func(t *testing.T) {
		url, err := handler.getPDPURL(ctx, "tenant-with-pdp")
		if err != nil {
			t.Fatalf("getPDPURL() unexpected error: %v", err)
		}
		if url != tenantPDPURL {
			t.Errorf("getPDPURL() = %q, want tenant PDP URL %q", url, tenantPDPURL)
		}
	})

	t.Run("tenant without custom PDP uses global URL", func(t *testing.T) {
		url, err := handler.getPDPURL(ctx, "tenant-without-pdp")
		if err != nil {
			t.Fatalf("getPDPURL() unexpected error: %v", err)
		}
		if url != globalPDPURL {
			t.Errorf("getPDPURL() = %q, want global PDP URL %q", url, globalPDPURL)
		}
	})

	t.Run("unknown tenant uses global URL", func(t *testing.T) {
		url, err := handler.getPDPURL(ctx, "unknown-tenant")
		if err != nil {
			t.Fatalf("getPDPURL() unexpected error: %v", err)
		}
		if url != globalPDPURL {
			t.Errorf("getPDPURL() = %q, want global PDP URL %q", url, globalPDPURL)
		}
	})

	t.Run("nil tenant lookup uses global URL", func(t *testing.T) {
		handlerNoLookup := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, http.DefaultClient, logger)
		url, err := handlerNoLookup.getPDPURL(ctx, "any-tenant")
		if err != nil {
			t.Fatalf("getPDPURL() unexpected error: %v", err)
		}
		if url != globalPDPURL {
			t.Errorf("getPDPURL() = %q, want global PDP URL %q", url, globalPDPURL)
		}
	})
}

func TestGetPDPURL_FailClosedBehavior(t *testing.T) {
	globalPDPURL := "https://global-pdp.example.com"

	cfg := &config.AuthZENProxyConfig{
		Enabled:                     true,
		PDPURL:                      globalPDPURL,
		Timeout:                     30,
		FailOpenOnTenantLookupError: false, // default fail-closed
	}

	// Create tenant lookup that returns an error
	tenantLookup := &mockTenantLookup{
		err: fmt.Errorf("database connection failed"),
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, tenantLookup, http.DefaultClient, logger)

	ctx := context.Background()

	t.Run("fail-closed returns error on tenant lookup failure", func(t *testing.T) {
		_, err := handler.getPDPURL(ctx, "any-tenant")
		if err == nil {
			t.Error("getPDPURL() expected error with fail-closed behavior, got nil")
		}
	})

	t.Run("fail-open returns global URL on tenant lookup failure", func(t *testing.T) {
		cfgFailOpen := &config.AuthZENProxyConfig{
			Enabled:                     true,
			PDPURL:                      globalPDPURL,
			Timeout:                     30,
			FailOpenOnTenantLookupError: true, // fail-open
		}
		handlerFailOpen := NewAuthZENProxyHandler(cfgFailOpen, &mockAuthorizer{allowAll: true}, tenantLookup, http.DefaultClient, logger)

		url, err := handlerFailOpen.getPDPURL(ctx, "any-tenant")
		if err != nil {
			t.Fatalf("getPDPURL() with fail-open unexpected error: %v", err)
		}
		if url != globalPDPURL {
			t.Errorf("getPDPURL() = %q, want global PDP URL %q", url, globalPDPURL)
		}
	})
}
