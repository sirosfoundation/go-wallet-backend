package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/authz"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
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

	// Default mock resolver that returns basic unsigned metadata
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{
				"credential_issuer": "https://issuer.example.com",
			},
		},
	}

	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, authorizer, tenantLookup, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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

func TestResolve_URLSubject_DefaultsToKey(t *testing.T) {
	// HTTPS URLs without an explicit subject_type must default to "key" for backward
	// compatibility (e.g. OIDF entity resolution over HTTPS uses subject.type="key").
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evalReq gotrust.EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&evalReq); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}
		if evalReq.Subject.Type != "key" {
			t.Errorf("Expected subject.type 'key' (default), got %q", evalReq.Subject.Type)
		}
		if evalReq.Subject.ID != "https://issuer.example.com" {
			t.Errorf("Expected subject.id 'https://issuer.example.com', got %q", evalReq.Subject.ID)
		}
		resp := gotrust.EvaluationResponse{Decision: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, pdpHandler)
	defer pdpServer.Close()

	reqBody := map[string]string{
		"subject_id": "https://issuer.example.com",
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

func TestResolve_URLSubject_ExplicitType(t *testing.T) {
	// With explicit subject_type "url", the subject is resolved locally.
	// The PDP receives a key-based trust evaluation request.
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evalReq gotrust.EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&evalReq); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}
		// Local resolution sends subject.type "key" to the PDP
		if evalReq.Subject.Type != "key" {
			t.Errorf("Expected subject.type 'key', got %q", evalReq.Subject.Type)
		}
		resp := gotrust.EvaluationResponse{Decision: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, pdpHandler)
	defer pdpServer.Close()

	reqBody := map[string]interface{}{
		"subject_id":   "https://issuer.example.com",
		"subject_type": "url",
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

func TestResolve_DIDSubject_StillWorks(t *testing.T) {
	// Verify backward compatibility: DID subjects still get type "key" and resource.type "resolution"
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evalReq gotrust.EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&evalReq); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}
		if evalReq.Subject.Type != "key" {
			t.Errorf("Expected subject.type 'key', got %q", evalReq.Subject.Type)
		}
		if evalReq.Resource.Type != "resolution" {
			t.Errorf("Expected resource.type 'resolution', got %q", evalReq.Resource.Type)
		}
		resp := gotrust.EvaluationResponse{Decision: true}
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

func TestResolve_InvalidSubjectType(t *testing.T) {
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, nil)
	if pdpServer != nil {
		defer pdpServer.Close()
	}

	reqBody := map[string]interface{}{
		"subject_id":   "did:web:example.com",
		"subject_type": "invalid",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestResolve_URLSubject_NonHTTPS_Rejected(t *testing.T) {
	// When subject_type="url" is explicitly set, subject_id must be a valid HTTPS URL.
	// HTTP URLs should be rejected with 400.
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, nil)
	if pdpServer != nil {
		defer pdpServer.Close()
	}

	reqBody := map[string]interface{}{
		"subject_id":   "http://issuer.example.com",
		"subject_type": "url",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestResolve_URLSubject_SPOCP_DefaultRules_Authorized(t *testing.T) {
	// Integration test: subject.type="url" with an HTTPS URL must be authorized by
	// the default SPOCP rules (Rule 5 added alongside the issuer-url registry).
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := gotrust.EvaluationResponse{Decision: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	})
	pdpServer := httptest.NewServer(pdpHandler)
	defer pdpServer.Close()

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}

	logger := zap.NewNop()
	spocpAuth, err := authz.NewSPOCPAuthorizer(nil, logger)
	if err != nil {
		t.Fatalf("failed to create SPOCP authorizer: %v", err)
	}
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{
				"credential_issuer": "https://issuer.example.com",
			},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, spocpAuth, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	reqBody := map[string]interface{}{
		"subject_id":   "https://issuer.example.com",
		"subject_type": "url",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d (url-type subject authorized by default SPOCP rules), got %d: %s",
			http.StatusOK, w.Code, w.Body.String())
	}
}

// ============================================================================
// credential_offer_uri Resource Type Tests
// ============================================================================

func TestResolve_CredentialOfferURI_Success(t *testing.T) {
	// A well-formed credential offer document served at the offer URI is returned
	// in context.credential_offer, with decision=true and no PDP call.
	offer := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
		"credential_configuration_ids": []interface{}{
			"UniversityDegreeCredential",
		},
		"grants": map[string]interface{}{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
				"pre-authorized_code": "abc123",
			},
		},
	}

	offerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(offer) //nolint:errcheck
	}))
	defer offerServer.Close()

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, offerServer.Client(), http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":    offerServer.URL + "/offer",
		"subject_type":  "url",
		"resource_type": "credential_offer_uri",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp["decision"] != true {
		t.Errorf("Expected decision=true, got %v", resp["decision"])
	}
	ctx, ok := resp["context"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected context object, got %T", resp["context"])
	}
	credOffer, ok := ctx["credential_offer"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected context.credential_offer object, got %T", ctx["credential_offer"])
	}
	if credOffer["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("Expected credential_issuer='https://issuer.example.com', got %v", credOffer["credential_issuer"])
	}
}

func TestResolve_CredentialOfferURI_NonHTTPS_Rejected(t *testing.T) {
	// HTTP (non-HTTPS) subject_id must be rejected before any fetch is attempted.
	_, router, pdpServer := setupAuthZENProxyHandler(t, &mockAuthorizer{allowAll: true}, nil)
	if pdpServer != nil {
		defer pdpServer.Close()
	}

	body, _ := json.Marshal(map[string]string{
		"subject_id":    "http://issuer.example.com/offer",
		"subject_type":  "url",
		"resource_type": "credential_offer_uri",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestResolve_CredentialOfferURI_FetchFailure(t *testing.T) {
	// If the offer URI cannot be fetched, return 502.
	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	// Use a port that is not listening so the fetch will fail
	body, _ := json.Marshal(map[string]string{
		"subject_id":    "https://127.0.0.1:1/offer",
		"subject_type":  "url",
		"resource_type": "credential_offer_uri",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestResolve_CredentialOfferURI_InvalidJSON(t *testing.T) {
	// If the offer endpoint returns invalid JSON, return 502.
	offerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not valid json")) //nolint:errcheck
	}))
	defer offerServer.Close()

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, offerServer.Client(), http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":    offerServer.URL + "/offer",
		"subject_type":  "url",
		"resource_type": "credential_offer_uri",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestResolve_CredentialOfferURI_MissingCredentialIssuer(t *testing.T) {
	// A JSON document without credential_issuer must be rejected with 502.
	offerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"credential_configuration_ids": []string{"MyCredential"},
		})
	}))
	defer offerServer.Close()

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, offerServer.Client(), http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":    offerServer.URL + "/offer",
		"subject_type":  "url",
		"resource_type": "credential_offer_uri",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestResolve_CredentialOfferURI_NonOKStatus(t *testing.T) {
	// If the offer endpoint returns a non-200 status, return 502.
	offerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer offerServer.Close()

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, offerServer.Client(), http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":    offerServer.URL + "/offer",
		"subject_type":  "url",
		"resource_type": "credential_offer_uri",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestResolve_CredentialOfferURI_RedirectToHTTP_Rejected(t *testing.T) {
	// A redirect from the HTTPS offer endpoint to a plain HTTP URL must be refused.
	// Set up a plain HTTP server that would receive the redirect target.
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should never be reached — the redirect must be refused before this.
		t.Error("plain HTTP redirect target was reached; redirect hardening failed")
		w.WriteHeader(http.StatusOK)
	}))
	defer httpTarget.Close()

	// TLS server that redirects to the plain HTTP target.
	offerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, httpTarget.URL+"/offer", http.StatusFound)
	}))
	defer offerServer.Close()

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, offerServer.Client(), http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":    offerServer.URL + "/offer",
		"subject_type":  "url",
		"resource_type": "credential_offer_uri",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d (redirect refused), got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestResolve_CredentialOfferURI_ResponseTooLarge(t *testing.T) {
	// A response body that exceeds 1MB must be rejected, not silently truncated.
	offerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write 1MB+1 bytes of filler — enough to exceed the cap.
		const limit = 1 << 20
		w.Write(make([]byte, limit+1)) //nolint:errcheck
	}))
	defer offerServer.Close()

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, offerServer.Client(), http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":    offerServer.URL + "/offer",
		"subject_type":  "url",
		"resource_type": "credential_offer_uri",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d (response too large), got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestResolve_UnknownResourceTypeURL_Rejected(t *testing.T) {
	// An unknown resource_type for URL subjects must be rejected with 400,
	// even if the SPOCP authorizer would otherwise permit it. Without this
	// explicit allowlist, an unknown type silently falls through to the
	// credential-issuer resolution path.
	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{},
		},
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, nil, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":    "https://issuer.example.com",
		"subject_type":  "url",
		"resource_type": "totally_unknown_type",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for unknown resource_type, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, tenantLookup, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
		handlerNoLookup := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, nil, http.DefaultClient, http.DefaultClient, logger)
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
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, tenantLookup, nil, nil, http.DefaultClient, http.DefaultClient, logger)

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
		handlerFailOpen := NewAuthZENProxyHandler(cfgFailOpen, &mockAuthorizer{allowAll: true}, tenantLookup, nil, nil, http.DefaultClient, http.DefaultClient, logger)

		url, err := handlerFailOpen.getPDPURL(ctx, "any-tenant")
		if err != nil {
			t.Fatalf("getPDPURL() with fail-open unexpected error: %v", err)
		}
		if url != globalPDPURL {
			t.Errorf("getPDPURL() = %q, want global PDP URL %q", url, globalPDPURL)
		}
	})
}

// ============================================================================
// NewAuthZENProxyHandlerFromConfig Tests
// ============================================================================

func TestNewAuthZENProxyHandlerFromConfig_Disabled(t *testing.T) {
	cfg := &config.Config{
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled: false,
		},
	}
	logger := zap.NewNop()
	handler, err := NewAuthZENProxyHandlerFromConfig(cfg, nil, nil, nil, http.DefaultClient, logger)
	if err != nil {
		t.Errorf("expected no error when disabled, got: %v", err)
	}
	if handler != nil {
		t.Error("expected nil handler when AuthZEN proxy is disabled")
	}
}

func TestNewAuthZENProxyHandlerFromConfig_EnabledNoRulesFile(t *testing.T) {
	// No rules file → SPOCP uses built-in default wallet rules (not an error)
	cfg := &config.Config{
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled: true,
			PDPURL:  "https://pdp.example.com",
			Timeout: 30,
		},
	}
	logger := zap.NewNop()

	handler, err := NewAuthZENProxyHandlerFromConfig(cfg, nil, nil, nil, http.DefaultClient, logger)
	if err != nil {
		t.Errorf("expected no error with no rules file, got: %v", err)
	}
	if handler == nil {
		t.Error("expected non-nil handler")
	}
	// PDP URL should remain set on the config
	if cfg.AuthZENProxy.PDPURL != "https://pdp.example.com" {
		t.Errorf("expected PDPURL to be preserved, got: %s", cfg.AuthZENProxy.PDPURL)
	}
}

func TestNewAuthZENProxyHandlerFromConfig_EnabledBadRulesFile_DebugMode(t *testing.T) {
	// Bad rules file in test mode → uses NoOpAuthorizer (warns but continues)
	cfg := &config.Config{
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled:   true,
			PDPURL:    "https://pdp.example.com",
			Timeout:   30,
			RulesFile: "/nonexistent/path/rules.spocp",
		},
	}
	logger := zap.NewNop()
	// gin.TestMode is set in init(), so the release-mode fail-closed guard won't trigger

	handler, err := NewAuthZENProxyHandlerFromConfig(cfg, nil, nil, nil, http.DefaultClient, logger)
	if err != nil {
		t.Errorf("expected no error in test mode with bad rules file, got: %v", err)
	}
	if handler == nil {
		t.Error("expected non-nil handler (should fall back to NoOpAuthorizer)")
	}
}

func TestNewAuthZENProxyHandlerFromConfig_EnabledBadRulesFile_ReleaseMode(t *testing.T) {
	// Bad rules file in release mode → fail-closed, must return an error
	cfg := &config.Config{
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled:   true,
			PDPURL:    "https://pdp.example.com",
			Timeout:   30,
			RulesFile: "/nonexistent/path/rules.spocp",
		},
	}
	logger := zap.NewNop()

	gin.SetMode(gin.ReleaseMode)
	defer gin.SetMode(gin.TestMode)

	handler, err := NewAuthZENProxyHandlerFromConfig(cfg, nil, nil, nil, http.DefaultClient, logger)
	if err == nil {
		t.Error("expected error in release mode when SPOCP authorizer cannot be initialized")
	}
	if handler != nil {
		t.Error("expected nil handler when initialization fails")
	}
}

func TestNewAuthZENProxyHandlerFromConfig_PDPURLFromAuthZENConfig(t *testing.T) {
	// AuthZENProxy.PDPURL takes precedence over Trust.PDPURL fallback
	cfg := &config.Config{
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled: true,
			PDPURL:  "https://authzen-pdp.example.com",
			Timeout: 30,
		},
		Trust: config.TrustConfig{
			PDPURL: "https://trust-pdp.example.com",
		},
	}
	logger := zap.NewNop()

	handler, err := NewAuthZENProxyHandlerFromConfig(cfg, nil, nil, nil, http.DefaultClient, logger)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	// The config's PDPURL should remain the authzen-specific one
	if cfg.AuthZENProxy.PDPURL != "https://authzen-pdp.example.com" {
		t.Errorf("expected PDPURL from AuthZENProxy config, got: %s", cfg.AuthZENProxy.PDPURL)
	}
}

func TestNewAuthZENProxyHandlerFromConfig_PDPURLFallbackFromTrust(t *testing.T) {
	// When AuthZENProxy.PDPURL is empty, PDPURL should be resolved from Trust.PDPURL
	cfg := &config.Config{
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled: true,
			PDPURL:  "", // empty – should fall back to Trust
			Timeout: 30,
		},
		Trust: config.TrustConfig{
			PDPURL: "https://trust-pdp.example.com",
		},
	}
	logger := zap.NewNop()

	handler, err := NewAuthZENProxyHandlerFromConfig(cfg, nil, nil, nil, http.DefaultClient, logger)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	// After init, the config's PDPURL should be updated to the Trust fallback
	if cfg.AuthZENProxy.PDPURL != "https://trust-pdp.example.com" {
		t.Errorf("expected PDPURL to fall back to Trust.PDPURL, got: %s", cfg.AuthZENProxy.PDPURL)
	}
}

func TestNewAuthZENProxyHandlerFromConfig_SetsDefaultTimeout(t *testing.T) {
	// Verify SetDefaults is called: a zero timeout should be set to 30
	cfg := &config.Config{
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled: true,
			PDPURL:  "https://pdp.example.com",
			Timeout: 0, // should be set to 30 by SetDefaults
		},
	}
	logger := zap.NewNop()

	handler, err := NewAuthZENProxyHandlerFromConfig(cfg, nil, nil, nil, http.DefaultClient, logger)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if cfg.AuthZENProxy.Timeout != 30 {
		t.Errorf("expected Timeout to be set to 30 by SetDefaults, got: %d", cfg.AuthZENProxy.Timeout)
	}
}

func TestNewAuthZENProxyHandlerFromConfig_WithTenantLookup(t *testing.T) {
	// Verify the tenant lookup is wired through to the handler
	tenantLookup := &mockTenantLookup{
		tenants: map[domain.TenantID]*domain.Tenant{
			"custom-tenant": {
				ID:   "custom-tenant",
				Name: "Custom Tenant",
				TrustConfig: domain.TrustConfig{
					PDPURL: "https://tenant-pdp.example.com",
				},
			},
		},
	}
	cfg := &config.Config{
		AuthZENProxy: config.AuthZENProxyConfig{
			Enabled: true,
			PDPURL:  "https://global-pdp.example.com",
			Timeout: 30,
		},
	}
	logger := zap.NewNop()

	handler, err := NewAuthZENProxyHandlerFromConfig(cfg, tenantLookup, nil, nil, http.DefaultClient, logger)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	// The handler should use the per-tenant PDP URL for "custom-tenant"
	pdpURL, err := handler.getPDPURL(context.Background(), "custom-tenant")
	if err != nil {
		t.Fatalf("getPDPURL() unexpected error: %v", err)
	}
	if pdpURL != "https://tenant-pdp.example.com" {
		t.Errorf("expected per-tenant PDP URL, got: %s", pdpURL)
	}
}

// ============================================================================
// URL Subject Resolution Tests
// ============================================================================

// mockMetadataResolver implements IssuerMetadataResolver for testing
type mockMetadataResolver struct {
	result *issuermetadata.ResolveResult
	err    error
}

func (m *mockMetadataResolver) ResolveWithInfo(ctx context.Context, issuerURL string) (*issuermetadata.ResolveResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestResolve_URLSubject_LocalResolution(t *testing.T) {
	// Mock PDP that returns a trust decision
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req gotrust.EvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify the PDP receives a key-based request (not URL)
		if req.Subject.Type != "key" {
			t.Errorf("expected PDP to receive subject.type='key', got '%s'", req.Subject.Type)
		}
		if req.Resource.Type != "jwk" {
			t.Errorf("expected resource.type='jwk', got '%s'", req.Resource.Type)
		}
		if len(req.Resource.Key) == 0 {
			t.Error("expected non-empty resource.key")
		}

		resp := gotrust.EvaluationResponse{Decision: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	pdpServer := httptest.NewServer(pdpHandler)
	defer pdpServer.Close()

	metadata := map[string]interface{}{
		"credential_issuer":   "https://issuer.example.com",
		"credential_endpoint": "https://issuer.example.com/credential",
		"jwks": map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "test-x",
					"y":   "test-y",
				},
			},
		},
		"display": []interface{}{
			map[string]interface{}{
				"name": "Test Issuer",
			},
		},
	}

	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: metadata,
		},
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Set("user_id", "test-user")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":   "https://issuer.example.com",
		"subject_type": "url",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp gotrust.EvaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if !resp.Decision {
		t.Error("expected decision=true")
	}
	if resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("expected trust_metadata in response")
	}

	// Verify metadata is returned
	tm, ok := resp.Context.TrustMetadata.(map[string]interface{})
	if !ok {
		t.Fatal("expected trust_metadata to be a map")
	}
	if tm["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("expected credential_issuer in metadata, got: %v", tm["credential_issuer"])
	}
}

func TestResolve_URLSubject_Untrusted(t *testing.T) {
	// Unsigned metadata that is untrusted: should still return metadata with decision=false.
	// Logos are inlined because metadata is unsigned (display-only, no trust claim).
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := gotrust.EvaluationResponse{Decision: false}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	pdpServer := httptest.NewServer(pdpHandler)
	defer pdpServer.Close()

	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{
				"credential_issuer": "https://untrusted.example.com",
				"jwks": map[string]interface{}{
					"keys": []interface{}{map[string]interface{}{"kty": "EC"}},
				},
			},
		},
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":   "https://untrusted.example.com",
		"subject_type": "url",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp gotrust.EvaluationResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Decision {
		t.Error("expected decision=false for untrusted issuer")
	}
	// Metadata should still be returned even when untrusted
	if resp.Context == nil || resp.Context.TrustMetadata == nil {
		t.Fatal("expected trust_metadata even for untrusted issuer")
	}
}

func TestResolve_URLSubject_MetadataResolutionFailure(t *testing.T) {
	resolver := &mockMetadataResolver{
		err: fmt.Errorf("connection refused"),
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          "http://pdp.example.com",
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":   "https://broken.example.com",
		"subject_type": "url",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestResolve_URLSubject_LogoInlining(t *testing.T) {
	// Serve a test logo image over TLS — logo inlining requires HTTPS.
	logoServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write([]byte("fake-png-data"))
	}))
	defer logoServer.Close()

	// Mock PDP that returns trusted
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := gotrust.EvaluationResponse{Decision: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	pdpServer := httptest.NewServer(pdpHandler)
	defer pdpServer.Close()

	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Metadata: map[string]interface{}{
				"credential_issuer": "https://issuer.example.com",
				"jwks": map[string]interface{}{
					"keys": []interface{}{map[string]interface{}{"kty": "EC"}},
				},
				"display": []interface{}{
					map[string]interface{}{
						"name": "Test Issuer",
						"logo": map[string]interface{}{
							"uri": logoServer.URL + "/logo.png",
						},
					},
				},
				"credential_configurations_supported": map[string]interface{}{
					"pid": map[string]interface{}{
						"format": "vc+sd-jwt",
						"display": []interface{}{
							map[string]interface{}{
								"name": "Personal ID",
								"logo": map[string]interface{}{
									"uri": logoServer.URL + "/cred-logo.png",
								},
							},
						},
					},
				},
			},
		},
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	// Use the TLS server's client so the handler can fetch HTTPS logo URLs.
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, logoServer.Client(), logoServer.Client(), logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":   "https://issuer.example.com",
		"subject_type": "url",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp gotrust.EvaluationResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !resp.Decision {
		t.Fatal("expected decision=true")
	}

	// Check that logos were inlined as data: URIs
	tm := resp.Context.TrustMetadata.(map[string]interface{})
	display := tm["display"].([]interface{})
	d0 := display[0].(map[string]interface{})
	logo := d0["logo"].(map[string]interface{})
	logoURI := logo["uri"].(string)
	if !strings.HasPrefix(logoURI, "data:image/png;base64,") {
		t.Errorf("expected inlined data: URI for top-level logo, got: %s", logoURI)
	}

	// Check credential configuration logo
	ccs := tm["credential_configurations_supported"].(map[string]interface{})
	pid := ccs["pid"].(map[string]interface{})
	credDisplay := pid["display"].([]interface{})
	cd0 := credDisplay[0].(map[string]interface{})
	credLogo := cd0["logo"].(map[string]interface{})
	credLogoURI := credLogo["uri"].(string)
	if !strings.HasPrefix(credLogoURI, "data:image/png;base64,") {
		t.Errorf("expected inlined data: URI for credential logo, got: %s", credLogoURI)
	}
}

func TestResolve_KeySubject_ProxiesToPDP(t *testing.T) {
	// For key subjects, should proxy directly to PDP (no local resolution)
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req gotrust.EvaluationRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Key subjects should be proxied with subject_type="key"
		if req.Subject.Type != "key" {
			t.Errorf("expected subject.type='key', got '%s'", req.Subject.Type)
		}

		resp := gotrust.EvaluationResponse{
			Decision: true,
			Context: &gotrust.EvaluationResponseContext{
				TrustMetadata: map[string]interface{}{"from": "pdp"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	pdpServer := httptest.NewServer(pdpHandler)
	defer pdpServer.Close()

	// Provide a resolver that should NOT be called for key subjects
	resolver := &mockMetadataResolver{
		err: fmt.Errorf("resolver should not be called for key subjects"),
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id": "https://entity.example.com",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp gotrust.EvaluationResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !resp.Decision {
		t.Error("expected decision=true")
	}
}

func TestResolve_URLSubject_SignedMetadata_VerificationFailed_Error(t *testing.T) {
	// When metadata contains a signed_metadata field whose JWT has an embedded
	// key (x5c/jwk) but verification fails, the handler must reject immediately
	// with 502 rather than forwarding potentially misleading unverified data.
	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := gotrust.EvaluationResponse{Decision: false}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	pdpServer := httptest.NewServer(pdpHandler)
	defer pdpServer.Close()

	// Use a JWT with a jwk header (embedded key present) but an invalid signature
	// so that VerifyJWTWithEmbeddedKey returns a verification failure.
	fakeJWKHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}}`))
	fakeJWT := fakeJWKHeader + ".fake-payload.fake-signature"

	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{
			Signed: true,
			Metadata: map[string]interface{}{
				"credential_issuer": "https://signed-untrusted.example.com",
				"signed_metadata":   fakeJWT,
			},
		},
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":   "https://signed-untrusted.example.com",
		"subject_type": "url",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected status %d for unverifiable signed_metadata JWT, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

// mockIssuerLookup implements IssuerLookup for testing.
type mockIssuerLookup struct {
	issuer *domain.CredentialIssuer
	err    error
}

func (m *mockIssuerLookup) GetByIdentifier(_ context.Context, _ domain.TenantID, _ string) (*domain.CredentialIssuer, error) {
	return m.issuer, m.err
}

func TestResolve_URLSubject_RegisteredIssuerInfo_IncludedWhenFound(t *testing.T) {
	// When an issuer is registered in the backend storage, /v1/resolve should
	// include its registration info (e.g. client_id) in the response as
	// registered_issuer — separate from trust_metadata.
	pdpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := gotrust.EvaluationResponse{Decision: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer pdpServer.Close()

	metadata := map[string]interface{}{
		"credential_issuer": "https://issuer.example.com",
	}
	resolver := &mockMetadataResolver{result: &issuermetadata.ResolveResult{Metadata: metadata}}

	registeredIssuer := &domain.CredentialIssuer{
		CredentialIssuerIdentifier: "https://issuer.example.com",
		ClientID:                   "my-client-id",
		Visible:                    true,
		TrustStatus:                domain.TrustStatus("trusted"),
		TrustFramework:             "EUCS",
	}
	issuerLookup := &mockIssuerLookup{issuer: registeredIssuer}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, issuerLookup, resolver, http.DefaultClient, http.DefaultClient, zap.NewNop())

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":   "https://issuer.example.com",
		"subject_type": "url",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	reg, ok := resp["registered_issuer"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected registered_issuer in response, got: %v", resp["registered_issuer"])
	}
	if reg["client_id"] != "my-client-id" {
		t.Errorf("expected client_id=my-client-id, got: %v", reg["client_id"])
	}
	if reg["trust_framework"] != "EUCS" {
		t.Errorf("expected trust_framework=EUCS, got: %v", reg["trust_framework"])
	}
	if reg["visible"] != true {
		t.Errorf("expected visible=true, got: %v", reg["visible"])
	}

	// trust_metadata should still be present and unchanged
	ctx, ok := resp["context"].(map[string]interface{})
	if !ok {
		t.Fatal("expected context in response")
	}
	if ctx["trust_metadata"] == nil {
		t.Error("expected trust_metadata in context")
	}
}

func TestResolve_URLSubject_RegisteredIssuerInfo_OmittedWhenNotFound(t *testing.T) {
	// When the issuer is not registered in backend storage, registered_issuer
	// should be absent from the response.
	pdpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := gotrust.EvaluationResponse{Decision: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer pdpServer.Close()

	metadata := map[string]interface{}{
		"credential_issuer": "https://unknown-issuer.example.com",
	}
	resolver := &mockMetadataResolver{result: &issuermetadata.ResolveResult{Metadata: metadata}}
	issuerLookup := &mockIssuerLookup{issuer: nil, err: nil}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, issuerLookup, resolver, http.DefaultClient, http.DefaultClient, zap.NewNop())

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]string{
		"subject_id":   "https://unknown-issuer.example.com",
		"subject_type": "url",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if _, exists := resp["registered_issuer"]; exists {
		t.Errorf("expected registered_issuer to be absent, got: %v", resp["registered_issuer"])
	}
}

func TestResolve_URLSubject_CredentialTypes_ForwardedToPDP(t *testing.T) {
	// Verify that credential_types from the resolve request are forwarded
	// to the PDP as action.parameters.credential_types.
	var receivedReq gotrust.EvaluationRequest

	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedReq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Return a response with credential_type_trust_marks in reason
		resp := gotrust.EvaluationResponse{
			Decision: true,
			Context: &gotrust.EvaluationResponseContext{
				Reason: map[string]interface{}{
					"credential_types": []interface{}{"eu.europa.ec.eudi.pid.1"},
					"credential_type_trust_marks": map[string]interface{}{
						"eu.europa.ec.eudi.pid.1": []interface{}{"http://registry.example.com/tm/pid"},
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	})

	pdpServer := httptest.NewServer(pdpHandler)
	defer pdpServer.Close()

	metadata := map[string]interface{}{
		"credential_issuer":   "https://issuer.example.com",
		"credential_endpoint": "https://issuer.example.com/credential",
		"jwks": map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "test-x",
					"y":   "test-y",
				},
			},
		},
	}

	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{Metadata: metadata},
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Set("user_id", "test-user")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]interface{}{
		"subject_id":       "https://issuer.example.com",
		"subject_type":     "url",
		"credential_types": []string{"eu.europa.ec.eudi.pid.1"},
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify credential_types were forwarded to PDP in action.parameters
	if receivedReq.Action == nil {
		t.Fatal("expected action to be set in PDP request")
	}
	if receivedReq.Action.Name != "credential-issuer" {
		t.Errorf("expected action.name='credential-issuer', got '%s'", receivedReq.Action.Name)
	}
	if receivedReq.Action.Parameters == nil {
		t.Fatal("expected action.parameters to be set")
	}
	ct, ok := receivedReq.Action.Parameters["credential_types"]
	if !ok {
		t.Fatal("expected credential_types in action.parameters")
	}
	ctSlice, ok := ct.([]interface{})
	if !ok {
		t.Fatalf("expected credential_types to be a slice, got %T", ct)
	}
	if len(ctSlice) != 1 || ctSlice[0] != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("unexpected credential_types: %v", ctSlice)
	}

	// Verify credential_type_trust_marks is returned in response
	var resp gotrust.EvaluationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Context == nil || resp.Context.Reason == nil {
		t.Fatal("expected context.reason in response")
	}
	if _, ok := resp.Context.Reason["credential_type_trust_marks"]; !ok {
		t.Error("expected credential_type_trust_marks in response reason")
	}
}

func TestResolve_URLSubject_NoCredentialTypes_OmitsParameters(t *testing.T) {
	// When credential_types is not provided, action.parameters should be nil.
	var receivedReq gotrust.EvaluationRequest

	pdpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedReq) //nolint:errcheck
		resp := gotrust.EvaluationResponse{Decision: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	})

	pdpServer := httptest.NewServer(pdpHandler)
	defer pdpServer.Close()

	metadata := map[string]interface{}{
		"credential_issuer":   "https://issuer.example.com",
		"credential_endpoint": "https://issuer.example.com/credential",
		"jwks": map[string]interface{}{
			"keys": []interface{}{
				map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "test-x", "y": "test-y"},
			},
		},
	}

	resolver := &mockMetadataResolver{
		result: &issuermetadata.ResolveResult{Metadata: metadata},
	}

	cfg := &config.AuthZENProxyConfig{
		Enabled:         true,
		PDPURL:          pdpServer.URL,
		Timeout:         30,
		AllowResolution: true,
	}
	logger := zap.NewNop()
	handler := NewAuthZENProxyHandler(cfg, &mockAuthorizer{allowAll: true}, nil, nil, resolver, http.DefaultClient, http.DefaultClient, logger)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "test-tenant")
		c.Set("user_id", "test-user")
		c.Next()
	})
	router.POST("/v1/resolve", handler.Resolve)

	body, _ := json.Marshal(map[string]interface{}{
		"subject_id":   "https://issuer.example.com",
		"subject_type": "url",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify action.parameters is nil when no credential_types provided
	if receivedReq.Action == nil {
		t.Fatal("expected action to be set")
	}
	if receivedReq.Action.Parameters != nil {
		t.Errorf("expected nil action.parameters when no credential_types, got: %v", receivedReq.Action.Parameters)
	}
}
