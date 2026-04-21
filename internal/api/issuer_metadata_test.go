package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/metadata"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func setupIssuerMetadataTest(t *testing.T) (*Handlers, *gin.Engine, *memory.Store) {
	t.Helper()
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
	}

	store := memory.NewStore()
	services := service.NewServices(store, cfg, logger)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	router := gin.New()
	// Mock auth middleware
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "default")
		c.Set("user_id", "test-user")
		c.Next()
	})
	router.GET("/issuer/:id/metadata", handlers.GetIssuerMetadata)

	return handlers, router, store
}

func TestGetIssuerMetadata_InvalidID(t *testing.T) {
	_, router, _ := setupIssuerMetadataTest(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuer/abc/metadata", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestGetIssuerMetadata_NotFound(t *testing.T) {
	_, router, _ := setupIssuerMetadataTest(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuer/999/metadata", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestGetIssuerMetadata_Success(t *testing.T) {
	// Start a mock issuer metadata server
	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-credential-issuer" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"credential_issuer":   "https://issuer.example.com",
				"credential_endpoint": "https://issuer.example.com/credential",
				"credential_configurations_supported": map[string]interface{}{
					"UniversityDegree": map[string]interface{}{
						"format": "jwt_vc_json",
					},
				},
			})
		} else {
			http.NotFound(w, r)
		}
	}))
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)

	// Create a tenant and issuer pointing to our mock server
	ctx := context.Background()
	store.Tenants().Create(ctx, &domain.Tenant{
		ID:      "default",
		Name:    "Default",
		Enabled: true,
	})
	issuer := &domain.CredentialIssuer{
		TenantID:                   "default",
		CredentialIssuerIdentifier: mockIssuer.URL,
		Visible:                    true,
	}
	if err := store.Issuers().Create(ctx, issuer); err != nil {
		t.Fatal(err)
	}
	issuerID := issuer.ID

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// The response should be the IssuerMetadata directly with proper JSON keys
	if result["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("Expected credential_issuer, got %v", result["credential_issuer"])
	}
}

func TestGetIssuerMetadata_CachesResponses(t *testing.T) {
	callCount := 0
	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":   "https://issuer.example.com",
			"credential_endpoint": "https://issuer.example.com/credential",
		})
	}))
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)

	ctx := context.Background()
	store.Tenants().Create(ctx, &domain.Tenant{
		ID:      "default",
		Name:    "Default",
		Enabled: true,
	})
	issuer := &domain.CredentialIssuer{
		TenantID:                   "default",
		CredentialIssuerIdentifier: mockIssuer.URL,
		Visible:                    true,
	}
	store.Issuers().Create(ctx, issuer)

	path := fmt.Sprintf("/issuer/%d/metadata", issuer.ID)

	// First request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("First request: expected %d, got %d", http.StatusOK, w.Code)
	}

	// Second request — should be cached
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("Second request: expected %d, got %d", http.StatusOK, w2.Code)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 upstream call (cached), got %d", callCount)
	}
}

func TestGetIssuerMetadata_UpstreamError(t *testing.T) {
	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)

	ctx := context.Background()
	store.Tenants().Create(ctx, &domain.Tenant{
		ID:      "default",
		Name:    "Default",
		Enabled: true,
	})
	issuer := &domain.CredentialIssuer{
		TenantID:                   "default",
		CredentialIssuerIdentifier: mockIssuer.URL,
		Visible:                    true,
	}
	store.Issuers().Create(ctx, issuer)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuer.ID), nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestGetIssuerMetadata_CrossTenantBlocked(t *testing.T) {
	_, router, store := setupIssuerMetadataTest(t)

	ctx := context.Background()
	// Create two tenants
	store.Tenants().Create(ctx, &domain.Tenant{
		ID: "default", Name: "Default", Enabled: true,
	})
	store.Tenants().Create(ctx, &domain.Tenant{
		ID: "other-tenant", Name: "Other", Enabled: true,
	})

	// Create issuer under "other-tenant" (not "default")
	issuer := &domain.CredentialIssuer{
		TenantID:                   "other-tenant",
		CredentialIssuerIdentifier: "https://issuer.example.com",
		Visible:                    true,
	}
	store.Issuers().Create(ctx, issuer)

	// Auth middleware sets tenant_id="default", so this issuer should not be found
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuer.ID), nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d (cross-tenant), got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestIssuerMetadataCache(t *testing.T) {
	cache := newIssuerMetadataCache()

	// Miss on empty cache
	_, ok := cache.get("https://example.com")
	if ok {
		t.Error("Expected cache miss")
	}

	// Put and hit
	m := &metadata.IssuerMetadata{
		CredentialIssuer: "https://example.com",
	}
	cache.put("https://example.com", m)

	cached, ok := cache.get("https://example.com")
	if !ok {
		t.Fatal("Expected cache hit")
	}
	if cached != m {
		t.Error("Cached result does not match")
	}
}
