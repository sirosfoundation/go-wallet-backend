package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestHandlers_Status_ContainsAPIVersion(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/status", handlers.Status)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify api_version is present and correct
	apiVersion, ok := response["api_version"]
	if !ok {
		t.Error("Expected api_version field in status response")
	}

	// api_version is returned as a number in JSON, which becomes float64
	if apiVersionFloat, ok := apiVersion.(float64); ok {
		if int(apiVersionFloat) != CurrentAPIVersion {
			t.Errorf("Expected api_version '%d', got '%v'", CurrentAPIVersion, apiVersion)
		}
	} else {
		t.Errorf("Expected api_version to be a number, got %T", apiVersion)
	}
}

func TestCurrentAPIVersion(t *testing.T) {
	// Verify the current API version is 2
	if CurrentAPIVersion != 2 {
		t.Errorf("Expected CurrentAPIVersion to be 2, got '%d'", CurrentAPIVersion)
	}
}

func setupDiscoverTrustTestHandlers(t *testing.T) (*Handlers, *gin.Engine) {
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
	handlers := NewHandlers(services, cfg, logger)

	router := gin.New()
	return handlers, router
}

func TestDiscoverAndTrust_MissingEntityIdentifier(t *testing.T) {
	handlers, router := setupDiscoverTrustTestHandlers(t)
	router.POST("/api/discover-and-trust", handlers.DiscoverAndTrust)

	reqBody := DiscoverAndTrustRequest{
		Role: "issuer",
		// Missing entity_identifier
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/discover-and-trust", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestDiscoverAndTrust_MissingRole(t *testing.T) {
	handlers, router := setupDiscoverTrustTestHandlers(t)
	router.POST("/api/discover-and-trust", handlers.DiscoverAndTrust)

	reqBody := map[string]string{
		"entity_identifier": "https://issuer.example.com",
		// Missing role
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/discover-and-trust", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestDiscoverAndTrust_InvalidRole(t *testing.T) {
	handlers, router := setupDiscoverTrustTestHandlers(t)
	router.POST("/api/discover-and-trust", handlers.DiscoverAndTrust)

	reqBody := map[string]string{
		"entity_identifier": "https://issuer.example.com",
		"role":              "invalid_role",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/discover-and-trust", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestDiscoverAndTrust_ValidIssuerRequest(t *testing.T) {
	handlers, router := setupDiscoverTrustTestHandlers(t)
	router.POST("/api/discover-and-trust", handlers.DiscoverAndTrust)

	reqBody := DiscoverAndTrustRequest{
		EntityIdentifier: "https://issuer.example.com",
		Role:             "issuer",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/discover-and-trust", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// The endpoint should return OK even if discovery fails (with appropriate status)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response DiscoverAndTrustResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response structure
	if response.DiscoveryStatus == "" {
		t.Error("Expected discovery_status to be set")
	}

	// Since we don't have a real issuer, discovery should fail but gracefully
	if response.DiscoveryStatus != "failed" {
		t.Logf("Discovery status: %s", response.DiscoveryStatus)
	}
}

func TestDiscoverAndTrust_ValidVerifierRequest(t *testing.T) {
	handlers, router := setupDiscoverTrustTestHandlers(t)
	router.POST("/api/discover-and-trust", handlers.DiscoverAndTrust)

	reqBody := DiscoverAndTrustRequest{
		EntityIdentifier: "https://verifier.example.com",
		Role:             "verifier",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/discover-and-trust", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// The endpoint should return OK even if discovery fails (with appropriate status)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response DiscoverAndTrustResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response structure
	if response.DiscoveryStatus == "" {
		t.Error("Expected discovery_status to be set")
	}
}

func TestDiscoverAndTrust_WithCredentialType(t *testing.T) {
	handlers, router := setupDiscoverTrustTestHandlers(t)
	router.POST("/api/discover-and-trust", handlers.DiscoverAndTrust)

	reqBody := DiscoverAndTrustRequest{
		EntityIdentifier: "https://issuer.example.com",
		Role:             "issuer",
		CredentialType:   "eu.europa.ec.eudi.pid.1",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/discover-and-trust", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestDiscoverAndTrustRequest_JSONBinding(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		expectError bool
	}{
		{
			name:        "valid issuer request",
			json:        `{"entity_identifier":"https://issuer.example.com","role":"issuer"}`,
			expectError: false,
		},
		{
			name:        "valid verifier request",
			json:        `{"entity_identifier":"https://verifier.example.com","role":"verifier"}`,
			expectError: false,
		},
		{
			name:        "valid request with credential_type",
			json:        `{"entity_identifier":"https://issuer.example.com","role":"issuer","credential_type":"eu.europa.ec.eudi.pid.1"}`,
			expectError: false,
		},
		{
			name:        "missing entity_identifier",
			json:        `{"role":"issuer"}`,
			expectError: true,
		},
		{
			name:        "missing role",
			json:        `{"entity_identifier":"https://issuer.example.com"}`,
			expectError: true,
		},
		{
			name:        "invalid role",
			json:        `{"entity_identifier":"https://issuer.example.com","role":"admin"}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlers, router := setupDiscoverTrustTestHandlers(t)
			router.POST("/api/discover-and-trust", handlers.DiscoverAndTrust)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/discover-and-trust", bytes.NewBufferString(tt.json))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			if tt.expectError {
				if w.Code != http.StatusBadRequest {
					t.Errorf("Expected status %d for invalid input, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
				}
			} else {
				if w.Code == http.StatusBadRequest {
					t.Errorf("Expected valid request to not return 400, got: %s", w.Body.String())
				}
			}
		})
	}
}

func TestDiscoverAndTrustResponse_Structure(t *testing.T) {
	handlers, router := setupDiscoverTrustTestHandlers(t)
	router.POST("/api/discover-and-trust", handlers.DiscoverAndTrust)

	reqBody := DiscoverAndTrustRequest{
		EntityIdentifier: "https://issuer.example.com",
		Role:             "issuer",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/discover-and-trust", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify the response can be unmarshaled into DiscoverAndTrustResponse
	var response DiscoverAndTrustResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response into DiscoverAndTrustResponse: %v", err)
	}

	// Verify required fields are present
	// trusted should be a boolean (could be true or false)
	// reason should be a string
	// discovery_status should be one of: success, partial, failed

	validStatuses := map[string]bool{"success": true, "partial": true, "failed": true}
	if !validStatuses[response.DiscoveryStatus] {
		t.Errorf("Invalid discovery_status: %s", response.DiscoveryStatus)
	}
}
