package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestHandlers(t *testing.T) (*Handlers, *gin.Engine) {
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

func TestNewHandlers(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{}
	store := memory.NewStore()
	services := service.NewServices(store, cfg, logger)

	handlers := NewHandlers(services, cfg, logger)

	if handlers == nil {
		t.Fatal("Expected handlers to not be nil")
	}
}

func TestHandlers_Status(t *testing.T) {
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

	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %v", response["status"])
	}

	if response["service"] != "wallet-backend" {
		t.Errorf("Expected service 'wallet-backend', got %v", response["service"])
	}
}

// TestHandlers_RegisterUser_Deprecated verifies password-based registration is deprecated
func TestHandlers_RegisterUser_Deprecated(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/register", handlers.RegisterUser)

	username := "testuser"
	password := "testpassword123"
	reqBody := domain.RegisterRequest{
		Username:    &username,
		Password:    &password,
		DisplayName: "Test User",
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Password-based registration is deprecated - expect 410 Gone
	if w.Code != http.StatusGone {
		t.Errorf("Expected status %d (Gone), got %d: %s", http.StatusGone, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["error"] == nil {
		t.Error("Expected error message in response")
	}

	if response["message"] == nil {
		t.Error("Expected migration message in response")
	}
}

// TestHandlers_LoginUser_Deprecated verifies password-based login is deprecated
func TestHandlers_LoginUser_Deprecated(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/login", handlers.LoginUser)

	loginReq := domain.LoginRequest{
		Username: "testuser",
		Password: "testpassword123",
	}
	body, _ := json.Marshal(loginReq)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Password-based login is deprecated - expect 410 Gone
	if w.Code != http.StatusGone {
		t.Errorf("Expected status %d (Gone), got %d: %s", http.StatusGone, w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["error"] == nil {
		t.Error("Expected error message in response")
	}

	if response["message"] == nil {
		t.Error("Expected migration message in response")
	}
}

// Test WebAuthn handlers
func TestHandlers_WebAuthn(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/webauthn/register/start", handlers.StartWebAuthnRegistration)
	router.POST("/webauthn/register/finish", handlers.FinishWebAuthnRegistration)
	router.POST("/webauthn/login/start", handlers.StartWebAuthnLogin)
	router.POST("/webauthn/login/finish", handlers.FinishWebAuthnLogin)

	t.Run("start registration", func(t *testing.T) {
		body := `{"username": "testuser", "displayName": "Test User"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/start", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Should return 200 with credential options
		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("finish registration without valid challenge", func(t *testing.T) {
		// Finish registration without a valid challenge should return 404
		body := `{"challenge_id": "non-existent-challenge", "credential_response": {}}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
		}
	})

	t.Run("start login", func(t *testing.T) {
		// Discoverable login doesn't require username
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/start", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Should return 200 with assertion options
		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("finish login without valid challenge", func(t *testing.T) {
		// Finish login without a valid challenge should return 404
		body := `{"challenge_id": "non-existent-challenge", "assertion_response": {}}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
		}
	})
}

// Test Presentation handlers (now implemented)
func TestHandlers_Presentation_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/presentations", handlers.GetAllPresentations)
	router.POST("/presentations", handlers.StorePresentation)
	router.GET("/presentations/:presentation_identifier", handlers.GetPresentationByIdentifier)

	tests := []struct {
		method   string
		endpoint string
	}{
		{http.MethodGet, "/presentations"},
		{http.MethodPost, "/presentations"},
		{http.MethodGet, "/presentations/123"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.endpoint, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.endpoint, nil)
			router.ServeHTTP(w, req)

			// Requires authentication - should return 401
			if w.Code != http.StatusUnauthorized {
				t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
			}
		})
	}
}

// authMiddleware is a test helper that sets auth context
func authMiddleware(userID, did string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Set("did", did)
		c.Next()
	}
}

// Test Credential handlers (now implemented)
func TestHandlers_StoreCredential_Success(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/credentials", authMiddleware("user-123", "did:example:123"), handlers.StoreCredential)

	// Use batch format as per reference implementation
	reqBody := struct {
		Credentials []domain.StoreCredentialRequest `json:"credentials"`
	}{
		Credentials: []domain.StoreCredentialRequest{
			{
				CredentialIdentifier: "cred-001",
				Credential:           `{"type": "VerifiableCredential"}`,
				Format:               domain.FormatJWTVC,
			},
		},
	}
	body, _ := json.Marshal(reqBody)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/credentials", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestHandlers_StoreCredential_InvalidJSON(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/credentials", authMiddleware("user-123", "did:example:123"), handlers.StoreCredential)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/credentials", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandlers_GetAllCredentials_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/credentials", handlers.GetAllCredentials)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/credentials", nil)
	router.ServeHTTP(w, req)

	// Should return 401 when not authenticated
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandlers_GetCredentialByIdentifier_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/credentials/:credential_identifier", handlers.GetCredentialByIdentifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/credentials/test-id", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// Test Issuer/Verifier handlers (now implemented)
func TestHandlers_IssuerVerifier_Success(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/issuers", handlers.GetAllIssuers)
	router.GET("/verifiers", handlers.GetAllVerifiers)

	tests := []string{"/issuers", "/verifiers"}

	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, endpoint, nil)
			router.ServeHTTP(w, req)

			// These endpoints don't require auth and return empty arrays
			if w.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
			}
		})
	}
}

// Test Proxy handler
func TestHandlers_Proxy(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/proxy", handlers.ProxyRequest)

	// Test with missing URL
	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should return 500 because URL is required
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d for missing URL, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test Certificate handler
func TestHandlers_GetCertificate(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/get-cert", handlers.GetCertificate)

	// Test with missing URL
	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/get-cert", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should return 400 because URL is required
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for missing URL, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test KeyAttestation handler - returns UNSUPPORTED when keys not configured
func TestHandlers_KeyAttestation_NotConfigured(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/attestation", handlers.GenerateKeyAttestation)

	// Valid request format but keys not configured
	body := `{"jwks": [{"kty": "EC"}], "openid4vci": {"nonce": "test-nonce"}}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/attestation", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should return 400 with UNSUPPORTED error when keys not configured
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandlers_KeyAttestation_InvalidRequest(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/attestation", handlers.GenerateKeyAttestation)

	// Empty request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/attestation", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Should return 400 for missing jwks
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Ensure context and uuid imports are used
var _ = context.Background
var _ = uuid.New
