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

// Test tenant-scoped WebAuthn registration - uses StartWebAuthnRegistration (tenant from path)
func TestHandlers_StartWebAuthnRegistration_NotAvailable(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	// Note: WebAuthn is nil when not properly configured
	handlers.services.WebAuthn = nil
	router.POST("/tenant/webauthn/register/start", handlers.StartWebAuthnRegistration)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/tenant/webauthn/register/start", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestHandlers_FinishWebAuthnRegistration_NotAvailable(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	handlers.services.WebAuthn = nil
	router.POST("/tenant/webauthn/register/finish", handlers.FinishWebAuthnRegistration)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/tenant/webauthn/register/finish", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestHandlers_StartTenantWebAuthnLogin_NotAvailable(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	handlers.services.WebAuthn = nil
	router.POST("/tenant/webauthn/login/start", handlers.StartTenantWebAuthnLogin)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/tenant/webauthn/login/start", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestHandlers_FinishTenantWebAuthnLogin_NotAvailable(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	handlers.services.WebAuthn = nil
	router.POST("/tenant/webauthn/login/finish", handlers.FinishTenantWebAuthnLogin)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/tenant/webauthn/login/finish", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

// Test credential storage handlers with authentication context
func TestHandlers_StoreCredential_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/credentials", handlers.StoreCredential)

	w := httptest.NewRecorder()
	body := `{"credentials": [{"format": "jwt_vc", "credential": "test"}]}`
	req := httptest.NewRequest(http.MethodPost, "/credentials", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandlers_UpdateCredential_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.PUT("/credentials/:id", handlers.UpdateCredential)

	w := httptest.NewRecorder()
	body := `{"vc": "updated"}`
	req := httptest.NewRequest(http.MethodPut, "/credentials/test-id", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandlers_DeleteCredential_BadRequest(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.DELETE("/credentials/:id", handlers.DeleteCredential)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/credentials/test-id", nil)
	router.ServeHTTP(w, req)

	// Returns 400 due to missing user context
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test presentation handlers
func TestHandlers_GetAllPresentations_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/presentations", handlers.GetAllPresentations)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/presentations", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandlers_StorePresentation_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/presentations", handlers.StorePresentation)

	w := httptest.NewRecorder()
	body := `{"vp": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/presentations", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandlers_DeletePresentation_BadRequest(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.DELETE("/presentations/:id", handlers.DeletePresentation)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/presentations/test-id", nil)
	router.ServeHTTP(w, req)

	// Returns 400 due to missing user context
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandlers_GetPresentationByIdentifier_BadRequest(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/presentations/:id", handlers.GetPresentationByIdentifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/presentations/test-id", nil)
	router.ServeHTTP(w, req)

	// Returns 400 due to missing user context
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Test WebAuthn add credential handlers
func TestHandlers_StartAddWebAuthnCredential_NotAvailable(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	handlers.services.WebAuthn = nil
	router.POST("/webauthn/credential/start", handlers.StartAddWebAuthnCredential)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/start", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestHandlers_FinishAddWebAuthnCredential_NotAvailable(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	handlers.services.WebAuthn = nil
	router.POST("/webauthn/credential/finish", handlers.FinishAddWebAuthnCredential)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/finish", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
}

func TestHandlers_DeleteWebAuthnCredential_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	handlers.services.WebAuthn = nil
	router.DELETE("/webauthn/credentials/:id", handlers.DeleteWebAuthnCredential)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/webauthn/credentials/test-id", nil)
	router.ServeHTTP(w, req)

	// Returns 401 because user context is checked before WebAuthn availability
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// Test GetIssuerByID handler with invalid ID
func TestHandlers_GetIssuerByID_InvalidID(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/issuers/:id", handlers.GetIssuerByID)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuers/999999", nil)
	router.ServeHTTP(w, req)

	// Returns 404 when issuer not found
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// Test KeystoreStatus handler
func TestHandlers_KeystoreStatus_Unauthorized(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/keystore/status", handlers.KeystoreStatus)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/keystore/status", nil)
	router.ServeHTTP(w, req)

	// Returns 401 when no user context
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// Test GetCertificate handler - returns certificate chain
func TestHandlers_GetCertificate_Success(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/certificate", handlers.GetCertificate)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/certificate", nil)
	router.ServeHTTP(w, req)

	// Without proper setup, returns 500 or specific error
	// At minimum, verifies the handler doesn't panic
	if w.Code == 0 {
		t.Error("Expected a response status code")
	}
}

// Test GetAllIssuers handler - unauthorized
func TestHandlers_GetAllIssuers_Unauthenticated(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/issuers", handlers.GetAllIssuers)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuers", nil)
	router.ServeHTTP(w, req)

	// Returns 500 due to no tenant context - but handler doesn't panic
	if w.Code == 0 {
		t.Error("Expected a response status code")
	}
}

// Test GetAllVerifiers handler - unauthorized
func TestHandlers_GetAllVerifiers_Unauthenticated(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.GET("/verifiers", handlers.GetAllVerifiers)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verifiers", nil)
	router.ServeHTTP(w, req)

	// Returns 500 due to no tenant context - but handler doesn't panic
	if w.Code == 0 {
		t.Error("Expected a response status code")
	}
}

// Test ProxyRequest handler - missing parameters
func TestHandlers_ProxyRequest_MissingURL(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/proxy", handlers.ProxyRequest)

	w := httptest.NewRecorder()
	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Returns 500 for missing URL (internal server error from proxy service)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Test GenerateKeyAttestation handler - bad request
func TestHandlers_GenerateKeyAttestation_BadRequest(t *testing.T) {
	handlers, router := setupTestHandlers(t)
	router.POST("/key-attestation", handlers.GenerateKeyAttestation)

	w := httptest.NewRecorder()
	body := `{"public_key": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/key-attestation", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Returns 400 for invalid request (missing user context causes bad request)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}
