package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/taggedbinary"
)

// setupTestHandlersWithUser creates test handlers and a user for authenticated tests
func setupTestHandlersWithUser(t *testing.T) (*Handlers, *gin.Engine, *domain.User) {
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
	handlers := NewHandlers(services, cfg, logger, "test")

	// Create a test user
	ctx := context.Background()
	displayName := "Test User"
	privateData := []byte(`{"encrypted": "data"}`)
	user := &domain.User{
		UUID:            domain.NewUserID(),
		DID:             "did:key:test123",
		DisplayName:     &displayName,
		PrivateData:     privateData,
		PrivateDataETag: domain.ComputePrivateDataETag(privateData),
		WebauthnCredentials: []domain.WebauthnCredential{
			{
				ID:           "cred-1",
				CredentialID: []byte("credential-id-bytes"),
				PublicKey:    []byte("public-key-bytes"),
				PRFCapable:   true,
				CreatedAt:    time.Now(),
			},
		},
		OpenIDRefreshTokenMaxAge: 3600,
	}
	if err := store.Users().Create(ctx, user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	router := gin.New()
	return handlers, router, user
}

// authMiddlewareForUser creates middleware that sets user context
func authMiddlewareForUser(user *domain.User) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", user.UUID.String())
		c.Set("did", user.DID)
		c.Next()
	}
}

// ====================
// Private Data Tests
// ====================

func TestHandlers_GetPrivateData_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/private-data", authMiddlewareForUser(user), handlers.GetPrivateData)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private-data", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify response contains privateData
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["privateData"] == nil {
		t.Error("Expected privateData in response")
	}

	// Verify X-Private-Data-ETag header is set
	etag := w.Header().Get("X-Private-Data-ETag")
	if etag == "" {
		t.Error("Expected X-Private-Data-ETag header")
	}
}

func TestHandlers_GetPrivateData_Unauthorized(t *testing.T) {
	handlers, router, _ := setupTestHandlersWithUser(t)
	router.GET("/private-data", handlers.GetPrivateData)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private-data", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestHandlers_GetPrivateData_NotModified(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/private-data", authMiddlewareForUser(user), handlers.GetPrivateData)

	// First request to get the ETag
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/private-data", nil)
	router.ServeHTTP(w1, req1)

	etag := w1.Header().Get("X-Private-Data-ETag")
	if etag == "" {
		t.Fatal("Expected X-Private-Data-ETag header")
	}

	// Second request with If-None-Match
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/private-data", nil)
	req2.Header.Set("If-None-Match", etag)
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusNotModified {
		t.Errorf("Expected status %d, got %d", http.StatusNotModified, w2.Code)
	}
}

func TestHandlers_UpdatePrivateData_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/private-data", authMiddlewareForUser(user), handlers.UpdatePrivateData)

	// Get current ETag first
	ctx := context.Background()
	_, currentEtag, _ := handlers.services.User.GetPrivateData(ctx, user.UUID)

	newPrivateData := taggedbinary.TaggedBytes([]byte(`{"new": "encrypted-data"}`))
	body, _ := json.Marshal(map[string]interface{}{"privateData": newPrivateData})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/private-data", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Private-Data-If-Match", currentEtag)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNoContent, w.Code, w.Body.String())
	}

	// Verify X-Private-Data-ETag header is set with new value
	newEtag := w.Header().Get("X-Private-Data-ETag")
	if newEtag == "" {
		t.Error("Expected X-Private-Data-ETag header")
	}
	if newEtag == currentEtag {
		t.Error("Expected ETag to change after update")
	}
}

func TestHandlers_UpdatePrivateData_ETagMismatch(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/private-data", authMiddlewareForUser(user), handlers.UpdatePrivateData)

	newPrivateData := taggedbinary.TaggedBytes([]byte(`{"new": "encrypted-data"}`))
	body, _ := json.Marshal(map[string]interface{}{"privateData": newPrivateData})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/private-data", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Private-Data-If-Match", "wrong-etag")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusPreconditionFailed {
		t.Errorf("Expected status %d, got %d: %s", http.StatusPreconditionFailed, w.Code, w.Body.String())
	}
}

// ====================
// Account Info Tests
// ====================

func TestHandlers_GetAccountInfo_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/account-info", authMiddlewareForUser(user), handlers.GetAccountInfo)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/account-info", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response AccountInfoResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response.UUID != user.UUID.String() {
		t.Errorf("Expected UUID %s, got %s", user.UUID.String(), response.UUID)
	}

	if response.DisplayName == nil || *response.DisplayName != *user.DisplayName {
		t.Errorf("DisplayName mismatch")
	}

	// Verify webauthnCredentials array exists
	if response.WebauthnCredentials == nil {
		t.Error("Expected webauthnCredentials array")
	}

	if len(response.WebauthnCredentials) != 1 {
		t.Errorf("Expected 1 credential, got %d", len(response.WebauthnCredentials))
	}

	// Verify credential fields
	cred := response.WebauthnCredentials[0]
	if cred.ID != "cred-1" {
		t.Errorf("Expected credential ID 'cred-1', got %s", cred.ID)
	}
	if !cred.PRFCapable {
		t.Error("Expected credential to be PRF capable")
	}
}

func TestHandlers_GetAccountInfo_Unauthorized(t *testing.T) {
	handlers, router, _ := setupTestHandlersWithUser(t)
	router.GET("/account-info", handlers.GetAccountInfo)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/account-info", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// ====================
// Update Settings Tests
// ====================

func TestHandlers_UpdateSettings_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/settings", authMiddlewareForUser(user), handlers.UpdateSettings)

	body, _ := json.Marshal(map[string]int64{
		"openidRefreshTokenMaxAgeInSeconds": 7200,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/settings", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestHandlers_UpdateSettings_Unauthorized(t *testing.T) {
	handlers, router, _ := setupTestHandlersWithUser(t)
	router.POST("/settings", handlers.UpdateSettings)

	body, _ := json.Marshal(map[string]int64{
		"openidRefreshTokenMaxAgeInSeconds": 7200,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/settings", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// ====================
// Delete User Tests
// ====================

func TestHandlers_DeleteUser_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.DELETE("/", authMiddlewareForUser(user), handlers.DeleteUser)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify user was deleted
	ctx := context.Background()
	_, err := handlers.services.User.GetUserByID(ctx, user.UUID)
	if err == nil {
		t.Error("Expected user to be deleted")
	}
}

func TestHandlers_DeleteUser_Unauthorized(t *testing.T) {
	handlers, router, _ := setupTestHandlersWithUser(t)
	router.DELETE("/", handlers.DeleteUser)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// ====================
// WebAuthn Credential Management Tests
// ====================

func TestHandlers_RenameWebAuthnCredential_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/webauthn/credential/:id/rename", authMiddlewareForUser(user), handlers.RenameWebAuthnCredential)

	body, _ := json.Marshal(map[string]string{
		"nickname": "My Phone",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/cred-1/rename", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNoContent, w.Code, w.Body.String())
	}
}

func TestHandlers_RenameWebAuthnCredential_NotFound(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/webauthn/credential/:id/rename", authMiddlewareForUser(user), handlers.RenameWebAuthnCredential)

	body, _ := json.Marshal(map[string]string{
		"nickname": "My Phone",
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/nonexistent/rename", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestHandlers_DeleteWebAuthnCredential_LastCredential(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/webauthn/credential/:id/delete", authMiddlewareForUser(user), handlers.DeleteWebAuthnCredential)

	// Get current ETag
	ctx := context.Background()
	_, currentEtag, _ := handlers.services.User.GetPrivateData(ctx, user.UUID)

	newPrivateData := taggedbinary.TaggedBytes([]byte(`{"updated": "private-data"}`))
	body, _ := json.Marshal(map[string]interface{}{
		"privateData": newPrivateData,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/cred-1/delete", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Private-Data-If-Match", currentEtag)
	router.ServeHTTP(w, req)

	// Should return 409 Conflict because it's the last credential
	if w.Code != http.StatusConflict {
		t.Errorf("Expected status %d (Conflict for last credential), got %d: %s", http.StatusConflict, w.Code, w.Body.String())
	}
}

func TestHandlers_DeleteWebAuthnCredential_NotFound(t *testing.T) {
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
	handlers := NewHandlers(services, cfg, logger, "test")

	// Create user with multiple credentials for this test
	ctx := context.Background()
	displayName := "Multi-Cred User"
	privateData := []byte(`{"encrypted": "data"}`)
	userWithMultipleCreds := &domain.User{
		UUID:            domain.NewUserID(),
		DID:             "did:key:multicred123",
		DisplayName:     &displayName,
		PrivateData:     privateData,
		PrivateDataETag: domain.ComputePrivateDataETag(privateData),
		WebauthnCredentials: []domain.WebauthnCredential{
			{
				ID:           "cred-1",
				CredentialID: []byte("credential-id-bytes-1"),
				PublicKey:    []byte("public-key-bytes-1"),
				PRFCapable:   true,
				CreatedAt:    time.Now(),
			},
			{
				ID:           "cred-2",
				CredentialID: []byte("credential-id-bytes-2"),
				PublicKey:    []byte("public-key-bytes-2"),
				PRFCapable:   true,
				CreatedAt:    time.Now(),
			},
		},
	}
	if err := store.Users().Create(ctx, userWithMultipleCreds); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	router := gin.New()
	router.POST("/webauthn/credential/:id/delete", authMiddlewareForUser(userWithMultipleCreds), handlers.DeleteWebAuthnCredential)

	newPrivateData := taggedbinary.TaggedBytes([]byte(`{"updated": "private-data"}`))
	body, _ := json.Marshal(map[string]interface{}{
		"privateData": newPrivateData,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webauthn/credential/nonexistent/delete", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

// ====================
// Auth Check Tests
// ====================

func TestHandlers_AuthCheck_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/auth-check", authMiddlewareForUser(user), handlers.AuthCheck)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth-check", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

// ====================
// Storage Tests with Authentication
// ====================

func TestHandlers_GetAllCredentials_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/vc", authMiddlewareForUser(user), handlers.GetAllCredentials)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vc", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify response contains vc_list
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v. Body: %s", err, w.Body.String())
	}

	if _, ok := response["vc_list"]; !ok {
		t.Errorf("Expected vc_list in response, got: %v", response)
	}
}

func TestHandlers_GetAllPresentations_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/vp", authMiddlewareForUser(user), handlers.GetAllPresentations)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vp", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Verify response contains vp_list
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v. Body: %s", err, w.Body.String())
	}

	if _, ok := response["vp_list"]; !ok {
		t.Errorf("Expected vp_list in response, got: %v", response)
	}
}

func TestHandlers_StoreAndGetCredential(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vc", authMiddlewareForUser(user), handlers.StoreCredential)
	router.GET("/vc/:credential_identifier", authMiddlewareForUser(user), handlers.GetCredentialByIdentifier)

	// Store a credential
	storeBody, _ := json.Marshal(map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"credentialIdentifier": "test-cred-123",
				"credential":           `{"@context":["https://www.w3.org/2018/credentials/v1"]}`,
				"format":               "jwt_vc",
			},
		},
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/vc", bytes.NewBuffer(storeBody))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("Store failed with status %d: %s", w1.Code, w1.Body.String())
	}

	// Retrieve the credential
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/vc/test-cred-123", nil)
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Get failed with status %d: %s", w2.Code, w2.Body.String())
	}

	var cred domain.VerifiableCredential
	if err := json.Unmarshal(w2.Body.Bytes(), &cred); err != nil {
		t.Fatalf("Failed to parse credential: %v", err)
	}

	if cred.CredentialIdentifier != "test-cred-123" {
		t.Errorf("Expected credential identifier 'test-cred-123', got %s", cred.CredentialIdentifier)
	}
}

func TestHandlers_DeleteCredential_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vc", authMiddlewareForUser(user), handlers.StoreCredential)
	router.DELETE("/vc/:credential_identifier", authMiddlewareForUser(user), handlers.DeleteCredential)

	// First store a credential
	storeBody, _ := json.Marshal(map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"credentialIdentifier": "to-delete",
				"credential":           `{"test": true}`,
				"format":               "jwt_vc",
			},
		},
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/vc", bytes.NewBuffer(storeBody))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	// Delete the credential
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodDelete, "/vc/to-delete", nil)
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Delete failed with status %d: %s", w2.Code, w2.Body.String())
	}
}

func TestHandlers_StorePresentation_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vp", authMiddlewareForUser(user), handlers.StorePresentation)

	body, _ := json.Marshal(domain.StorePresentationRequest{
		PresentationIdentifier:                  "pres-123",
		Presentation:                            `{"@context":["https://www.w3.org/2018/credentials/v1"]}`,
		PresentationSubmission:                  `{"id":"submission"}`,
		IncludedVerifiableCredentialIdentifiers: []string{"cred-1"},
		Audience:                                "verifier-1",
		IssuanceDate:                            time.Now(),
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/vp", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

// ====================
// Additional Credential Tests
// ====================

func TestHandlers_UpdateCredential_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vc", authMiddlewareForUser(user), handlers.StoreCredential)
	router.POST("/vc/update", authMiddlewareForUser(user), handlers.UpdateCredential)

	// First store a credential
	storeBody, _ := json.Marshal(map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"credentialIdentifier": "cred-update-test",
				"credential":           `{"test": true}`,
				"format":               "jwt_vc",
			},
		},
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/vc", bytes.NewBuffer(storeBody))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("Store failed: %s", w1.Body.String())
	}

	// Update the credential
	updateBody, _ := json.Marshal(map[string]interface{}{
		"credential": map[string]interface{}{
			"credentialIdentifier": "cred-update-test",
			"instanceId":           42,
			"sigCount":             5,
		},
	})

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/vc/update", bytes.NewBuffer(updateBody))
	req2.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Update failed with status %d: %s", w2.Code, w2.Body.String())
	}
}

func TestHandlers_UpdateCredential_NotFound(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vc/update", authMiddlewareForUser(user), handlers.UpdateCredential)

	updateBody, _ := json.Marshal(map[string]interface{}{
		"credential": map[string]interface{}{
			"credentialIdentifier": "nonexistent-cred",
			"instanceId":           1,
		},
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/vc/update", bytes.NewBuffer(updateBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestHandlers_GetCredentialByIdentifier_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vc", authMiddlewareForUser(user), handlers.StoreCredential)
	router.GET("/vc/:credential_identifier", authMiddlewareForUser(user), handlers.GetCredentialByIdentifier)

	// First store a credential
	storeBody, _ := json.Marshal(map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"credentialIdentifier": "cred-get-test",
				"credential":           `{"test": "value"}`,
				"format":               "jwt_vc",
			},
		},
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/vc", bytes.NewBuffer(storeBody))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	// Get by identifier
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/vc/cred-get-test", nil)
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w2.Code, w2.Body.String())
	}

	var cred domain.VerifiableCredential
	if err := json.Unmarshal(w2.Body.Bytes(), &cred); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if cred.CredentialIdentifier != "cred-get-test" {
		t.Errorf("Expected identifier 'cred-get-test', got '%s'", cred.CredentialIdentifier)
	}
}

func TestHandlers_GetCredentialByIdentifier_NotFound(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/vc/:credential_identifier", authMiddlewareForUser(user), handlers.GetCredentialByIdentifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vc/nonexistent", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestHandlers_DeleteCredential_NotFound(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.DELETE("/vc/:credential_identifier", authMiddlewareForUser(user), handlers.DeleteCredential)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/vc/nonexistent", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

// ====================
// Additional Presentation Tests
// ====================

func TestHandlers_GetPresentationByIdentifier_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vp", authMiddlewareForUser(user), handlers.StorePresentation)
	router.GET("/vp/:presentation_identifier", authMiddlewareForUser(user), handlers.GetPresentationByIdentifier)

	// First store a presentation
	storeBody, _ := json.Marshal(domain.StorePresentationRequest{
		PresentationIdentifier:                  "pres-get-test",
		Presentation:                            `{"@context":["https://www.w3.org/2018/credentials/v1"]}`,
		IncludedVerifiableCredentialIdentifiers: []string{"cred-1"},
		Audience:                                "verifier-1",
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/vp", bytes.NewBuffer(storeBody))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	// Get by identifier
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/vp/pres-get-test", nil)
	router.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w2.Code, w2.Body.String())
	}

	var pres domain.VerifiablePresentation
	if err := json.Unmarshal(w2.Body.Bytes(), &pres); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if pres.PresentationIdentifier != "pres-get-test" {
		t.Errorf("Expected identifier 'pres-get-test', got '%s'", pres.PresentationIdentifier)
	}
}

func TestHandlers_GetPresentationByIdentifier_NotFound(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/vp/:presentation_identifier", authMiddlewareForUser(user), handlers.GetPresentationByIdentifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/vp/nonexistent", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestHandlers_DeletePresentation_Success(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vp", authMiddlewareForUser(user), handlers.StorePresentation)
	router.DELETE("/vp/:presentation_identifier", authMiddlewareForUser(user), handlers.DeletePresentation)

	// First store a presentation
	storeBody, _ := json.Marshal(domain.StorePresentationRequest{
		PresentationIdentifier:                  "pres-delete-test",
		Presentation:                            `{"@context":["https://www.w3.org/2018/credentials/v1"]}`,
		IncludedVerifiableCredentialIdentifiers: []string{"cred-1"},
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/vp", bytes.NewBuffer(storeBody))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	// Delete presentation
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodDelete, "/vp/pres-delete-test", nil)
	router.ServeHTTP(w2, req2)

	// Handler returns 204 No Content on success
	if w2.Code != http.StatusNoContent {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNoContent, w2.Code, w2.Body.String())
	}
}

func TestHandlers_DeletePresentation_NotFound(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.DELETE("/vp/:presentation_identifier", authMiddlewareForUser(user), handlers.DeletePresentation)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/vp/nonexistent", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestHandlers_StorePresentation_Invalid(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vp", authMiddlewareForUser(user), handlers.StorePresentation)

	// Missing required fields - service layer validation returns error, handler returns 500
	body, _ := json.Marshal(map[string]interface{}{
		"presentation": `{"test": true}`,
		// Missing presentationIdentifier
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/vp", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Handler returns 500 for service-layer validation errors
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

// ====================
// Issuer and Verifier Tests
// ====================

func TestHandlers_GetAllIssuers_Empty(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/issuer/all", authMiddlewareForUser(user), handlers.GetAllIssuers)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuer/all", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestHandlers_GetIssuerByID_NotFound(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/issuer/:id", authMiddlewareForUser(user), handlers.GetIssuerByID)

	// Use numeric ID that doesn't exist (non-numeric returns 400)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuer/99999", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestHandlers_GetAllVerifiers_Empty(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.GET("/verifier/all", authMiddlewareForUser(user), handlers.GetAllVerifiers)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verifier/all", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

// ====================
// Edge Case Tests
// ====================

func TestHandlers_StoreCredential_EmptyCredentials(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vc", authMiddlewareForUser(user), handlers.StoreCredential)

	body, _ := json.Marshal(map[string]interface{}{
		"credentials": []map[string]interface{}{},
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/vc", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Empty credentials array returns 400 (handler validates this)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestHandlers_StoreCredential_MissingFormat(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vc", authMiddlewareForUser(user), handlers.StoreCredential)

	body, _ := json.Marshal(map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"credentialIdentifier": "test-cred",
				"credential":           `{"test": true}`,
				// Missing format - handler doesn't validate this, succeeds
			},
		},
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/vc", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	// Handler accepts credentials without format (format validation is lenient)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestHandlers_DeleteCredential_CascadesPresentations(t *testing.T) {
	handlers, router, user := setupTestHandlersWithUser(t)
	router.POST("/vc", authMiddlewareForUser(user), handlers.StoreCredential)
	router.POST("/vp", authMiddlewareForUser(user), handlers.StorePresentation)
	router.DELETE("/vc/:credential_identifier", authMiddlewareForUser(user), handlers.DeleteCredential)
	router.GET("/vp", authMiddlewareForUser(user), handlers.GetAllPresentations)

	// Store a credential
	storeCredBody, _ := json.Marshal(map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"credentialIdentifier": "cascade-test-cred",
				"credential":           `{"test": true}`,
				"format":               "jwt_vc",
			},
		},
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/vc", bytes.NewBuffer(storeCredBody))
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)

	// Store a presentation that includes the credential
	storePresBody, _ := json.Marshal(domain.StorePresentationRequest{
		PresentationIdentifier:                  "cascade-test-pres",
		Presentation:                            `{"test": true}`,
		IncludedVerifiableCredentialIdentifiers: []string{"cascade-test-cred"},
	})

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/vp", bytes.NewBuffer(storePresBody))
	req2.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w2, req2)

	// Delete the credential - should cascade to presentation
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodDelete, "/vc/cascade-test-cred", nil)
	router.ServeHTTP(w3, req3)

	if w3.Code != http.StatusOK {
		t.Errorf("Delete credential failed: %s", w3.Body.String())
	}

	// Check that presentation was also deleted
	w4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodGet, "/vp", nil)
	router.ServeHTTP(w4, req4)

	var vpResponse struct {
		VPList []domain.VerifiablePresentation `json:"vp_list"`
	}
	if err := json.Unmarshal(w4.Body.Bytes(), &vpResponse); err != nil {
		t.Fatalf("Failed to parse vp response: %v", err)
	}

	// Presentation should have been deleted (or vp_list should be empty/nil)
	if len(vpResponse.VPList) != 0 {
		t.Errorf("Expected 0 presentations after cascade delete, got %d", len(vpResponse.VPList))
	}
}
