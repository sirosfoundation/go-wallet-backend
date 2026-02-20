package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// TestHarness provides a complete test environment with an HTTP server,
// configured services, and helper methods for making API requests.
type TestHarness struct {
	T        *testing.T
	Server   *httptest.Server
	Config   *config.Config
	Router   *gin.Engine
	Storage  storage.Store
	Services *service.Services
	Logger   *zap.Logger

	// Client is a pre-configured HTTP client for making requests
	Client *http.Client

	// BaseURL is the URL of the test server
	BaseURL string
}

// TestHarnessOption configures the test harness
type TestHarnessOption func(*TestHarness)

// WithConfig sets a custom config for the test harness
func WithConfig(cfg *config.Config) TestHarnessOption {
	return func(h *TestHarness) {
		h.Config = cfg
	}
}

// NewTestHarness creates a new test harness with a running test server
func NewTestHarness(t *testing.T, opts ...TestHarnessOption) *TestHarness {
	t.Helper()

	gin.SetMode(gin.TestMode)

	logger, _ := zap.NewDevelopment()

	h := &TestHarness{
		T:      t,
		Logger: logger,
		Client: &http.Client{},
	}

	// Apply options
	for _, opt := range opts {
		opt(h)
	}

	// Default config if not provided
	if h.Config == nil {
		h.Config = &config.Config{
			Server: config.ServerConfig{
				Host:     "localhost",
				Port:     8080,
				RPID:     "localhost",
				RPOrigin: "http://localhost:8080",
				RPName:   "Test Wallet",
			},
			Storage: config.StorageConfig{
				Type: "memory",
			},
			JWT: config.JWTConfig{
				Secret:      "test-secret-key-for-integration-tests",
				ExpiryHours: 24,
				RefreshDays: 7,
				Issuer:      "test-wallet-backend",
			},
		}
	}

	// Create memory storage
	h.Storage = memory.NewStore()

	// Create services
	h.Services = service.NewServices(h.Storage, h.Config, logger)

	// Create handlers (using "test" mode for integration tests)
	handlers := api.NewHandlers(h.Services, h.Config, logger, "test")

	// Setup router
	h.Router = gin.New()
	h.Router.Use(gin.Recovery())
	setupRoutes(h.Router, handlers, h.Config, h.Storage, logger)

	// Create test server
	h.Server = httptest.NewServer(h.Router)
	h.BaseURL = h.Server.URL

	// Register cleanup
	t.Cleanup(func() {
		h.Server.Close()
	})

	return h
}

// setupRoutes configures all API routes (mirrors the main server setup)
func setupRoutes(r *gin.Engine, h *api.Handlers, cfg *config.Config, store storage.Store, logger *zap.Logger) {
	// Create auth middleware
	auth := middleware.AuthMiddleware(cfg, store, logger)

	// Health/status (public)
	r.GET("/status", h.Status)

	// User routes (deprecated password-based - public)
	r.POST("/user/register", h.RegisterUser)
	r.POST("/user/login", h.LoginUser)

	// WebAuthn routes (public - for registration/login)
	r.POST("/user/register-webauthn-begin", h.StartWebAuthnRegistration)
	r.POST("/user/register-webauthn-finish", h.FinishWebAuthnRegistration)
	r.POST("/user/login-webauthn-begin", h.StartWebAuthnLogin)
	r.POST("/user/login-webauthn-finish", h.FinishWebAuthnLogin)

	// Session routes (authenticated)
	session := r.Group("/user/session")
	session.Use(auth)
	{
		session.GET("/account-info", h.GetAccountInfo)
		session.GET("/private-data", h.GetPrivateData)
		session.POST("/private-data", h.UpdatePrivateData)
		session.DELETE("", h.DeleteUser)
		session.POST("/settings", h.UpdateSettings)

		// WebAuthn credential management
		session.POST("/webauthn-credential/add-begin", h.StartAddWebAuthnCredential)
		session.POST("/webauthn-credential/add-finish", h.FinishAddWebAuthnCredential)
		session.DELETE("/webauthn-credential/:id", h.DeleteWebAuthnCredential)
		session.POST("/webauthn-credential/:id/rename", h.RenameWebAuthnCredential)
	}

	// Storage routes (authenticated)
	storage := r.Group("/storage")
	storage.Use(auth)
	{
		// Credentials
		storage.GET("/vc", h.GetAllCredentials)
		storage.POST("/vc", h.StoreCredential)
		storage.GET("/vc/:id", h.GetCredentialByIdentifier)
		storage.PUT("/vc/:id", h.UpdateCredential)
		storage.DELETE("/vc/:id", h.DeleteCredential)

		// Presentations
		storage.GET("/vp", h.GetAllPresentations)
		storage.POST("/vp", h.StorePresentation)
		storage.GET("/vp/:id", h.GetPresentationByIdentifier)
		storage.DELETE("/vp/:id", h.DeletePresentation)
	}

	// Issuer routes (public)
	r.GET("/issuer/all", h.GetAllIssuers)
	r.GET("/issuer/:id", h.GetIssuerByID)

	// Verifier routes (public)
	r.GET("/verifier/all", h.GetAllVerifiers)

	// Key attestation routes (public)
	r.GET("/wallet-provider/certificate", h.GetCertificate)
	r.POST("/wallet-provider/key-attestation", h.GenerateKeyAttestation)

	// Auth check (public - returns 200 always for token validation done by client)
	r.GET("/auth/check", h.AuthCheck)
}

// Request makes an HTTP request to the test server
func (h *TestHarness) Request(method, path string, body interface{}) *Response {
	h.T.Helper()

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			h.T.Fatalf("Failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, h.BaseURL+path, bodyReader)
	if err != nil {
		h.T.Fatalf("Failed to create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return h.Do(req)
}

// Do executes an HTTP request and returns a Response wrapper
func (h *TestHarness) Do(req *http.Request) *Response {
	h.T.Helper()

	resp, err := h.Client.Do(req)
	if err != nil {
		h.T.Fatalf("Request failed: %v", err)
	}

	return &Response{
		T:        h.T,
		Response: resp,
	}
}

// GET makes a GET request
func (h *TestHarness) GET(path string) *Response {
	return h.Request(http.MethodGet, path, nil)
}

// POST makes a POST request with a JSON body
func (h *TestHarness) POST(path string, body interface{}) *Response {
	return h.Request(http.MethodPost, path, body)
}

// DELETE makes a DELETE request
func (h *TestHarness) DELETE(path string) *Response {
	return h.Request(http.MethodDelete, path, nil)
}

// WithAuth returns a new request builder with authentication
func (h *TestHarness) WithAuth(token string) *AuthenticatedClient {
	return &AuthenticatedClient{
		harness: h,
		token:   token,
	}
}

// AuthenticatedClient wraps the harness with auth headers
type AuthenticatedClient struct {
	harness *TestHarness
	token   string
}

// GET makes an authenticated GET request
func (c *AuthenticatedClient) GET(path string) *Response {
	c.harness.T.Helper()
	req, _ := http.NewRequest(http.MethodGet, c.harness.BaseURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.harness.Do(req)
}

// POST makes an authenticated POST request
func (c *AuthenticatedClient) POST(path string, body interface{}) *Response {
	c.harness.T.Helper()
	var bodyReader io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(jsonBody)
	}
	req, _ := http.NewRequest(http.MethodPost, c.harness.BaseURL+path, bodyReader)
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.harness.Do(req)
}

// DELETE makes an authenticated DELETE request
func (c *AuthenticatedClient) DELETE(path string) *Response {
	c.harness.T.Helper()
	req, _ := http.NewRequest(http.MethodDelete, c.harness.BaseURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.harness.Do(req)
}

// Response wraps an HTTP response with assertion helpers
type Response struct {
	T        *testing.T
	Response *http.Response
	body     []byte
	bodyRead bool
}

// Body returns the response body as bytes
func (r *Response) Body() []byte {
	r.T.Helper()
	if !r.bodyRead {
		var err error
		r.body, err = io.ReadAll(r.Response.Body)
		if err != nil {
			r.T.Fatalf("Failed to read response body: %v", err)
		}
		_ = r.Response.Body.Close()
		r.bodyRead = true
	}
	return r.body
}

// JSON unmarshals the response body into the given target
func (r *Response) JSON(target interface{}) *Response {
	r.T.Helper()
	if err := json.Unmarshal(r.Body(), target); err != nil {
		r.T.Fatalf("Failed to unmarshal response: %v\nBody: %s", err, string(r.Body()))
	}
	return r
}

// Status asserts the response status code
func (r *Response) Status(expected int) *Response {
	r.T.Helper()
	if r.Response.StatusCode != expected {
		r.T.Errorf("Expected status %d, got %d\nBody: %s", expected, r.Response.StatusCode, string(r.Body()))
	}
	return r
}

// Header returns the value of a response header
func (r *Response) Header(name string) string {
	return r.Response.Header.Get(name)
}

// HasHeader asserts that a header exists
func (r *Response) HasHeader(name string) *Response {
	r.T.Helper()
	if r.Header(name) == "" {
		r.T.Errorf("Expected header %q to be present", name)
	}
	return r
}

// BodyContains asserts the response body contains a substring
func (r *Response) BodyContains(substr string) *Response {
	r.T.Helper()
	if !bytes.Contains(r.Body(), []byte(substr)) {
		r.T.Errorf("Expected body to contain %q\nBody: %s", substr, string(r.Body()))
	}
	return r
}

// BodyEquals asserts the response body equals exactly
func (r *Response) BodyEquals(expected string) *Response {
	r.T.Helper()
	if string(r.Body()) != expected {
		r.T.Errorf("Expected body:\n%s\nGot:\n%s", expected, string(r.Body()))
	}
	return r
}

// Pretty returns pretty-printed JSON for debugging
func (r *Response) Pretty() string {
	var v interface{}
	if err := json.Unmarshal(r.Body(), &v); err != nil {
		return string(r.Body())
	}
	pretty, _ := json.MarshalIndent(v, "", "  ")
	return string(pretty)
}

// Debug logs the response for debugging
func (r *Response) Debug() *Response {
	fmt.Printf("=== Response ===\nStatus: %d\nHeaders: %v\nBody:\n%s\n================\n",
		r.Response.StatusCode, r.Response.Header, r.Pretty())
	return r
}

// TestUser represents a test user with authentication token
type TestUser struct {
	UUID        domain.UserID
	DisplayName string
	DID         string
	Token       string
	PrivateData []byte
}

// CreateTestUser creates a user directly in storage and generates a valid JWT token.
// This bypasses WebAuthn authentication for testing authenticated endpoints.
func (h *TestHarness) CreateTestUser(displayName string) *TestUser {
	h.T.Helper()

	ctx := context.Background()

	// Create user
	userID := domain.NewUserID()
	now := time.Now()
	did := fmt.Sprintf("did:key:%s", userID.String())
	privateData := []byte(`{"testKey":"testValue"}`)

	user := &domain.User{
		UUID:            userID,
		DisplayName:     &displayName,
		DID:             did,
		PrivateData:     privateData,
		PrivateDataETag: domain.ComputePrivateDataETag(privateData),
		WalletType:      domain.WalletTypeClient,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Store user
	if err := h.Storage.Users().Create(ctx, user); err != nil {
		h.T.Fatalf("Failed to create test user: %v", err)
	}

	// Generate token using UserService (default tenant for test users)
	token, err := h.Services.User.GenerateTokenForUser(user, domain.DefaultTenantID)
	if err != nil {
		h.T.Fatalf("Failed to generate token for test user: %v", err)
	}

	return &TestUser{
		UUID:        userID,
		DisplayName: displayName,
		DID:         did,
		Token:       token,
		PrivateData: privateData,
	}
}

// CreateTestUserWithCredentials creates a user with a mock WebAuthn credential.
// Useful for testing credential management endpoints.
func (h *TestHarness) CreateTestUserWithCredentials(displayName string) *TestUser {
	h.T.Helper()

	ctx := context.Background()

	// Create user
	userID := domain.NewUserID()
	now := time.Now()
	did := fmt.Sprintf("did:key:%s", userID.String())
	privateData := []byte(`{"testKey":"testValue"}`)

	// Create a mock credential
	credential := domain.WebauthnCredential{
		ID:              "test-credential-1",
		CredentialID:    []byte("mock-credential-id-1"),
		PublicKey:       []byte("mock-public-key"),
		AttestationType: "none",
		Transport:       []string{"internal"},
		Flags:           0x45, // UP | UV | AT
		Authenticator: domain.Authenticator{
			AAGUID:    []byte("mock-aaguid-12345"),
			SignCount: 0,
		},
		PRFCapable: false,
		CreatedAt:  now,
	}

	user := &domain.User{
		UUID:                userID,
		DisplayName:         &displayName,
		DID:                 did,
		PrivateData:         privateData,
		PrivateDataETag:     domain.ComputePrivateDataETag(privateData),
		WalletType:          domain.WalletTypeClient,
		WebauthnCredentials: []domain.WebauthnCredential{credential},
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	// Store user
	if err := h.Storage.Users().Create(ctx, user); err != nil {
		h.T.Fatalf("Failed to create test user with credentials: %v", err)
	}

	// Generate token using UserService (default tenant for test users)
	token, err := h.Services.User.GenerateTokenForUser(user, domain.DefaultTenantID)
	if err != nil {
		h.T.Fatalf("Failed to generate token for test user: %v", err)
	}

	return &TestUser{
		UUID:        userID,
		DisplayName: displayName,
		DID:         did,
		Token:       token,
		PrivateData: privateData,
	}
}

// AuthGET makes an authenticated GET request
func (h *TestHarness) AuthGET(user *TestUser, path string) *Response {
	return h.AuthRequest(user, "GET", path, nil)
}

// AuthPOST makes an authenticated POST request
func (h *TestHarness) AuthPOST(user *TestUser, path string, body interface{}) *Response {
	return h.AuthRequest(user, "POST", path, body)
}

// AuthPUT makes an authenticated PUT request
func (h *TestHarness) AuthPUT(user *TestUser, path string, body interface{}) *Response {
	return h.AuthRequest(user, "PUT", path, body)
}

// AuthDELETE makes an authenticated DELETE request
func (h *TestHarness) AuthDELETE(user *TestUser, path string) *Response {
	return h.AuthRequest(user, "DELETE", path, nil)
}

// AuthRequest makes an authenticated HTTP request
func (h *TestHarness) AuthRequest(user *TestUser, method, path string, body interface{}) *Response {
	h.T.Helper()

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			h.T.Fatalf("Failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, h.BaseURL+path, bodyReader)
	if err != nil {
		h.T.Fatalf("Failed to create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add authentication header
	req.Header.Set("Authorization", "Bearer "+user.Token)

	return h.Do(req)
}
