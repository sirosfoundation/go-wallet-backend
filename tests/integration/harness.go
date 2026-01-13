package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// TestHarness provides a complete test environment with an HTTP server,
// configured services, and helper methods for making API requests.
type TestHarness struct {
	T       *testing.T
	Server  *httptest.Server
	Config  *config.Config
	Router  *gin.Engine
	Storage storage.Store
	Logger  *zap.Logger

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
	services := service.NewServices(h.Storage, h.Config, logger)

	// Create handlers
	handlers := api.NewHandlers(services, h.Config, logger)

	// Setup router
	h.Router = gin.New()
	h.Router.Use(gin.Recovery())
	setupRoutes(h.Router, handlers)

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
func setupRoutes(r *gin.Engine, h *api.Handlers) {
	// Health/status
	r.GET("/status", h.Status)

	// User routes (deprecated password-based)
	r.POST("/user/register", h.RegisterUser)
	r.POST("/user/login", h.LoginUser)

	// WebAuthn routes
	r.POST("/user/register-webauthn-begin", h.StartWebAuthnRegistration)
	r.POST("/user/register-webauthn-finish", h.FinishWebAuthnRegistration)
	r.POST("/user/login-webauthn-begin", h.StartWebAuthnLogin)
	r.POST("/user/login-webauthn-finish", h.FinishWebAuthnLogin)

	// Session routes
	r.GET("/user/session/account-info", h.GetAccountInfo)
	r.GET("/user/session/private-data", h.GetPrivateData)
	r.POST("/user/session/private-data", h.UpdatePrivateData)
	r.DELETE("/user/session", h.DeleteUser)
	r.POST("/user/session/settings", h.UpdateSettings)

	// WebAuthn credential management
	r.POST("/user/session/webauthn-credential/add-begin", h.StartAddWebAuthnCredential)
	r.POST("/user/session/webauthn-credential/add-finish", h.FinishAddWebAuthnCredential)
	r.DELETE("/user/session/webauthn-credential/:id", h.DeleteWebAuthnCredential)
	r.POST("/user/session/webauthn-credential/:id/rename", h.RenameWebAuthnCredential)

	// Storage routes - Credentials
	r.GET("/storage/vc", h.GetAllCredentials)
	r.POST("/storage/vc", h.StoreCredential)
	r.GET("/storage/vc/:id", h.GetCredentialByIdentifier)
	r.PUT("/storage/vc/:id", h.UpdateCredential)
	r.DELETE("/storage/vc/:id", h.DeleteCredential)

	// Storage routes - Presentations
	r.GET("/storage/vp", h.GetAllPresentations)
	r.POST("/storage/vp", h.StorePresentation)
	r.GET("/storage/vp/:id", h.GetPresentationByIdentifier)
	r.DELETE("/storage/vp/:id", h.DeletePresentation)

	// Issuer routes
	r.GET("/issuer/all", h.GetAllIssuers)
	r.GET("/issuer/:id", h.GetIssuerByID)

	// Verifier routes
	r.GET("/verifier/all", h.GetAllVerifiers)

	// Key attestation routes
	r.GET("/wallet-provider/certificate", h.GetCertificate)
	r.POST("/wallet-provider/key-attestation", h.GenerateKeyAttestation)

	// Auth check
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
		r.Response.Body.Close()
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
