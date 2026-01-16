package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// AdminTestHarness provides a test environment for the admin API
type AdminTestHarness struct {
	T       *testing.T
	Server  *httptest.Server
	Router  *gin.Engine
	Storage storage.Store
	Logger  *zap.Logger

	// Client is a pre-configured HTTP client for making requests
	Client *http.Client

	// BaseURL is the URL of the test server
	BaseURL string

	// AdminToken is the bearer token for admin API authentication
	AdminToken string
}

// NewAdminTestHarness creates a new test harness for the admin API
func NewAdminTestHarness(t *testing.T) *AdminTestHarness {
	t.Helper()

	gin.SetMode(gin.TestMode)

	logger, _ := zap.NewDevelopment()

	// Generate a test token
	testToken := "test-admin-token-for-integration-tests"

	h := &AdminTestHarness{
		T:          t,
		Logger:     logger,
		Client:     &http.Client{},
		Storage:    memory.NewStore(),
		AdminToken: testToken,
	}

	// Create admin handlers
	adminHandlers := api.NewAdminHandlers(h.Storage, logger)

	// Setup router
	h.Router = gin.New()
	h.Router.Use(gin.Recovery())
	h.Router.Use(middleware.Logger(logger))
	setupAdminRoutes(h.Router, adminHandlers, testToken, logger)

	// Create test server
	h.Server = httptest.NewServer(h.Router)
	h.BaseURL = h.Server.URL

	// Register cleanup
	t.Cleanup(func() {
		h.Server.Close()
	})

	return h
}

// setupAdminRoutes configures all admin API routes (mirrors the main server setup)
func setupAdminRoutes(r *gin.Engine, h *api.AdminHandlers, adminToken string, logger *zap.Logger) {
	// Public status endpoint (no auth required)
	r.GET("/admin/status", h.AdminStatus)

	// Protected admin routes
	admin := r.Group("/admin")
	admin.Use(middleware.AdminAuthMiddleware(adminToken, logger))
	{
		// Tenant management
		tenants := admin.Group("/tenants")
		{
			tenants.GET("", h.ListTenants)
			tenants.POST("", h.CreateTenant)
			tenants.GET("/:id", h.GetTenant)
			tenants.PUT("/:id", h.UpdateTenant)
			tenants.DELETE("/:id", h.DeleteTenant)

			// Tenant user management
			tenants.GET("/:id/users", h.GetTenantUsers)
			tenants.POST("/:id/users", h.AddUserToTenant)
			tenants.DELETE("/:id/users/:user_id", h.RemoveUserFromTenant)

			// Tenant issuer management
			tenants.GET("/:id/issuers", h.ListIssuers)
			tenants.POST("/:id/issuers", h.CreateIssuer)
			tenants.GET("/:id/issuers/:issuer_id", h.GetIssuer)
			tenants.PUT("/:id/issuers/:issuer_id", h.UpdateIssuer)
			tenants.DELETE("/:id/issuers/:issuer_id", h.DeleteIssuer)

			// Tenant verifier management
			tenants.GET("/:id/verifiers", h.ListVerifiers)
			tenants.POST("/:id/verifiers", h.CreateVerifier)
			tenants.GET("/:id/verifiers/:verifier_id", h.GetVerifier)
			tenants.PUT("/:id/verifiers/:verifier_id", h.UpdateVerifier)
			tenants.DELETE("/:id/verifiers/:verifier_id", h.DeleteVerifier)
		}
	}
}

// Request makes an HTTP request to the test server
func (h *AdminTestHarness) Request(method, path string, body interface{}) *Response {
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

	// Add admin token authentication
	if h.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.AdminToken)
	}

	return h.Do(req)
}

// Do executes an HTTP request and returns a Response wrapper
func (h *AdminTestHarness) Do(req *http.Request) *Response {
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
func (h *AdminTestHarness) GET(path string) *Response {
	return h.Request(http.MethodGet, path, nil)
}

// POST makes a POST request with a JSON body
func (h *AdminTestHarness) POST(path string, body interface{}) *Response {
	return h.Request(http.MethodPost, path, body)
}

// PUT makes a PUT request with a JSON body
func (h *AdminTestHarness) PUT(path string, body interface{}) *Response {
	return h.Request(http.MethodPut, path, body)
}

// DELETE makes a DELETE request
func (h *AdminTestHarness) DELETE(path string) *Response {
	return h.Request(http.MethodDelete, path, nil)
}
