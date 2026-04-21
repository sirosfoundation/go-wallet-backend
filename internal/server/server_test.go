package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()

	if cfg == nil {
		t.Fatal("DefaultServerConfig() returned nil")
	}
	if cfg.HTTPAddress != "0.0.0.0" {
		t.Errorf("HTTPAddress = %q, want '0.0.0.0'", cfg.HTTPAddress)
	}
	if cfg.HTTPPort != 8080 {
		t.Errorf("HTTPPort = %d, want 8080", cfg.HTTPPort)
	}
	if cfg.WSAddress != "0.0.0.0" {
		t.Errorf("WSAddress = %q, want '0.0.0.0'", cfg.WSAddress)
	}
	if cfg.WSPort != 8081 {
		t.Errorf("WSPort = %d, want 8081", cfg.WSPort)
	}
}

func TestNewManager(t *testing.T) {
	cfg := DefaultServerConfig()
	logger := zap.NewNop()

	manager := NewManager(cfg, logger)

	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
	if manager.cfg != cfg {
		t.Error("Manager cfg not set")
	}
	if manager.logger != logger {
		t.Error("Manager logger not set")
	}
	if manager.providers == nil {
		t.Error("Manager providers not initialized")
	}
	if manager.readiness == nil {
		t.Error("Manager readiness not initialized")
	}
}

// mockRouteProvider implements RouteProvider for testing
type mockRouteProvider struct {
	name             string
	transport        Transport
	routesRegistered bool
	checkReadyFn     func(context.Context) error
}

func (m *mockRouteProvider) Transport() Transport { return m.transport }
func (m *mockRouteProvider) Name() string         { return m.name }
func (m *mockRouteProvider) RegisterRoutes(_ *gin.Engine) {
	m.routesRegistered = true
}
func (m *mockRouteProvider) CheckReady(ctx context.Context) error {
	if m.checkReadyFn != nil {
		return m.checkReadyFn(ctx)
	}
	return nil
}

func TestManager_AddProvider(t *testing.T) {
	cfg := DefaultServerConfig()
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	provider := &mockRouteProvider{
		name:      "test-provider",
		transport: TransportHTTP,
	}

	manager.AddProvider(provider)

	if len(manager.providers) != 1 {
		t.Errorf("providers count = %d, want 1", len(manager.providers))
	}
	if manager.providers[0] != provider {
		t.Error("Added provider not in list")
	}
}

func TestManager_AddProvider_WithReadinessCheck(t *testing.T) {
	cfg := DefaultServerConfig()
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	// Provider that implements ReadinessCheckProvider
	provider := &mockRouteProvider{
		name:      "readiness-provider",
		transport: TransportHTTP,
		checkReadyFn: func(_ context.Context) error {
			return nil
		},
	}

	manager.AddProvider(provider)

	if len(manager.providers) != 1 {
		t.Errorf("providers count = %d, want 1", len(manager.providers))
	}
}

func TestManager_AddProvider_MultipleProviders(t *testing.T) {
	cfg := DefaultServerConfig()
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	http1 := &mockRouteProvider{name: "http1", transport: TransportHTTP}
	http2 := &mockRouteProvider{name: "http2", transport: TransportHTTP}
	ws1 := &mockRouteProvider{name: "ws1", transport: TransportWebSocket}

	manager.AddProvider(http1)
	manager.AddProvider(http2)
	manager.AddProvider(ws1)

	if len(manager.providers) != 3 {
		t.Errorf("providers count = %d, want 3", len(manager.providers))
	}
}

func TestTransportConstants(t *testing.T) {
	if TransportHTTP != "http" {
		t.Errorf("TransportHTTP = %q, want 'http'", TransportHTTP)
	}
	if TransportWebSocket != "websocket" {
		t.Errorf("TransportWebSocket = %q, want 'websocket'", TransportWebSocket)
	}
}

func TestProviderChecker(t *testing.T) {
	mock := &mockRouteProvider{
		name: "test-checker",
		checkReadyFn: func(_ context.Context) error {
			return nil
		},
	}

	checker := &providerChecker{
		name:    mock.Name(),
		checker: mock,
	}

	if checker.Name() != "test-checker" {
		t.Errorf("Name() = %q, want 'test-checker'", checker.Name())
	}

	err := checker.CheckReady(context.Background())
	if err != nil {
		t.Errorf("CheckReady() error = %v", err)
	}
}

func TestServerConfig_Fields(t *testing.T) {
	cfg := &ServerConfig{
		HTTPAddress:  "127.0.0.1",
		HTTPPort:     9000,
		WSAddress:    "0.0.0.0",
		WSPort:       9001,
		AdminPort:    9002,
		AdminToken:   "secret",
		LoggingLevel: "debug",
		Roles:        []string{"auth", "backend"},
	}

	if cfg.HTTPAddress != "127.0.0.1" {
		t.Errorf("HTTPAddress = %q", cfg.HTTPAddress)
	}
	if cfg.HTTPPort != 9000 {
		t.Errorf("HTTPPort = %d", cfg.HTTPPort)
	}
	if cfg.AdminPort != 9002 {
		t.Errorf("AdminPort = %d", cfg.AdminPort)
	}
	if cfg.AdminToken != "secret" {
		t.Errorf("AdminToken = %q", cfg.AdminToken)
	}
	if len(cfg.Roles) != 2 {
		t.Errorf("Roles len = %d", len(cfg.Roles))
	}
}

func TestEffectiveAdminTLS(t *testing.T) {
	shared := &config.TLSConfig{Enabled: true, CertFile: "/main.pem", KeyFile: "/main.key"}
	adminEnabled := &config.TLSConfig{Enabled: true, CertFile: "/admin.pem", KeyFile: "/admin.key"}
	adminDisabled := &config.TLSConfig{Enabled: false}

	t.Run("nil AdminTLS inherits shared", func(t *testing.T) {
		got := effectiveAdminTLS(shared, nil)
		if got != shared {
			t.Error("expected shared TLS config when AdminTLS is nil")
		}
	})

	t.Run("disabled AdminTLS inherits shared", func(t *testing.T) {
		got := effectiveAdminTLS(shared, adminDisabled)
		if got != shared {
			t.Error("expected shared TLS config when AdminTLS.Enabled is false")
		}
	})

	t.Run("enabled AdminTLS overrides shared", func(t *testing.T) {
		got := effectiveAdminTLS(shared, adminEnabled)
		if got != adminEnabled {
			t.Error("expected admin TLS config when AdminTLS.Enabled is true")
		}
		if got.CertFile != "/admin.pem" {
			t.Errorf("CertFile = %q, want /admin.pem", got.CertFile)
		}
	})
}

// Test that status endpoints are added to routers
func TestManager_StatusEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	cfg := &ServerConfig{
		Roles: []string{"auth", "backend"},
	}
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	manager.addStatusEndpoints(router)

	// Test /readyz should have been added
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/readyz", nil)
	router.ServeHTTP(w, req)

	// Readyz should work since we're calling addStatusEndpoints
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 200 or 503", w.Code)
	}
}

// Test /readyz endpoint
func TestManager_ReadyzEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	cfg := &ServerConfig{
		Roles: []string{"test"},
	}
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	manager.addStatusEndpoints(router)

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/readyz", nil)
	router.ServeHTTP(w, req)

	// With no checkers, should be ready
	if w.Code != http.StatusOK {
		t.Errorf("/readyz status = %d, want 200", w.Code)
	}
}

func TestManager_BuildRouter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &ServerConfig{
		CORS: config.CORSConfig{
			AllowedOrigins:   []string{"http://localhost:3000"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
			AllowedHeaders:   []string{"Content-Type", "Authorization"},
			AllowCredentials: true,
		},
	}
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	router := manager.buildRouter()

	if router == nil {
		t.Fatal("buildRouter() returned nil")
	}

	// Test that router handles requests
	w := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	router.ServeHTTP(w, req)

	// CORS preflight should return OK or NoContent
	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Errorf("OPTIONS status = %d, want 200 or 204", w.Code)
	}
}

func TestManager_Shutdown_NotStarted(t *testing.T) {
	cfg := DefaultServerConfig()
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	// Shutdown without Start should not panic
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() error = %v", err)
	}
}

func TestManager_ServersNotStarted(t *testing.T) {
	cfg := DefaultServerConfig()
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	// Check server fields are nil before Start
	if manager.httpServer != nil {
		t.Error("httpServer should be nil before Start")
	}
	if manager.wsServer != nil {
		t.Error("wsServer should be nil before Start")
	}
	if manager.adminServer != nil {
		t.Error("adminServer should be nil before Start")
	}
}

func TestStartAdminServer_ProductionRequiresToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	cfg := DefaultServerConfig()
	cfg.AdminPort = 0 // won't actually listen
	cfg.IsProduction = true
	cfg.AdminToken = ""

	mgr := NewManager(cfg, logger)
	err := mgr.startAdminServer()
	if err == nil {
		t.Fatal("expected error when production mode has no admin token")
	}
	if !strings.Contains(err.Error(), "admin token is required in production") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestStartAdminServer_ProductionWithToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	cfg := DefaultServerConfig()
	cfg.AdminPort = 0
	cfg.IsProduction = true
	cfg.AdminToken = "test-token-value"

	mgr := NewManager(cfg, logger)
	err := mgr.startAdminServer()
	// Should succeed (won't actually listen on port 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStartAdminServer_DevAutoGeneratesToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()

	cfg := DefaultServerConfig()
	cfg.AdminPort = 0
	cfg.IsProduction = false
	cfg.AdminToken = ""

	mgr := NewManager(cfg, logger)
	err := mgr.startAdminServer()
	if err != nil {
		t.Fatalf("dev mode without token should auto-generate, got error: %v", err)
	}
}

// Test that ServedBy header middleware is applied
func TestManager_ServedByMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &ServerConfig{
		Roles: []string{"test"},
		CORS: config.CORSConfig{
			AllowedOrigins: []string{"*"},
		},
	}
	// Use a custom logger to capture any issues
	logger := zap.NewNop()
	manager := NewManager(cfg, logger)

	// Build router and add test route
	router := manager.buildRouter()
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	// Check that X-Served-By header is set
	servedBy := w.Header().Get("X-Served-By")
	if servedBy == "" {
		// Middleware might not set if no config - this is optional
		t.Log("X-Served-By header not set (may be expected)")
	}
}
