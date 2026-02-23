package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func testConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPName:   "Test",
			RPOrigin: "http://localhost:8080",
			CORS: config.CORSConfig{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"*"},
			},
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret-key-for-testing-purposes-only",
			ExpiryHours: 24,
			Issuer:      "test",
		},
		Storage: config.StorageConfig{
			Type: "memory",
		},
		Logging: config.LoggingConfig{
			Level: "debug",
		},
		Security: config.SecurityConfig{
			AuthRateLimit: config.AuthRateLimitConfig{
				Enabled:         true,
				RequestsPerMin:  100,
				LockoutDuration: 60,
			},
		},
	}
}

func TestNew(t *testing.T) {
	cfg := &Config{
		Config: testConfig(),
		Logger: testLogger(),
		Roles:  []string{"auth"},
	}

	runner, err := New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, runner)
	assert.Equal(t, modes.RoleAuth, runner.Role())
}

func TestRunner_Role(t *testing.T) {
	cfg := &Config{
		Config: testConfig(),
		Logger: testLogger(),
	}

	runner, err := New(cfg)
	require.NoError(t, err)
	assert.Equal(t, modes.RoleAuth, runner.Role())
	assert.Equal(t, modes.RoleAuth, runner.Name())
}

func TestSetupAuthRouter(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()

	// Create in-memory store for testing
	store, err := backend.New(nil, cfg)
	require.NoError(t, err)
	defer store.Close()

	services := service.NewServices(store, cfg, logger)
	roles := []string{"auth"}

	gin.SetMode(gin.TestMode)
	router := setupAuthRouter(cfg, services, store, logger, roles)
	require.NotNil(t, router)

	// Test health endpoint
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/status", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test health endpoint
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestSetupAuthRouter_PublicRoutes(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()

	store, err := backend.New(nil, cfg)
	require.NoError(t, err)
	defer store.Close()

	services := service.NewServices(store, cfg, logger)
	roles := []string{"auth"}

	gin.SetMode(gin.TestMode)
	router := setupAuthRouter(cfg, services, store, logger, roles)

	// Test deprecated password endpoints return 410
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/user/register", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusGone, w.Code)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/user/login", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusGone, w.Code)
}

func TestSetupAuthRouter_WebAuthnRoutes(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()

	store, err := backend.New(nil, cfg)
	require.NoError(t, err)
	defer store.Close()

	services := service.NewServices(store, cfg, logger)
	roles := []string{"auth"}

	gin.SetMode(gin.TestMode)
	router := setupAuthRouter(cfg, services, store, logger, roles)

	// Test WebAuthn registration begin endpoint exists
	// (We expect a 200 response with options or an error if WebAuthn is not configured)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/user/register-webauthn-begin", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	// Should get 200 or 503 (WebAuthn not available), not 404
	assert.NotEqual(t, http.StatusNotFound, w.Code)

	// Test WebAuthn login begin endpoint exists
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/user/login-webauthn-begin", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

func TestSetupAuthRouter_TokenRefreshRoute(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()

	store, err := backend.New(nil, cfg)
	require.NoError(t, err)
	defer store.Close()

	services := service.NewServices(store, cfg, logger)
	roles := []string{"auth"}

	gin.SetMode(gin.TestMode)
	router := setupAuthRouter(cfg, services, store, logger, roles)

	// Test token refresh endpoint exists
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/user/token/refresh", nil)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	// Should get 400 (bad request - missing body) or 503 (WebAuthn not available), not 404
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

func TestSetupAuthRouter_ProtectedRoutesRequireAuth(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()

	store, err := backend.New(nil, cfg)
	require.NoError(t, err)
	defer store.Close()

	services := service.NewServices(store, cfg, logger)
	roles := []string{"auth"}

	gin.SetMode(gin.TestMode)
	router := setupAuthRouter(cfg, services, store, logger, roles)

	// Test protected routes without auth token return 401
	protectedRoutes := []struct {
		method string
		path   string
	}{
		{"GET", "/user/session/account-info"},
		{"POST", "/user/session/settings"},
		{"POST", "/user/session/webauthn/register-begin"},
		{"DELETE", "/user/session"},
		{"POST", "/user/logout"},
	}

	for _, route := range protectedRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(route.method, route.path, nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusUnauthorized, w.Code, "Expected 401 for %s %s", route.method, route.path)
		})
	}
}

func TestSetupAuthRouter_AuthCheckHelper(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()

	store, err := backend.New(nil, cfg)
	require.NoError(t, err)
	defer store.Close()

	services := service.NewServices(store, cfg, logger)
	roles := []string{"auth"}

	gin.SetMode(gin.TestMode)
	router := setupAuthRouter(cfg, services, store, logger, roles)

	// Test auth check helper (GET)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/helper/auth-check", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test auth check helper (POST)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/helper/auth-check", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
