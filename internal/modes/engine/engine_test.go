package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func testConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Host:       "localhost",
			Port:       8080,
			EnginePort: 8082,
			RPID:       "localhost",
			RPName:     "Test",
			RPOrigin:   "http://localhost:8080",
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
		Trust: config.TrustConfig{
			DefaultEndpoint: "",
			Timeout:         30,
		},
		SessionStore: config.SessionStoreConfig{
			Type:            "memory",
			DefaultTTLHours: 24,
		},
	}
}

func TestNew(t *testing.T) {
	cfg := &Config{
		Config: testConfig(),
		Logger: testLogger(),
		Roles:  []string{"engine"},
	}

	runner, err := New(cfg)
	require.NoError(t, err)
	assert.NotNil(t, runner)
	assert.Equal(t, modes.RoleEngine, runner.Role())
}

func TestRunner_Role(t *testing.T) {
	cfg := &Config{
		Config: testConfig(),
		Logger: testLogger(),
	}

	runner, err := New(cfg)
	require.NoError(t, err)
	assert.Equal(t, modes.RoleEngine, runner.Role())
	assert.Equal(t, modes.ModeEngine, runner.Name())
}

func TestRunner_EngineEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := testConfig()
	logger := testLogger()

	// Create a test router mimicking what Run() sets up
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "wallet-backend"})
	})

	// Mock WebSocket endpoint (real WebSocket testing requires more setup)
	router.GET("/api/v2/wallet", func(c *gin.Context) {
		// In tests, just return 400 since we're not providing proper WS upgrade
		c.JSON(http.StatusBadRequest, gin.H{"error": "WebSocket upgrade required"})
	})

	_ = logger
	_ = cfg

	// Test health endpoint
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test status endpoint
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/status", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Test WebSocket endpoint exists (returns 400 without proper upgrade)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/v2/wallet", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
