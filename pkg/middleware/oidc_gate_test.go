package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

func init() {
	gin.SetMode(gin.TestMode)
}

type mockTenantStore struct {
	tenant *domain.Tenant
	err    error
}

func (m *mockTenantStore) GetTenant(id string) (*domain.Tenant, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.tenant, nil
}

func TestOIDCGateMiddleware_NoGate(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	// Tenant with no OIDC gate (mode = none)
	tenant := &domain.Tenant{
		ID:   "test-tenant",
		Name: "Test Tenant",
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeNone,
		},
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant", tenant)
		c.Next()
	})
	router.Use(OIDCGateMiddleware(cache, "registration", logger))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOIDCGateMiddleware_GateEnabled_NoToken(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	// Tenant with registration gate enabled
	tenant := &domain.Tenant{
		ID:   "test-tenant",
		Name: "Test Tenant",
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeRegistration,
			RegistrationOP: &domain.OIDCProviderConfig{
				DisplayName: "Corporate SSO",
				Issuer:      "https://idp.example.com",
				ClientID:    "wallet-client",
				Scopes:      "openid profile email groups",
			},
		},
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant", tenant)
		c.Next()
	})
	router.Use(OIDCGateMiddleware(cache, "registration", logger))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "oidc_gate_required", resp["error"])

	oidcConfig, ok := resp["oidc_config"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "https://idp.example.com", oidcConfig["issuer"])
	assert.Equal(t, "wallet-client", oidcConfig["client_id"])
	assert.Equal(t, "Corporate SSO", oidcConfig["display_name"])
	assert.Equal(t, "openid profile email groups", oidcConfig["scopes"])
}

func TestOIDCGateMiddleware_LoginGate_NoToken(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	// Tenant with login gate enabled - no display_name or scopes (tests defaults)
	tenant := &domain.Tenant{
		ID:   "test-tenant",
		Name: "Test Tenant",
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeLogin,
			LoginOP: &domain.OIDCProviderConfig{
				Issuer:   "https://login-idp.example.com",
				ClientID: "wallet-login",
				// No DisplayName or Scopes - should use defaults
			},
		},
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant", tenant)
		c.Next()
	})
	router.Use(OIDCGateMiddleware(cache, "login", logger))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "oidc_gate_required", resp["error"])

	oidcConfig, ok := resp["oidc_config"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "https://login-idp.example.com", oidcConfig["issuer"])
	assert.Equal(t, "wallet-login", oidcConfig["client_id"])
	// Default display_name falls back to issuer URL
	assert.Equal(t, "https://login-idp.example.com", oidcConfig["display_name"])
	// Default scopes
	assert.Equal(t, "openid profile email", oidcConfig["scopes"])
}

func TestOIDCGateMiddleware_BothMode(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	// Tenant with both gates enabled
	tenant := &domain.Tenant{
		ID:   "test-tenant",
		Name: "Test Tenant",
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeBoth,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://reg-idp.example.com",
				ClientID: "wallet-reg",
			},
			LoginOP: &domain.OIDCProviderConfig{
				Issuer:   "https://login-idp.example.com",
				ClientID: "wallet-login",
			},
		},
	}

	// Test registration gate
	t.Run("registration", func(t *testing.T) {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("tenant", tenant)
			c.Next()
		})
		router.Use(OIDCGateMiddleware(cache, "registration", logger))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("POST", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		oidcConfig := resp["oidc_config"].(map[string]interface{})
		assert.Equal(t, "https://reg-idp.example.com", oidcConfig["issuer"])
	})

	// Test login gate
	t.Run("login", func(t *testing.T) {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("tenant", tenant)
			c.Next()
		})
		router.Use(OIDCGateMiddleware(cache, "login", logger))
		router.POST("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		req := httptest.NewRequest("POST", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		oidcConfig := resp["oidc_config"].(map[string]interface{})
		assert.Equal(t, "https://login-idp.example.com", oidcConfig["issuer"])
	})
}

func TestOIDCGateMiddleware_WrongGateType(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	// Tenant with only registration gate (login gate not set)
	tenant := &domain.Tenant{
		ID:   "test-tenant",
		Name: "Test Tenant",
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeRegistration,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "wallet-client",
			},
		},
	}

	// Login endpoint should not be gated since mode is registration-only
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant", tenant)
		c.Next()
	})
	router.Use(OIDCGateMiddleware(cache, "login", logger))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should pass through since login gate is not enabled for registration-only mode
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOIDCGateMiddleware_NoTenant(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	router := gin.New()
	// No tenant in context
	router.Use(OIDCGateMiddleware(cache, "registration", logger))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should pass through since no tenant means no gate config
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOIDCGateMiddleware_InvalidToken(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	// Tenant with gate enabled
	tenant := &domain.Tenant{
		ID:   "test-tenant",
		Name: "Test Tenant",
		OIDCGate: domain.OIDCGateConfig{
			Mode: domain.OIDCGateModeRegistration,
			RegistrationOP: &domain.OIDCProviderConfig{
				Issuer:   "https://idp.example.com",
				ClientID: "wallet-client",
			},
		},
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("tenant", tenant)
		c.Next()
	})
	router.Use(OIDCGateMiddleware(cache, "registration", logger))
	router.POST("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return 401 with oidc_config since token is invalid
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "oidc_gate_required", resp["error"])
}

func TestValidatorCache_GetOrCreate(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	config1 := &domain.OIDCProviderConfig{
		Issuer:   "https://idp1.example.com",
		ClientID: "client1",
	}

	config2 := &domain.OIDCProviderConfig{
		Issuer:   "https://idp2.example.com",
		ClientID: "client2",
	}

	// Get validators
	v1a := cache.GetOrCreate(config1)
	v1b := cache.GetOrCreate(config1)
	v2 := cache.GetOrCreate(config2)

	// Same config should return same validator
	assert.Same(t, v1a, v1b)

	// Different config should return different validator
	assert.NotSame(t, v1a, v2)
}

func TestValidatorCache_CustomAudience(t *testing.T) {
	logger := zaptest.NewLogger(t)
	cache := NewValidatorCache(nil, logger)

	config := &domain.OIDCProviderConfig{
		Issuer:   "https://idp.example.com",
		ClientID: "wallet-client",
		Audience: "custom-audience", // Custom audience different from client_id
	}

	v := cache.GetOrCreate(config)
	assert.NotNil(t, v)
}
