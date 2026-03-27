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
	router.Use(OIDCGateMiddleware(cache, GateTypeRegistration, logger))
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
	router.Use(OIDCGateMiddleware(cache, GateTypeRegistration, logger))
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
	router.Use(OIDCGateMiddleware(cache, GateTypeLogin, logger))
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
		router.Use(OIDCGateMiddleware(cache, GateTypeRegistration, logger))
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
		router.Use(OIDCGateMiddleware(cache, GateTypeLogin, logger))
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
	router.Use(OIDCGateMiddleware(cache, GateTypeLogin, logger))
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
	router.Use(OIDCGateMiddleware(cache, GateTypeRegistration, logger))
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
	router.Use(OIDCGateMiddleware(cache, GateTypeRegistration, logger))
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

func TestClaimsMatch(t *testing.T) {
	tests := []struct {
		name     string
		expected interface{}
		actual   interface{}
		want     bool
	}{
		// Basic type matching
		{name: "bool true match", expected: true, actual: true, want: true},
		{name: "bool false match", expected: false, actual: false, want: true},
		{name: "bool mismatch", expected: true, actual: false, want: false},
		{name: "string match", expected: "admin", actual: "admin", want: true},
		{name: "string mismatch", expected: "admin", actual: "user", want: false},
		{name: "float match", expected: 1.5, actual: 1.5, want: true},
		{name: "float mismatch", expected: 1.5, actual: 2.5, want: false},
		{name: "int to float match", expected: 42, actual: float64(42), want: true},
		{name: "int to float mismatch", expected: 42, actual: float64(43), want: false},

		// String in array matching (common for groups/roles)
		{name: "string in array", expected: "admin", actual: []interface{}{"admin", "user"}, want: true},
		{name: "string not in array", expected: "superadmin", actual: []interface{}{"admin", "user"}, want: false},
		{name: "string vs empty array", expected: "admin", actual: []interface{}{}, want: false},

		// Array subset matching
		{name: "array exact match", expected: []interface{}{"admin"}, actual: []interface{}{"admin"}, want: true},
		{name: "array subset match", expected: []interface{}{"admin"}, actual: []interface{}{"admin", "user"}, want: true},
		{name: "array superset no match", expected: []interface{}{"admin", "superadmin"}, actual: []interface{}{"admin"}, want: false},
		{name: "array all present", expected: []interface{}{"admin", "user"}, actual: []interface{}{"user", "admin", "guest"}, want: true},
		{name: "array order independent", expected: []interface{}{"b", "a"}, actual: []interface{}{"a", "b", "c"}, want: true},
		{name: "array partial missing", expected: []interface{}{"admin", "missing"}, actual: []interface{}{"admin", "user"}, want: false},

		// Single-element array vs scalar
		{name: "single array vs string", expected: []interface{}{"admin"}, actual: "admin", want: true},
		{name: "single array vs wrong string", expected: []interface{}{"admin"}, actual: "user", want: false},
		{name: "multi array vs string no match", expected: []interface{}{"admin", "user"}, actual: "admin", want: false},

		// Type mismatches
		{name: "string vs bool", expected: "true", actual: true, want: false},
		{name: "bool vs string", expected: true, actual: "true", want: false},
		{name: "string vs number", expected: "42", actual: float64(42), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claimsMatch(tt.expected, tt.actual)
			assert.Equal(t, tt.want, got, "claimsMatch(%v, %v) = %v, want %v", tt.expected, tt.actual, got, tt.want)
		})
	}
}
