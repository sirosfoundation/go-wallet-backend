package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestValidatorCache_EvictsLeastRecentlyUsedWhenFull(t *testing.T) {
	cache := NewValidatorCache(nil, zaptest.NewLogger(t))
	cache.maxEntries = 2
	clock := time.Now()
	cache.now = func() time.Time { return clock }

	cfg := func(n string) *domain.OIDCProviderConfig {
		return &domain.OIDCProviderConfig{Issuer: "https://" + n + ".example.com", ClientID: n}
	}

	a := cache.GetOrCreate(cfg("a"))
	clock = clock.Add(time.Second)
	cache.GetOrCreate(cfg("b"))
	clock = clock.Add(time.Second)
	assert.Same(t, a, cache.GetOrCreate(cfg("a"))) // touch a; b is now LRU
	clock = clock.Add(time.Second)
	cache.GetOrCreate(cfg("c")) // evicts b

	assert.Equal(t, 2, cache.Len())
	assert.Same(t, a, cache.GetOrCreate(cfg("a")), "recently used entry must survive")
}

func TestValidatorCache_DropsIdleEntries(t *testing.T) {
	cache := NewValidatorCache(nil, zaptest.NewLogger(t))
	cache.idleTTL = time.Minute
	clock := time.Now()
	cache.now = func() time.Time { return clock }

	old := &domain.OIDCProviderConfig{Issuer: "https://old.example.com", ClientID: "old"}
	v1 := cache.GetOrCreate(old)
	clock = clock.Add(2 * time.Minute)
	cache.GetOrCreate(&domain.OIDCProviderConfig{Issuer: "https://new.example.com", ClientID: "new"})

	assert.Equal(t, 1, cache.Len(), "idle entry must be dropped when a new one is added")
	assert.NotSame(t, v1, cache.GetOrCreate(old), "an evicted provider gets a fresh validator")
}

func TestValidatorCache_BoundedUnderChurn(t *testing.T) {
	cache := NewValidatorCache(nil, zaptest.NewLogger(t))
	cache.maxEntries = 8
	for i := 0; i < 100; i++ {
		cache.GetOrCreate(&domain.OIDCProviderConfig{Issuer: fmt.Sprintf("https://idp%d.example.com", i), ClientID: "c"})
	}
	assert.LessOrEqual(t, cache.Len(), 8)
}

// An entry idle past the TTL is a miss for the very lookup that finds it: it
// must be rebuilt, not revived by that lookup's own touch.
func TestValidatorCache_IdleEntryIsRebuiltOnLookup(t *testing.T) {
	cache := NewValidatorCache(nil, zaptest.NewLogger(t))
	cache.idleTTL = time.Minute
	clock := time.Now()
	cache.now = func() time.Time { return clock }

	cfg := &domain.OIDCProviderConfig{Issuer: "https://idp.example.com", ClientID: "c"}
	v1 := cache.GetOrCreate(cfg)

	clock = clock.Add(30 * time.Second)
	assert.Same(t, v1, cache.GetOrCreate(cfg), "within the TTL the entry is reused")

	clock = clock.Add(2 * time.Minute)
	v2 := cache.GetOrCreate(cfg)
	assert.NotSame(t, v1, v2, "an entry idle past the TTL must be rebuilt")
	assert.Equal(t, 1, cache.Len())
}
