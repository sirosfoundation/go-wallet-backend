package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func createTestConfig(jwtSecret string) *config.Config {
	return &config.Config{
		JWT: config.JWTConfig{
			Secret:      jwtSecret,
			ExpiryHours: 1,
		},
	}
}

func createValidToken(secret string, userID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func createExpiredToken(secret string, userID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(-time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func createTokenWithTenantID(secret string, userID string, tenantID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   userID,
		"tenant_id": tenantID,
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

// Helper function to create a test store with default tenant
func createTestStore(t *testing.T) storage.Store {
	store := memory.NewStore()
	// Default tenant is auto-created by memory store
	return store
}

// Helper function to add custom tenant to store
func addTestTenant(t *testing.T, store storage.Store, tenantID string, enabled bool) {
	tenant := &domain.Tenant{
		ID:          domain.TenantID(tenantID),
		Name:        tenantID,
		DisplayName: tenantID,
		Enabled:     enabled,
	}
	if err := store.Tenants().Create(t.Context(), tenant); err != nil {
		t.Fatalf("Failed to create test tenant: %v", err)
	}
}

// Helper function to create a test router with auth middleware and a success handler
func createTestRouter(cfg *config.Config, store storage.Store, logger *zap.Logger) *gin.Engine {
	router := gin.New()
	router.Use(AuthMiddleware(cfg, store, logger))
	router.GET("/test", func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user_id not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})
	return router
}

func TestAuthMiddleware_NoAuthHeader(t *testing.T) {
	logger := zap.NewNop()
	cfg := createTestConfig("test-secret")
	store := createTestStore(t)
	router := createTestRouter(cfg, store, logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddleware_InvalidFormat(t *testing.T) {
	logger := zap.NewNop()
	cfg := createTestConfig("test-secret")
	store := createTestStore(t)
	router := createTestRouter(cfg, store, logger)

	tests := []struct {
		name   string
		header string
	}{
		{"no bearer prefix", "invalid-token"},
		{"only bearer", "Bearer"},
		{"empty value", "Bearer "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", tt.header)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
			}
		})
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	logger := zap.NewNop()
	cfg := createTestConfig("test-secret")
	store := createTestStore(t)
	router := createTestRouter(cfg, store, logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-jwt-token")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddleware_ExpiredToken(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore(t)
	router := createTestRouter(cfg, store, logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+createExpiredToken(secret, "user-123"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore(t)
	router := createTestRouter(cfg, store, logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+createValidToken(secret, "user-123"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestAuthMiddleware_WrongSecret(t *testing.T) {
	logger := zap.NewNop()
	cfg := createTestConfig("correct-secret")
	store := createTestStore(t)
	router := createTestRouter(cfg, store, logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// Token signed with different secret
	req.Header.Set("Authorization", "Bearer "+createValidToken("wrong-secret", "user-123"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddleware_ExtractsTenantID(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore(t)

	// Add custom tenant for this test
	addTestTenant(t, store, "test-tenant", true)

	// Create a router that returns the tenant_id from context
	router := gin.New()
	router.Use(AuthMiddleware(cfg, store, logger))
	router.GET("/test", func(c *gin.Context) {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant_id not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"tenant_id": tenantID})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+createTokenWithTenantID(secret, "user-123", "test-tenant"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify the tenant_id was extracted correctly
	expected := `{"tenant_id":"test-tenant"}`
	if w.Body.String() != expected {
		t.Errorf("Expected body %s, got %s", expected, w.Body.String())
	}
}

func TestAuthMiddleware_DefaultsTenantIDWhenMissing(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore(t)

	// Create a router that returns the tenant_id from context
	router := gin.New()
	router.Use(AuthMiddleware(cfg, store, logger))
	router.GET("/test", func(c *gin.Context) {
		tenantID, exists := c.Get("tenant_id")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant_id not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"tenant_id": tenantID})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// Use a token without tenant_id
	req.Header.Set("Authorization", "Bearer "+createValidToken(secret, "user-123"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify the tenant_id defaults to "default"
	expected := `{"tenant_id":"default"}`
	if w.Body.String() != expected {
		t.Errorf("Expected body %s, got %s", expected, w.Body.String())
	}
}

func TestAuthMiddleware_InvalidTenantInJWT(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore(t)

	router := gin.New()
	router.Use(AuthMiddleware(cfg, store, logger))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// Use a token with a nonexistent tenant
	req.Header.Set("Authorization", "Bearer "+createTokenWithTenantID(secret, "user-123", "nonexistent-tenant"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d for invalid tenant, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddleware_DisabledTenantInJWT(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore(t)

	// Add a disabled tenant
	addTestTenant(t, store, "disabled-tenant", false)

	router := gin.New()
	router.Use(AuthMiddleware(cfg, store, logger))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// Use a token with a disabled tenant
	req.Header.Set("Authorization", "Bearer "+createTokenWithTenantID(secret, "user-123", "disabled-tenant"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status %d for disabled tenant, got %d", http.StatusForbidden, w.Code)
	}
}

func TestAuthMiddleware_HeaderTenantMismatch(t *testing.T) {
	// Test that JWT tenant takes precedence even when X-Tenant-ID header differs
	// The request should succeed but the header mismatch should be logged
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore(t)

	addTestTenant(t, store, "jwt-tenant", true)
	addTestTenant(t, store, "header-tenant", true)

	router := gin.New()
	router.Use(AuthMiddleware(cfg, store, logger))
	router.GET("/test", func(c *gin.Context) {
		tenantID, _ := c.Get("tenant_id")
		c.JSON(http.StatusOK, gin.H{"tenant_id": tenantID})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// JWT has "jwt-tenant" but header has "header-tenant"
	req.Header.Set("Authorization", "Bearer "+createTokenWithTenantID(secret, "user-123", "jwt-tenant"))
	req.Header.Set("X-Tenant-ID", "header-tenant")
	router.ServeHTTP(w, req)

	// Should succeed with JWT tenant (JWT is authoritative)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Should use JWT tenant, not header tenant
	expected := `{"tenant_id":"jwt-tenant"}`
	if w.Body.String() != expected {
		t.Errorf("Expected body %s, got %s", expected, w.Body.String())
	}
}

func TestAuthMiddleware_TenantObjectInContext(t *testing.T) {
	// Test that the full tenant object is available in context
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore(t)

	router := gin.New()
	router.Use(AuthMiddleware(cfg, store, logger))
	router.GET("/test", func(c *gin.Context) {
		tenant, exists := c.Get("tenant")
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant not found in context"})
			return
		}
		// Just verify we got something - actual type would be *domain.Tenant
		if tenant == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "tenant is nil"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+createValidToken(secret, "user-123"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestLogger(t *testing.T) {
	logger := zap.NewNop()

	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)

	router.Use(Logger(logger))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestLogger_WithDifferentMethods(t *testing.T) {
	logger := zap.NewNop()

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, router := gin.CreateTestContext(w)

			router.Use(Logger(logger))
			router.Handle(method, "/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			req := httptest.NewRequest(method, "/test", nil)
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
			}
		})
	}
}

// Tests for GenerateAdminToken
func TestGenerateAdminToken(t *testing.T) {
	token, err := GenerateAdminToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Token should be 64 hex characters (32 bytes encoded as hex)
	if len(token) != 64 {
		t.Errorf("Expected token length 64, got %d", len(token))
	}

	// Tokens should be unique
	token2, _ := GenerateAdminToken()
	if token == token2 {
		t.Error("Generated tokens should be unique")
	}
}

// Tests for AdminAuthMiddleware
func createAdminTestRouter(token string, logger *zap.Logger) *gin.Engine {
	router := gin.New()
	router.Use(AdminAuthMiddleware(token, logger))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	return router
}

func TestAdminAuthMiddleware_NoAuthHeader(t *testing.T) {
	logger := zap.NewNop()
	router := createAdminTestRouter("secret-token", logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAdminAuthMiddleware_InvalidFormat(t *testing.T) {
	logger := zap.NewNop()
	router := createAdminTestRouter("secret-token", logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAdminAuthMiddleware_EmptyToken(t *testing.T) {
	logger := zap.NewNop()
	router := createAdminTestRouter("secret-token", logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer ")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAdminAuthMiddleware_InvalidToken(t *testing.T) {
	logger := zap.NewNop()
	router := createAdminTestRouter("secret-token", logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAdminAuthMiddleware_ValidToken(t *testing.T) {
	logger := zap.NewNop()
	token := "secret-token"
	router := createAdminTestRouter(token, logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestAdminAuthMiddleware_CaseInsensitiveBearer(t *testing.T) {
	logger := zap.NewNop()
	token := "secret-token"
	router := createAdminTestRouter(token, logger)

	// Test with lowercase "bearer"
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d with lowercase bearer, got %d", http.StatusOK, w.Code)
	}
}
