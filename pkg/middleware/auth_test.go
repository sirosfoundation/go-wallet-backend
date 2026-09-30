package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
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

// createTokenWithJTI creates a valid, non-expired token carrying a specific
// jti and iat, for exercising blacklist/revocation checks.
func createTokenWithJTI(secret, userID, jti string, issuedAt time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"jti":     jti,
		"iat":     issuedAt.Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
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

// createTestStore creates a memory store with a default tenant for testing
func createTestStore() storage.Store {
	store := memory.NewStore()
	// Create default tenant that JWT tokens reference
	_ = store.Tenants().Create(context.Background(), &domain.Tenant{
		ID:      domain.DefaultTenantID,
		Name:    "Default",
		Enabled: true,
	})
	return store
}

func TestAuthMiddleware_NoAuthHeader(t *testing.T) {
	logger := zap.NewNop()
	cfg := createTestConfig("test-secret")
	store := createTestStore()
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
	store := createTestStore()
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
	store := createTestStore()
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
	store := createTestStore()
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
	store := createTestStore()
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
	store := createTestStore()
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

func TestAuthMiddleware_MissingUserID(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	store := createTestStore()
	router := createTestRouter(cfg, store, logger)

	// A token that's otherwise valid (correctly signed, not expired) but
	// carries no "user_id" claim at all.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// createBlacklistTestRouter is like createTestRouter but wires
// AuthMiddlewareWithBlacklist with a real blacklist, the same way
// internal/server/providers.go wires it for production request paths (see
// #382 - AuthMiddleware itself hardcodes a nil blacklist and is
// deliberately NOT used here).
func createBlacklistTestRouter(cfg *config.Config, store storage.Store, blacklist TokenBlacklistChecker, logger *zap.Logger) *gin.Engine {
	router := gin.New()
	router.Use(AuthMiddlewareWithBlacklist(cfg, store, blacklist, logger))
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

func TestAuthMiddlewareWithBlacklist_LoggedOutTokenRejected(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	cfg.Security.TokenBlacklist.Enabled = true
	store := createTestStore()

	// The real blacklist implementation backing Logout (internal/api/
	// handlers.go), constructed the same way service.NewServices does,
	// wired directly into AuthMiddlewareWithBlacklist - not a test double -
	// proving the actual wired configuration, not just that the middleware
	// accepts a blacklist when handed one manually.
	blacklist := service.NewTokenBlacklist(cfg.Security.TokenBlacklist, logger)
	router := createBlacklistTestRouter(cfg, store, blacklist, logger)

	tokenStr := createTokenWithJTI(secret, "user-123", "jti-logout-1", time.Now())

	// Token works before logout.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 before logout, got %d: %s", w.Code, w.Body.String())
	}

	// Simulate Logout blacklisting this token's jti (see
	// api.Handlers.Logout).
	if err := blacklist.Add(context.Background(), "jti-logout-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// The same token must now be rejected.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for logged-out token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthMiddlewareWithBlacklist_DeletedUserTokenRejected(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	cfg.Security.TokenBlacklist.Enabled = true
	store := createTestStore()

	blacklist := service.NewTokenBlacklist(cfg.Security.TokenBlacklist, logger)
	router := createBlacklistTestRouter(cfg, store, blacklist, logger)

	issuedAt := time.Now().Add(-time.Minute)
	tokenStr := createTokenWithJTI(secret, "user-456", "jti-predelete", issuedAt)

	// Token works before deletion.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 before deletion, got %d: %s", w.Code, w.Body.String())
	}

	// Simulate account deletion (see UserService.DeleteUser /
	// SetTokenBlacklist): revokes every token for the user, not just one jti.
	if err := blacklist.RevokeUser(context.Background(), "user-456"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}

	// The token issued before deletion must now be rejected, even though its
	// own jti was never individually blacklisted.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for deleted user's token, got %d: %s", w.Code, w.Body.String())
	}

	// A token for a different, non-deleted user must still work.
	otherToken := createTokenWithJTI(secret, "user-789", "jti-other", time.Now())
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for unrelated user's token, got %d: %s", w.Code, w.Body.String())
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
