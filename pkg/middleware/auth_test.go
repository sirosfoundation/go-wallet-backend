package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

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

// Helper function to create a test router with auth middleware and a success handler
func createTestRouter(cfg *config.Config, logger *zap.Logger) *gin.Engine {
	router := gin.New()
	router.Use(AuthMiddleware(cfg, logger))
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
	router := createTestRouter(cfg, logger)

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
	router := createTestRouter(cfg, logger)

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
	router := createTestRouter(cfg, logger)

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
	router := createTestRouter(cfg, logger)

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
	router := createTestRouter(cfg, logger)

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
	router := createTestRouter(cfg, logger)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	// Token signed with different secret
	req.Header.Set("Authorization", "Bearer "+createValidToken("wrong-secret", "user-123"))
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
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
