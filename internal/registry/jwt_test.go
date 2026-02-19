package registry

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testJWTLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func generateTestToken(secret, issuer string, expiry time.Duration) string {
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func generateExpiredToken(secret, issuer string) string {
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func TestJWTMiddleware_NoHeader_AuthNotRequired(t *testing.T) {
	config := JWTConfig{
		Secret:      "test-secret",
		Issuer:      "test-issuer",
		RequireAuth: false,
	}
	logger := testJWTLogger()

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		authenticated := isAuthenticated(c)
		c.JSON(http.StatusOK, gin.H{"authenticated": authenticated})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"authenticated":false`)
}

func TestJWTMiddleware_NoHeader_AuthRequired(t *testing.T) {
	config := JWTConfig{
		Secret:      "test-secret",
		Issuer:      "test-issuer",
		RequireAuth: true,
	}
	logger := testJWTLogger()

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

func TestJWTMiddleware_ValidToken(t *testing.T) {
	secret := "test-secret"
	issuer := "test-issuer"

	config := JWTConfig{
		Secret:      secret,
		Issuer:      issuer,
		RequireAuth: false,
	}
	logger := testJWTLogger()

	token := generateTestToken(secret, issuer, 1*time.Hour)

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		authenticated := isAuthenticated(c)
		c.JSON(http.StatusOK, gin.H{"authenticated": authenticated})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"authenticated":true`)
}

func TestJWTMiddleware_ExpiredToken_AuthNotRequired(t *testing.T) {
	secret := "test-secret"
	issuer := "test-issuer"

	config := JWTConfig{
		Secret:      secret,
		Issuer:      issuer,
		RequireAuth: false,
	}
	logger := testJWTLogger()

	token := generateExpiredToken(secret, issuer)

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		authenticated := isAuthenticated(c)
		c.JSON(http.StatusOK, gin.H{"authenticated": authenticated})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	// Should proceed but not be authenticated
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"authenticated":false`)
}

func TestJWTMiddleware_ExpiredToken_AuthRequired(t *testing.T) {
	secret := "test-secret"
	issuer := "test-issuer"

	config := JWTConfig{
		Secret:      secret,
		Issuer:      issuer,
		RequireAuth: true,
	}
	logger := testJWTLogger()

	token := generateExpiredToken(secret, issuer)

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired token")
}

func TestJWTMiddleware_WrongSecret(t *testing.T) {
	config := JWTConfig{
		Secret:      "correct-secret",
		Issuer:      "test-issuer",
		RequireAuth: true,
	}
	logger := testJWTLogger()

	// Generate token with wrong secret
	token := generateTestToken("wrong-secret", "test-issuer", 1*time.Hour)

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTMiddleware_WrongIssuer(t *testing.T) {
	secret := "test-secret"

	config := JWTConfig{
		Secret:      secret,
		Issuer:      "expected-issuer",
		RequireAuth: true,
	}
	logger := testJWTLogger()

	// Generate token with wrong issuer
	token := generateTestToken(secret, "wrong-issuer", 1*time.Hour)

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTMiddleware_InvalidHeaderFormat(t *testing.T) {
	config := JWTConfig{
		Secret:      "test-secret",
		Issuer:      "test-issuer",
		RequireAuth: true,
	}
	logger := testJWTLogger()

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		name   string
		header string
	}{
		{"no bearer", "some-token"},
		{"basic instead of bearer", "Basic dXNlcjpwYXNz"},
		{"just bearer", "Bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.header)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

func TestJWTMiddleware_InvalidToken(t *testing.T) {
	config := JWTConfig{
		Secret:      "test-secret",
		Issuer:      "test-issuer",
		RequireAuth: true,
	}
	logger := testJWTLogger()

	router := gin.New()
	router.Use(JWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	tests := []struct {
		name  string
		token string
	}{
		{"garbage", "Bearer not-a-jwt"},
		{"malformed jwt", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.garbage"},
		{"empty token", "Bearer "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.token)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

func TestJWTMiddleware_DifferentSigningMethods(t *testing.T) {
	secret := "test-secret-at-least-32-chars-long-for-hs384"
	issuer := "test-issuer"

	config := JWTConfig{
		Secret:      secret,
		Issuer:      issuer,
		RequireAuth: true,
	}
	logger := testJWTLogger()

	tests := []struct {
		name   string
		method jwt.SigningMethod
		valid  bool
	}{
		{"HS256", jwt.SigningMethodHS256, true},
		{"HS384", jwt.SigningMethodHS384, true},
		{"HS512", jwt.SigningMethodHS512, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.RegisteredClaims{
				Issuer:    issuer,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			}
			token := jwt.NewWithClaims(tt.method, claims)
			tokenString, err := token.SignedString([]byte(secret))
			require.NoError(t, err)

			router := gin.New()
			router.Use(JWTMiddleware(config, logger))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)
			router.ServeHTTP(w, req)

			if tt.valid {
				assert.Equal(t, http.StatusOK, w.Code)
			} else {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
			}
		})
	}
}

func TestJWTMiddleware_CaseInsensitiveBearer(t *testing.T) {
	secret := "test-secret"
	issuer := "test-issuer"

	config := JWTConfig{
		Secret:      secret,
		Issuer:      issuer,
		RequireAuth: true,
	}
	logger := testJWTLogger()

	token := generateTestToken(secret, issuer, 1*time.Hour)

	tests := []struct {
		name   string
		bearer string
	}{
		{"lowercase", "bearer"},
		{"uppercase", "BEARER"},
		{"mixed", "BeArEr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(JWTMiddleware(config, logger))
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.bearer+" "+token)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestOptionalJWTMiddleware(t *testing.T) {
	config := JWTConfig{
		Secret:      "test-secret",
		Issuer:      "test-issuer",
		RequireAuth: true, // This should be overridden
	}
	logger := testJWTLogger()

	router := gin.New()
	router.Use(OptionalJWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		authenticated := isAuthenticated(c)
		c.JSON(http.StatusOK, gin.H{"authenticated": authenticated})
	})

	// Request without auth should still succeed
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"authenticated":false`)
}

func TestOptionalJWTMiddleware_WithValidToken(t *testing.T) {
	secret := "test-secret"
	issuer := "test-issuer"

	config := JWTConfig{
		Secret:      secret,
		Issuer:      issuer,
		RequireAuth: true, // Overridden by OptionalJWTMiddleware
	}
	logger := testJWTLogger()

	token := generateTestToken(secret, issuer, 1*time.Hour)

	router := gin.New()
	router.Use(OptionalJWTMiddleware(config, logger))
	router.GET("/test", func(c *gin.Context) {
		authenticated := isAuthenticated(c)
		c.JSON(http.StatusOK, gin.H{"authenticated": authenticated})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"authenticated":true`)
}
