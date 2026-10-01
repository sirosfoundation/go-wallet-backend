package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
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
			Issuer:      "test-issuer",
			ExpiryHours: 1,
		},
	}
}

func createValidToken(secret string, userID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":     "test-issuer",
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

func createExpiredToken(secret string, userID string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":     "test-issuer",
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
		"iss":     "test-issuer",
		"user_id": userID,
		"jti":     jti,
		"iat":     issuedAt.Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(secret))
	return tokenString
}

// createTokenWithSID builds a legacy HMAC access token carrying a "sid"
// claim (the refresh-token family/session id - see
// service.WebAuthnService.generateToken's doc comment), for testing #402's
// family-revocation check.
func createTokenWithSID(secret, userID, jti, sid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"jti":     jti,
		"sid":     sid,
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
		"iss": "test-issuer",
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

// TestAuthMiddlewareWithBlacklist_RevokedFamilyTokenRejected is a regression
// test for #402: an access token carrying a "sid" claim must be rejected
// once Logout has revoked that refresh-token family (TokenBlacklist.
// RevokeFamily), even though this specific access token's own jti was
// never individually blacklisted - proving the actual security gap #402
// was filed for: a still-valid access token from the same session as a
// stolen/still-held refresh token must also stop working once that session
// is logged out, not linger until it naturally expires.
func TestAuthMiddlewareWithBlacklist_RevokedFamilyTokenRejected(t *testing.T) {
	logger := zap.NewNop()
	secret := "test-secret"
	cfg := createTestConfig(secret)
	cfg.Security.TokenBlacklist.Enabled = true
	store := createTestStore()

	blacklist := service.NewTokenBlacklist(cfg.Security.TokenBlacklist, logger)
	router := createBlacklistTestRouter(cfg, store, blacklist, logger)

	tokenStr := createTokenWithSID(secret, "user-123", "jti-family-1", "sid-family-1")

	// Token works before the family is revoked.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 before family revocation, got %d: %s", w.Code, w.Body.String())
	}

	// Simulate Logout revoking the whole family (see api.Handlers.Logout).
	if err := blacklist.RevokeFamily(context.Background(), "sid-family-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	// The same access token - its own jti never individually blacklisted -
	// must now be rejected too.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a token whose refresh-token family was revoked, got %d: %s", w.Code, w.Body.String())
	}

	// A token from a DIFFERENT family must be unaffected.
	otherToken := createTokenWithSID(secret, "user-789", "jti-family-2", "sid-family-2")
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+otherToken)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for a token from an unrelated, non-revoked family, got %d: %s", w.Code, w.Body.String())
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

func TestAuthMiddlewareWithBlacklist_RefusesHMACWhenLegacyDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "0123456789abcdef0123456789abcdef", Issuer: "test-issuer"}}
	cfg.AS.Enabled = true // AS on + legacy off => legacy disabled
	tok := gojwtSigned(t, []byte(cfg.JWT.Secret), map[string]any{"user_id": "u", "tenant_id": "default"})

	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	reached := false
	r.GET("/t", AuthMiddlewareWithBlacklist(cfg, nil, nil, zap.NewNop()), func(c *gin.Context) { reached = true })
	req := httptest.NewRequest("GET", "/t", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(w, req)
	if w.Code != 401 || reached {
		t.Errorf("valid HMAC token must be refused when legacy is disabled, got %d reached=%v", w.Code, reached)
	}
}

// A loaded config (as Load() builds it) with as.legacy.enabled=false and the
// AS disabled in this process must still refuse HMAC on the no-AS path.
func TestAuthMiddlewareWithBlacklist_LoadedConfigLegacyOff(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	p := dir + "/c.yaml"
	yaml := "server:\n  rp_id: localhost\n  rp_origin: http://localhost:8080\njwt:\n  secret: test-secret-that-is-at-least-32-bytes!\nas:\n  legacy:\n    enabled: false\n"
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	tok := gojwtSigned(t, []byte(cfg.JWT.Secret), map[string]any{"user_id": "u", "tenant_id": "default"})
	w := httptest.NewRecorder()
	_, r := gin.CreateTestContext(w)
	r.GET("/t", AuthMiddlewareWithBlacklist(cfg, nil, nil, zap.NewNop()), func(c *gin.Context) { c.Status(200) })
	req := httptest.NewRequest("GET", "/t", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddlewareWithBlacklist_LegacyIssuerPinned(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "0123456789abcdef0123456789abcdef"
	serve := func(cfg *config.Config, tok string) int {
		w := httptest.NewRecorder()
		_, r := gin.CreateTestContext(w)
		r.GET("/t", AuthMiddlewareWithBlacklist(cfg, nil, nil, zap.NewNop()), func(c *gin.Context) { c.Status(200) })
		req := httptest.NewRequest("GET", "/t", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		r.ServeHTTP(w, req)
		return w.Code
	}
	mint := func(claims map[string]any) string {
		h := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range claims {
			h[k] = v
		}
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, h).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret, Issuer: "wallet-backend"}}
	// The token is refused at the issuer check, before any store lookup, so a
	// nil store is fine for the rejection cases; the accepted case is covered
	// by the other tests with a real store.
	if code := serve(cfg, mint(map[string]any{"user_id": "u", "tenant_id": "default"})); code != 401 {
		t.Errorf("missing iss: got %d want 401", code)
	}
	if code := serve(cfg, mint(map[string]any{"user_id": "u", "tenant_id": "default", "iss": "other"})); code != 401 {
		t.Errorf("mismatched iss: got %d want 401", code)
	}
	empty := &config.Config{JWT: config.JWTConfig{Secret: secret}}
	if code := serve(empty, mint(map[string]any{"user_id": "u", "tenant_id": "default", "iss": ""})); code != 401 {
		t.Errorf("empty jwt.issuer must fail closed: got %d want 401", code)
	}
}
