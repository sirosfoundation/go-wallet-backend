package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gojose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/claims"
	"github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// stubTenantStore implements storage.TenantStore for testing.
type stubTenantStore struct {
	tenants map[domain.TenantID]*domain.Tenant
}

func (s *stubTenantStore) GetByID(_ context.Context, id domain.TenantID) (*domain.Tenant, error) {
	t, ok := s.tenants[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return t, nil
}

func (s *stubTenantStore) Create(context.Context, *domain.Tenant) error { return nil }
func (s *stubTenantStore) Update(context.Context, *domain.Tenant) error { return nil }
func (s *stubTenantStore) GetAll(context.Context) ([]*domain.Tenant, error) {
	return nil, nil
}

// setupTokenAuthTest creates a test JWKS server and validator.
func setupTokenAuthTest(t *testing.T) (*validator.Validator, *ecdsa.PrivateKey, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := gojose.JSONWebKey{Key: &key.PublicKey, KeyID: "test-key", Algorithm: string(gojose.ES256)}
	jwks := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{jwk}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	v := validator.New(validator.Config{
		JWKSURL: srv.URL,
		Issuer:  "test-issuer",
	})
	v.Start(context.Background())
	t.Cleanup(v.Stop)

	// Poll until the validator has actually fetched the JWKS, rather than
	// sleeping a fixed duration (flaky under slow/contended CI runners).
	probe := signToken(t, key, "test-issuer", claims.AccessTokenClaims{})
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := v.Validate(context.Background(), probe); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("validator did not fetch JWKS in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	return v, key, "test-issuer"
}

// signToken creates a signed JWT for testing.
func signToken(t *testing.T, key *ecdsa.PrivateKey, issuer string, cl claims.AccessTokenClaims) string {
	t.Helper()
	signer, err := gojose.NewSigner(
		gojose.SigningKey{Algorithm: gojose.ES256, Key: key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	cl.Claims = jwt.Claims{
		Issuer:    issuer,
		Subject:   cl.Claims.Subject,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
		Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	raw, err := jwt.Signed(signer).Claims(cl).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTokenAuthMiddleware_ValidToken(t *testing.T) {
	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"test-tenant": {ID: "test-tenant", Enabled: true},
	}}
	logger := zap.NewNop()

	token := signToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-123"},
		TenantID: "test-tenant",
		TAC:      "rwl",
	})

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(v, tenants, nil, logger))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"user_id":   c.GetString("user_id"),
			"tenant_id": c.GetString("tenant_id"),
		})
	})

	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, c.Request)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body) //nolint:errcheck
	if body["user_id"] != "user-123" {
		t.Errorf("expected user_id=user-123, got %s", body["user_id"])
	}
	if body["tenant_id"] != "test-tenant" {
		t.Errorf("expected tenant_id=test-tenant, got %s", body["tenant_id"])
	}
}

func TestTokenAuthMiddleware_MissingAuth(t *testing.T) {
	v, _, _ := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}}
	logger := zap.NewNop()

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(v, tenants, nil, logger))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestTokenAuthMiddleware_InvalidToken(t *testing.T) {
	v, _, _ := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}}
	logger := zap.NewNop()

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(v, tenants, nil, logger))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer invalid.token.here")
	r.ServeHTTP(w, c.Request)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestTokenAuthMiddleware_DisabledTenant(t *testing.T) {
	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"disabled": {ID: "disabled", Enabled: false},
	}}
	logger := zap.NewNop()

	token := signToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-123"},
		TenantID: "disabled",
		TAC:      "r",
	})

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(v, tenants, nil, logger))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, c.Request)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestTokenAuthMiddleware_UnknownTenant(t *testing.T) {
	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{}}
	logger := zap.NewNop()

	token := signToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-123"},
		TenantID: "nonexistent",
		TAC:      "r",
	})

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(v, tenants, nil, logger))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, c.Request)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

// TestTokenAuthMiddleware_RevokedUserDenied proves the #391 review fix:
// per-jti revocation is already enforced inside v.Validate itself (via the
// go-tokenauth Validator's own Revocation checker - see
// blacklistRevocationChecker in internal/server/providers.go), but that
// checker only ever sees a jti, never a user_id, so account deletion's
// bulk user-level revocation (TokenBlacklist.RevokeUser, #383) would
// otherwise never be consulted for a token validated through this path -
// only for the legacy AuthMiddlewareWithBlacklist path. TokenAuthMiddleware
// must check it itself, using the blacklist passed in directly.
func TestTokenAuthMiddleware_RevokedUserDenied(t *testing.T) {
	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"test-tenant": {ID: "test-tenant", Enabled: true},
	}}
	logger := zap.NewNop()

	token := signToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "revoked-user"},
		TenantID: "test-tenant",
		TAC:      "rwl",
	})

	blacklist := service.NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, logger)
	if err := blacklist.RevokeUser(context.Background(), "revoked-user"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(v, tenants, blacklist, logger))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked user, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTokenAuthMiddleware_NonRevokedUserAllowed is the sanity check for the
// test above: the same blacklist wiring still allows a token whose subject
// hasn't been revoked.
func TestTokenAuthMiddleware_NonRevokedUserAllowed(t *testing.T) {
	v, key, issuer := setupTokenAuthTest(t)
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"test-tenant": {ID: "test-tenant", Enabled: true},
	}}
	logger := zap.NewNop()

	token := signToken(t, key, issuer, claims.AccessTokenClaims{
		Claims:   jwt.Claims{Subject: "user-123"},
		TenantID: "test-tenant",
		TAC:      "rwl",
	})

	blacklist := service.NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, logger)
	if err := blacklist.RevokeUser(context.Background(), "some-other-user"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(v, tenants, blacklist, logger))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-revoked user, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMustHaveTAC_Sufficient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(func(c *gin.Context) {
		c.Set("tokenauth_result", &claims.Result{TAC: "rwla"})
		c.Next()
	})
	r.Use(MustHaveTAC("rw"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMustHaveTAC_Insufficient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(func(c *gin.Context) {
		c.Set("tokenauth_result", &claims.Result{TAC: "r"})
		c.Next()
	})
	r.Use(MustHaveTAC("rw"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestMustHaveTAC_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(MustHaveTAC("r"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireAudience_Match(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(func(c *gin.Context) {
		c.Set("tokenauth_result", &claims.Result{Audience: []string{"wallet-registry"}})
		c.Next()
	})
	r.Use(RequireAudience("wallet-registry", "wallet-backend"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequireAudience_NoMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(func(c *gin.Context) {
		c.Set("tokenauth_result", &claims.Result{Audience: []string{"wallet-registry"}})
		c.Next()
	})
	r.Use(RequireAudience("wallet-backend"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireAudience_EmptyAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(func(c *gin.Context) {
		c.Set("tokenauth_result", &claims.Result{})
		c.Next()
	})
	r.Use(RequireAudience("wallet-backend"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestRequireAudience_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.Use(RequireAudience("wallet-backend"))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireAudience_PanicsWithNoAllowedAudiences(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected RequireAudience() with no arguments to panic")
		}
	}()
	RequireAudience()
}

func TestExtractBearer(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"valid", "Bearer abc123", "abc123"},
		{"empty", "", ""},
		{"no bearer", "Basic abc123", ""},
		{"case insensitive", "bearer abc123", "abc123"},
		{"no token", "Bearer ", ""},
		{"extra spaces", "Bearer  abc123 ", "abc123"},
	}

	gin.SetMode(gin.TestMode)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				c.Request.Header.Set("Authorization", tt.header)
			}
			got := extractBearer(c)
			if got != tt.want {
				t.Errorf("extractBearer() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTokenAuthMiddleware_LegacyAllowedGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	secret := []byte("0123456789abcdef0123456789abcdef")
	v := validator.New(validator.Config{Legacy: validator.LegacyConfig{Enabled: true, HMACSecret: secret}})
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{"default": {ID: "default", Enabled: true}}}

	tok := hmacLegacyToken(t, secret)

	run := func(allowed func(time.Time) bool) int {
		w := httptest.NewRecorder()
		_, r := gin.CreateTestContext(w)
		r.Use(TokenAuthMiddleware(v, tenants, nil, zap.NewNop(), WithLegacyAllowed(allowed)))
		r.GET("/t", func(c *gin.Context) { c.Status(200) })
		req := httptest.NewRequest("GET", "/t", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := run(func(time.Time) bool { return true }); code != 200 {
		t.Errorf("legacy allowed: got %d", code)
	}
	if code := run(func(time.Time) bool { return false }); code != 401 {
		t.Errorf("legacy refused after sunset: got %d", code)
	}
}

func TestLegacyIssuanceGate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(allowed func(time.Time) bool) int {
		w := httptest.NewRecorder()
		_, r := gin.CreateTestContext(w)
		r.POST("/login", LegacyIssuanceGate(allowed), func(c *gin.Context) { c.Status(200) })
		r.ServeHTTP(w, httptest.NewRequest("POST", "/login", nil))
		return w.Code
	}
	if run(nil) != 200 || run(func(time.Time) bool { return true }) != 200 {
		t.Error("gate must pass when legacy is allowed")
	}
	if run(func(time.Time) bool { return false }) != 410 {
		t.Error("gate must answer 410 once legacy is closed")
	}
}
