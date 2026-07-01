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
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
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

func (s *stubTenantStore) Create(context.Context, *domain.Tenant) error   { return nil }
func (s *stubTenantStore) Update(context.Context, *domain.Tenant) error   { return nil }
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

	// Wait for JWKS to be fetched
	time.Sleep(100 * time.Millisecond)

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
	r.Use(TokenAuthMiddleware(v, tenants, logger))
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
	r.Use(TokenAuthMiddleware(v, tenants, logger))
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
	r.Use(TokenAuthMiddleware(v, tenants, logger))
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
	r.Use(TokenAuthMiddleware(v, tenants, logger))
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
	r.Use(TokenAuthMiddleware(v, tenants, logger))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, c.Request)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
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
