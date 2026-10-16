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
	legacyjwt "github.com/golang-jwt/jwt/v5"
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

// testTokenAudience is the audience every test in this file configures its
// validator with and signs its tokens for. go-tokenauth v0.5.0 made
// Config.Audiences mandatory (both validation paths now refuse to validate
// at all when it's empty, closing a fail-open audience-confusion gap) -
// see signToken/setupTokenAuthTest.
const testTokenAudience = "test-audience"

// testTokenAuthConfig returns a minimal config for TokenAuthMiddleware in
// tests. Only JWT.Secret matters - it's used solely to re-parse a
// legacy-mode token for its "sid" claim (see legacytoken.SID) - and none of
// the ES256/EdDSA-signed tokens these tests present are legacy-mode, so
// its exact value is otherwise irrelevant here.
func testTokenAuthConfig() *config.Config {
	return &config.Config{JWT: config.JWTConfig{Secret: "test-tokenauth-secret"}}
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
		JWKSURL:   srv.URL,
		Issuer:    "test-issuer",
		Audiences: []string{testTokenAudience},
	})
	v.Start(context.Background())
	t.Cleanup(v.Stop)

	// Poll until the validator has actually fetched the JWKS, rather than
	// sleeping a fixed duration (flaky under slow/contended CI runners).
	probe := signToken(t, key, "test-issuer", claims.AccessTokenClaims{
		Claims: jwt.Claims{Audience: jwt.Audience{testTokenAudience}},
	})
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
		Audience:  cl.Claims.Audience,
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
		Claims:   jwt.Claims{Subject: "user-123", Audience: jwt.Audience{testTokenAudience}},
		TenantID: "test-tenant",
		TAC:      "rwl",
	})

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(testTokenAuthConfig(), v, tenants, nil, logger))
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
	r.Use(TokenAuthMiddleware(testTokenAuthConfig(), v, tenants, nil, logger))
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
	r.Use(TokenAuthMiddleware(testTokenAuthConfig(), v, tenants, nil, logger))
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
		Claims:   jwt.Claims{Subject: "user-123", Audience: jwt.Audience{testTokenAudience}},
		TenantID: "disabled",
		TAC:      "r",
	})

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(testTokenAuthConfig(), v, tenants, nil, logger))
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
		Claims:   jwt.Claims{Subject: "user-123", Audience: jwt.Audience{testTokenAudience}},
		TenantID: "nonexistent",
		TAC:      "r",
	})

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(testTokenAuthConfig(), v, tenants, nil, logger))
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
		Claims:   jwt.Claims{Subject: "revoked-user", Audience: jwt.Audience{testTokenAudience}},
		TenantID: "test-tenant",
		TAC:      "rwl",
	})

	blacklist := service.NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, logger)
	if err := blacklist.RevokeUser(context.Background(), "revoked-user"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(testTokenAuthConfig(), v, tenants, blacklist, logger))
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
		Claims:   jwt.Claims{Subject: "user-123", Audience: jwt.Audience{testTokenAudience}},
		TenantID: "test-tenant",
		TAC:      "rwl",
	})

	blacklist := service.NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, logger)
	if err := blacklist.RevokeUser(context.Background(), "some-other-user"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	r.Use(TokenAuthMiddleware(testTokenAuthConfig(), v, tenants, blacklist, logger))
	r.GET("/test", func(c *gin.Context) { c.Status(200) })

	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.Header.Set("Authorization", "Bearer "+token)
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-revoked user, got %d: %s", w.Code, w.Body.String())
	}
}

// createLegacyModeTokenWithSID signs a legacy HMAC token shaped exactly
// like WebAuthnService.generateToken (see internal/service/webauthn.go),
// carrying a "sid" claim - go-tokenauth's Validator "auto-detects" this as
// ModeLegacy purely from its HS256 header alg (see validator.Validate's own
// doc comment), independent of go-tokenauth's own LegacyTokenClaims shape,
// which has no "sid" field at all and simply ignores it on unmarshal.
func createLegacyModeTokenWithSID(secret, userID, jti, sid string) string {
	token := legacyjwt.NewWithClaims(legacyjwt.SigningMethodHS256, legacyjwt.MapClaims{
		"user_id":   userID,
		"tenant_id": "test-tenant",
		"jti":       jti,
		"sid":       sid,
		"iss":       "legacy-mode-test-issuer",
		"aud":       testTokenAudience,
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := token.SignedString([]byte(secret))
	return signed
}

// TestTokenAuthMiddleware_ModeLegacy_RevokedFamilyTokenRejected is a
// regression test for #402: go-tokenauth's Validator "auto-detects
// new-style vs legacy" tokens (TokenAuthMiddleware's own doc comment), so a
// WebAuthnService-issued legacy HMAC token reaches THIS middleware instead
// of the legacy AuthMiddlewareWithBlacklist whenever the AS is enabled.
// Without checking family revocation here too (via legacytoken.SID's
// re-parse - go-tokenauth's shared *claims.Result has no "sid" field),
// revoking a session's refresh-token family on logout would be silently
// ineffective for exactly this deployment mode.
func TestTokenAuthMiddleware_ModeLegacy_RevokedFamilyTokenRejected(t *testing.T) {
	secret := "legacy-mode-test-secret"
	v := validator.New(validator.Config{
		Audiences: []string{testTokenAudience},
		Legacy: validator.LegacyConfig{
			Enabled:    true,
			HMACSecret: []byte(secret),
			Issuers:    []string{"legacy-mode-test-issuer"},
		},
	})
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{
		"test-tenant": {ID: "test-tenant", Enabled: true},
	}}
	logger := zap.NewNop()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}

	blacklist := service.NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, logger)

	tokenStr := createLegacyModeTokenWithSID(secret, "user-123", "jti-legacy-mode-family-1", "sid-legacy-mode-family-1")

	router := gin.New()
	router.Use(TokenAuthMiddleware(cfg, v, tenants, blacklist, logger))
	router.GET("/test", func(c *gin.Context) { c.Status(200) })

	// Works before the family is revoked.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 before family revocation, got %d: %s", w.Code, w.Body.String())
	}

	if err := blacklist.RevokeFamily(context.Background(), "sid-legacy-mode-family-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	// The same token - its own jti never individually blacklisted - must
	// now be rejected.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a ModeLegacy token whose refresh-token family was revoked, got %d: %s", w.Code, w.Body.String())
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

func TestExtractBearerToken_Request(t *testing.T) {
	tests := []struct {
		name, header, want string
	}{
		{"valid", "Bearer abc", "abc"},
		{"mixed case scheme", "bEaReR abc", "abc"},
		{"whitespace trimmed", "Bearer  abc ", "abc"},
		{"absent", "", ""},
		{"other scheme", "Basic abc", ""},
		{"scheme only", "Bearer", ""},
		{"no separator", "Bearerabc", ""},
		{"longer scheme", "Bearers abc", ""},
		{"leading space", " Bearer abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			if got := ExtractBearerToken(req); got != tt.want {
				t.Errorf("ExtractBearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestTokenAuthMiddleware_ModeLegacy_FamilyCheckAppliesInsideClockSkewWindow
// proves a token go-tokenauth accepted via its leeway (expired 2s ago, 5s
// default leeway) still gets its revoked-family check: the SID re-parse must
// not fail open inside that window.
func TestTokenAuthMiddleware_ModeLegacy_FamilyCheckAppliesInsideClockSkewWindow(t *testing.T) {
	secret := "legacy-mode-test-secret"
	v := validator.New(validator.Config{
		Audiences: []string{testTokenAudience},
		Legacy:    validator.LegacyConfig{Enabled: true, HMACSecret: []byte(secret), Issuers: []string{"legacy-mode-test-issuer"}},
	})
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{"test-tenant": {ID: "test-tenant", Enabled: true}}}
	logger := zap.NewNop()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}
	blacklist := service.NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, logger)

	tok := legacyjwt.NewWithClaims(legacyjwt.SigningMethodHS256, legacyjwt.MapClaims{
		"user_id": "user-123", "tenant_id": "test-tenant", "jti": "jti-skew", "sid": "sid-skew",
		"iss": "legacy-mode-test-issuer", "aud": testTokenAudience,
		"exp": time.Now().Add(-2 * time.Second).Unix(),
	})
	tokenStr, _ := tok.SignedString([]byte(secret))

	router := gin.New()
	router.Use(TokenAuthMiddleware(cfg, v, tenants, blacklist, logger))
	router.GET("/test", func(c *gin.Context) { c.Status(200) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("precondition: skew-window token should be accepted before revocation, got %d", w.Code)
	}
	_ = blacklist.RevokeFamily(context.Background(), "sid-skew", time.Now().Add(time.Hour))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (revoked family) for a token inside the skew window, got %d: %s", w.Code, w.Body.String())
	}
}

// TestTokenAuthMiddleware_ModeLegacy_UndeterminableSIDFailsClosed proves that
// when the validator accepted a legacy token but the family id cannot be
// re-derived (here: cfg.JWT.Secret differs from the validator's secret), the
// request is rejected rather than skipping the family check.
func TestTokenAuthMiddleware_ModeLegacy_UndeterminableSIDFailsClosed(t *testing.T) {
	validatorSecret := "legacy-mode-test-secret"
	v := validator.New(validator.Config{
		Audiences: []string{testTokenAudience},
		Legacy:    validator.LegacyConfig{Enabled: true, HMACSecret: []byte(validatorSecret), Issuers: []string{"legacy-mode-test-issuer"}},
	})
	tenants := &stubTenantStore{tenants: map[domain.TenantID]*domain.Tenant{"test-tenant": {ID: "test-tenant", Enabled: true}}}
	logger := zap.NewNop()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "a-different-secret"}}
	blacklist := service.NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, logger)

	tokenStr := createLegacyModeTokenWithSID(validatorSecret, "user-123", "jti-x", "sid-x")
	router := gin.New()
	router.Use(TokenAuthMiddleware(cfg, v, tenants, blacklist, logger))
	router.GET("/test", func(c *gin.Context) { c.Status(200) })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 (fail closed), got %d: %s", w.Code, w.Body.String())
	}
}

// Legacy-mode results are exempt from RequireAudience (their aud is the RP
// ID, already validated by go-tokenauth); new-style tokens are not.
func TestRequireAudience_LegacyModeExempt_SessionModeStillEnforced(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(res *claims.Result) int {
		w := httptest.NewRecorder()
		_, r := gin.CreateTestContext(w)
		r.Use(func(c *gin.Context) { c.Set("tokenauth_result", res); c.Next() })
		r.Use(RequireAudience("wallet-backend"))
		r.GET("/t", func(c *gin.Context) { c.Status(200) })
		r.ServeHTTP(w, httptest.NewRequest("GET", "/t", nil))
		return w.Code
	}
	if code := run(&claims.Result{Mode: claims.ModeLegacy, Audience: []string{"wallet.example.com"}}); code != 200 {
		t.Errorf("legacy RP-ID audience: expected 200, got %d", code)
	}
	if code := run(&claims.Result{Mode: claims.ModeSession, Audience: []string{"wallet.example.com"}}); code != 403 {
		t.Errorf("session-mode wrong audience: expected 403, got %d", code)
	}
}

// ModeLegacy login tokens (aud=RP ID) pass RequireAudience but must be
// refused by RequireAudienceStrict, which a narrower future group opts in to.
func TestRequireAudience_LegacyExemptionIsExplicit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name string
		mw   gin.HandlerFunc
		want int
	}{
		{"RequireAudience admits legacy", RequireAudience("wallet-registry"), 200},
		{"RequireAudienceStrict refuses legacy", RequireAudienceStrict("wallet-registry"), 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)
			r.Use(func(c *gin.Context) {
				c.Set("tokenauth_result", &claims.Result{Mode: claims.ModeLegacy, Audience: []string{"wallet.example.com"}})
				c.Next()
			})
			r.Use(tc.mw)
			r.GET("/test", func(c *gin.Context) { c.Status(200) })
			r.ServeHTTP(w, httptest.NewRequest("GET", "/test", nil))
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}
