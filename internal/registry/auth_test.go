package registry

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
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

const (
	testIssuer = "https://as.example.org"
	testSecret = "0123456789abcdef0123456789abcdef"
	testRPID   = "wallet.example.org"
)

type authEnv struct {
	key  *ecdsa.PrivateKey
	jwks *httptest.Server
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return &authEnv{key: key, jwks: srv}
}

// validator builds a go-tokenauth validator WITHOUT legacy support, as the
// registry does: the legacy HMAC authorization server no longer exists. Its
// audience list is deliberately wider than the registry's ("wallet-backend"
// too) so the registry's own audience rule is exercised on top of it.
func (e *authEnv) validator(t *testing.T) *validator.Validator {
	t.Helper()
	v := validator.New(validator.Config{
		JWKSURL:   e.jwks.URL,
		Issuer:    testIssuer,
		Audiences: []string{"wallet-registry", "wallet-backend"},
	})
	v.Start(context.Background())
	t.Cleanup(v.Stop)
	return v
}

func (e *authEnv) es256(t *testing.T, aud []string, tenant string, exp time.Time) string {
	t.Helper()
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: e.key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	require.NoError(t, err)
	claims := struct {
		josejwt.Claims
		TenantID string `json:"tenant_id"`
		TAC      string `json:"tac"`
	}{
		Claims: josejwt.Claims{
			Issuer: testIssuer, Subject: "user-1", Audience: aud, ID: "jti-1",
			IssuedAt: josejwt.NewNumericDate(time.Now().Add(-time.Minute)),
			Expiry:   josejwt.NewNumericDate(exp),
		},
		TenantID: tenant, TAC: "r",
	}
	tok, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return tok
}

func hmacToken(t *testing.T, secret string, aud []string, tenant string) string {
	t.Helper()
	c := gojwt.MapClaims{"iss": "wallet-backend", "user_id": "u1", "tenant_id": tenant,
		"exp": time.Now().Add(time.Hour).Unix()}
	c["aud"] = testRPID
	if aud != nil {
		c["aud"] = aud
	}
	s, err := gojwt.NewWithClaims(gojwt.SigningMethodHS256, c).SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

// probe runs a request through the auth chain and reports what a downstream
// handler (the rate limiter) would see.
type probeResult struct {
	status int
	body   string
	auth   bool
	tenant string
	hasTen bool
}

func probe(t *testing.T, cfg AuthConfig, authz string) probeResult {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	var res probeResult
	g := r.Group("/registry")
	g.Use(AuthMiddlewares(cfg)...)
	g.GET("/status", func(c *gin.Context) {
		res.auth = isAuthenticated(c)
		_, res.hasTen = c.Get(string(TenantIDKey))
		res.tenant = getTenantID(c)
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/registry/status", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	res.status = w.Code
	res.body = w.Body.String()
	return res
}

func TestAuthMiddlewares_Strict(t *testing.T) {
	env := newAuthEnv(t)
	v := env.validator(t)
	cfg := AuthConfig{Validator: v, RequireAuth: true, Logger: zap.NewNop()}
	future := time.Now().Add(time.Hour)

	t.Run("no token is 401", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, probe(t, cfg, "").status)
	})
	t.Run("garbage token is 401", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, probe(t, cfg, "Bearer not-a-jwt").status)
	})
	t.Run("valid ES256 with wallet-registry", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+env.es256(t, []string{"wallet-registry"}, "acme", future))
		assert.Equal(t, http.StatusOK, r.status)
		assert.True(t, r.auth)
		assert.Equal(t, "acme", r.tenant)
	})
	t.Run("ES256 without tenant leaves tenant key unset", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+env.es256(t, []string{"wallet-registry"}, "", future))
		assert.Equal(t, http.StatusOK, r.status)
		assert.True(t, r.auth)
		assert.False(t, r.hasTen)
	})
	t.Run("ES256 with additional audiences still accepted", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+env.es256(t, []string{"wallet-backend", "wallet-registry"}, "acme", future))
		assert.Equal(t, http.StatusOK, r.status)
	})
	t.Run("ES256 wrong audience is 403", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+env.es256(t, []string{"wallet-backend"}, "acme", future))
		assert.Equal(t, http.StatusForbidden, r.status)
		assert.Contains(t, r.body, "audience not permitted", "rejected by the registry audience rule")
	})
	t.Run("ES256 no audience is 401 (rejected by go-tokenauth v0.5)", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+env.es256(t, nil, "acme", future))
		assert.Equal(t, http.StatusUnauthorized, r.status)
	})
	t.Run("expired ES256 is 401", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+env.es256(t, []string{"wallet-registry"}, "acme", time.Now().Add(-time.Hour)))
		assert.Equal(t, http.StatusUnauthorized, r.status)
	})
	t.Run("HMAC tokens are never accepted (legacy AS removed)", func(t *testing.T) {
		for name, tok := range map[string]string{
			"rp id audience": hmacToken(t, testSecret, nil, "acme"),
			"registry aud":   hmacToken(t, testSecret, []string{"wallet-registry"}, "acme"),
			"wrong secret":   hmacToken(t, "ffffffffffffffffffffffffffffffff", nil, "acme"),
		} {
			r := probe(t, cfg, "Bearer "+tok)
			assert.Equal(t, http.StatusUnauthorized, r.status, name)
			assert.False(t, r.auth, name)
		}
	})
}

type fakeTenants struct{ enabled map[string]bool }

func (f fakeTenants) GetByID(_ context.Context, id domain.TenantID) (*domain.Tenant, error) {
	en, ok := f.enabled[string(id)]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return &domain.Tenant{ID: id, Enabled: en}, nil
}

type fakeBlacklist struct{ revokedUser, revokedJTI string }

func (fakeBlacklist) IsFamilyRevoked(context.Context, string) bool { return false }

func (f fakeBlacklist) IsBlacklisted(_ context.Context, j string) bool {
	return f.revokedJTI != "" && j == f.revokedJTI
}
func (f fakeBlacklist) IsUserRevoked(_ context.Context, u string) bool {
	return f.revokedUser != "" && u == f.revokedUser
}

func TestAuthMiddlewares_StrictWithTenantStoreAndBlacklist(t *testing.T) {
	env := newAuthEnv(t)
	v := env.validator(t)
	future := time.Now().Add(time.Hour)
	tok := "Bearer " + env.es256(t, []string{"wallet-registry"}, "acme", future)

	cfg := AuthConfig{Validator: v, RequireAuth: true, Logger: zap.NewNop(),
		Tenants: fakeTenants{enabled: map[string]bool{"acme": true}}}
	assert.Equal(t, http.StatusOK, probe(t, cfg, tok).status)

	cfg.Tenants = fakeTenants{enabled: map[string]bool{"acme": false}}
	assert.Equal(t, http.StatusForbidden, probe(t, cfg, tok).status, "disabled tenant")

	cfg.Tenants = fakeTenants{enabled: map[string]bool{}}
	assert.Equal(t, http.StatusUnauthorized, probe(t, cfg, tok).status)

	cfg.Tenants = fakeTenants{enabled: map[string]bool{"acme": true}}
	cfg.Blacklist = fakeBlacklist{revokedUser: "user-1"}
	r := probe(t, cfg, tok)
	assert.Equal(t, http.StatusUnauthorized, r.status)
	assert.Contains(t, r.body, "Token has been revoked")
	// Positive control: a blacklist that does not name the user lets it through.
	cfg.Blacklist = fakeBlacklist{revokedUser: "someone-else"}
	assert.Equal(t, http.StatusOK, probe(t, cfg, tok).status)
}

func TestAuthMiddlewares_JTIRevocation(t *testing.T) {
	env := newAuthEnv(t)
	future := time.Now().Add(time.Hour)
	es := "Bearer " + env.es256(t, []string{"wallet-registry"}, "acme", future) // jti-1

	for _, strict := range []bool{true, false} {
		cfg := AuthConfig{
			Validator: env.validator(t), RequireAuth: strict, Logger: zap.NewNop(),
			Blacklist: fakeBlacklist{revokedJTI: "unrelated-jti"},
		}

		// Positive control: with no matching jti revoked the token passes the
		// whole chain.
		r := probe(t, cfg, es)
		assert.Equal(t, http.StatusOK, r.status, "control, strict=%v", strict)
		assert.True(t, r.auth, "control, strict=%v", strict)

		cfg.Blacklist = fakeBlacklist{revokedJTI: "jti-1"}
		r = probe(t, cfg, es)
		assert.False(t, r.auth, "jti revoked, strict=%v", strict)
		if strict {
			assert.Equal(t, http.StatusUnauthorized, r.status)
			assert.Contains(t, r.body, "Token has been revoked")
		}
	}
}

func TestAuthMiddlewares_OptionalTenantAndUserChecks(t *testing.T) {
	env := newAuthEnv(t)
	tok := "Bearer " + env.es256(t, []string{"wallet-registry"}, "acme", time.Now().Add(time.Hour))
	cfg := AuthConfig{Validator: env.validator(t), Logger: zap.NewNop(),
		Tenants: fakeTenants{enabled: map[string]bool{"acme": true}}}

	r := probe(t, cfg, tok)
	assert.Equal(t, http.StatusOK, r.status)
	assert.True(t, r.auth)

	cfg.Tenants = fakeTenants{enabled: map[string]bool{"acme": false}}
	r = probe(t, cfg, tok)
	assert.Equal(t, http.StatusOK, r.status, "public request is never rejected")
	assert.False(t, r.auth, "disabled tenant")

	cfg.Tenants = fakeTenants{enabled: map[string]bool{}}
	assert.False(t, probe(t, cfg, tok).auth, "unknown tenant")

	// token without tenant_id is checked against the default tenant
	noTen := "Bearer " + env.es256(t, []string{"wallet-registry"}, "", time.Now().Add(time.Hour))
	cfg.Tenants = fakeTenants{enabled: map[string]bool{"default": true}}
	assert.True(t, probe(t, cfg, noTen).auth)
	cfg.Tenants = fakeTenants{enabled: map[string]bool{"acme": true}}
	assert.False(t, probe(t, cfg, noTen).auth)

	cfg.Tenants = fakeTenants{enabled: map[string]bool{"acme": true}}
	cfg.Blacklist = fakeBlacklist{revokedUser: "user-1"}
	assert.False(t, probe(t, cfg, tok).auth, "deleted user")
}

func TestAuthMiddlewares_Optional(t *testing.T) {
	env := newAuthEnv(t)
	v := env.validator(t)
	cfg := AuthConfig{Validator: v, RequireAuth: false, Logger: zap.NewNop()}
	future := time.Now().Add(time.Hour)

	t.Run("no token allowed and unauthenticated", func(t *testing.T) {
		r := probe(t, cfg, "")
		assert.Equal(t, http.StatusOK, r.status)
		assert.False(t, r.auth)
	})
	t.Run("non-bearer header ignored", func(t *testing.T) {
		r := probe(t, cfg, "Basic abc")
		assert.Equal(t, http.StatusOK, r.status)
		assert.False(t, r.auth)
	})
	t.Run("valid token authenticates and sets tenant", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+env.es256(t, []string{"wallet-registry"}, "acme", future))
		assert.Equal(t, http.StatusOK, r.status)
		assert.True(t, r.auth)
		assert.Equal(t, "acme", r.tenant)
	})
	t.Run("token without tenant leaves key unset", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+env.es256(t, []string{"wallet-registry"}, "", future))
		assert.True(t, r.auth)
		assert.False(t, r.hasTen)
	})
	t.Run("invalid, expired and wrong-audience tokens continue unauthenticated", func(t *testing.T) {
		for name, tok := range map[string]string{
			"garbage":  "not-a-jwt",
			"expired":  env.es256(t, []string{"wallet-registry"}, "acme", time.Now().Add(-time.Hour)),
			"audience": env.es256(t, []string{"wallet-backend"}, "acme", future),
			"badhmac":  hmacToken(t, "ffffffffffffffffffffffffffffffff", nil, "acme"),
		} {
			r := probe(t, cfg, "Bearer "+tok)
			assert.Equal(t, http.StatusOK, r.status, name)
			assert.False(t, r.auth, name)
		}
	})
	t.Run("HMAC tokens are ignored (legacy AS removed)", func(t *testing.T) {
		r := probe(t, cfg, "Bearer "+hmacToken(t, testSecret, []string{testRPID}, "acme"))
		assert.Equal(t, http.StatusOK, r.status)
		assert.False(t, r.auth)
	})
	t.Run("nil validator treats everything as unauthenticated", func(t *testing.T) {
		r := probe(t, AuthConfig{}, "Bearer "+hmacToken(t, testSecret, nil, "acme"))
		assert.Equal(t, http.StatusOK, r.status)
		assert.False(t, r.auth)
	})
}
