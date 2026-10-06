package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	gojose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const (
	regTestSecret = "0123456789abcdef0123456789abcdef"
	regTestRPID   = "wallet.example.org"
)

type regAS struct {
	key *ecdsa.PrivateKey
	srv *httptest.Server
}

// newRegAS serves a JWKS at /auth/.well-known/jwks.json, i.e. exactly where
// the registry derives the URL from as.external_url.
func newRegAS(t *testing.T) *regAS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := gojose.JSONWebKeySet{Keys: []gojose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &regAS{key: key, srv: srv}
}

func (a *regAS) token(t *testing.T, aud []string) string {
	t.Helper()
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: a.key},
		(&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	require.NoError(t, err)
	tok, err := josejwt.Signed(signer).Claims(struct {
		josejwt.Claims
		TenantID string `json:"tenant_id"`
		TAC      string `json:"tac"`
	}{
		Claims: josejwt.Claims{Issuer: "wallet-backend", Subject: "u", Audience: aud,
			Expiry: josejwt.NewNumericDate(time.Now().Add(time.Hour))},
		TenantID: "acme", TAC: "r",
	}).Serialize()
	require.NoError(t, err)
	return tok
}

func regHMAC(t *testing.T) string {
	t.Helper()
	s, err := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"iss": "wallet-backend", "aud": regTestRPID, "user_id": "u", "tenant_id": "acme",
		"exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(regTestSecret))
	require.NoError(t, err)
	return s
}

func baseRegistryConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.LoadRegistryOnly("")
	require.NoError(t, err)
	return cfg
}

func registryTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := baseRegistryConfig(t)
	cfg.Registry.Cache.Path = filepath.Join(t.TempDir(), "cache.json")
	cfg.Registry.Source.URL = "http://127.0.0.1:1/unreachable.json"
	cfg.Registry.DynamicCache.Enabled = false
	// The test AS listens on plain http; the guarded JWKS fetch needs both.
	cfg.HTTPClient.AllowHTTP, cfg.HTTPClient.AllowPrivateIPs = true, true
	return cfg
}

func doRegistryGet(t *testing.T, p *RegistryProvider, authz string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	p.RegisterRoutes(r)
	req := httptest.NewRequest(http.MethodGet, "/registry/status", nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}

func TestRegistryProvider_ProtectedRoutes(t *testing.T) {
	as := newRegAS(t)
	cfg := registryTestConfig(t)
	cfg.Registry.RequireAuth = true
	cfg.AS.Enabled = false // registry-only: validates, does not run the AS
	cfg.AS.ExternalURL = as.srv.URL
	cfg.AS.Legacy.Enabled = true
	cfg.Server.RPID = regTestRPID
	cfg.JWT.Secret = regTestSecret
	require.NoError(t, cfg.ValidateRegistry())

	p, err := NewRegistryProvider(cfg, zap.NewNop())
	require.NoError(t, err)
	require.NoError(t, p.Start(context.Background()))
	t.Cleanup(func() { _ = p.Close() })
	require.NotNil(t, p.validator)

	assert.Equal(t, http.StatusUnauthorized, doRegistryGet(t, p, ""))
	assert.Equal(t, http.StatusUnauthorized, doRegistryGet(t, p, "Bearer junk"))
	assert.Equal(t, http.StatusOK, doRegistryGet(t, p, "Bearer "+as.token(t, []string{"wallet-registry"})))
	// An AS token for another audience is refused by the validator (v0.5).
	assert.Equal(t, http.StatusUnauthorized, doRegistryGet(t, p, "Bearer "+as.token(t, []string{"wallet-backend"})))
	assert.Equal(t, http.StatusOK, doRegistryGet(t, p, "Bearer "+regHMAC(t)), "legacy HMAC accepted while enabled")

	// Legacy HMAC from a different issuer is rejected (jwt.issuer is enforced).
	badIss, err := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"iss": "someone-else", "aud": regTestRPID, "user_id": "u", "tenant_id": "acme",
		"exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(regTestSecret))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, doRegistryGet(t, p, "Bearer "+badIss))

	// Legacy off: HMAC no longer accepted.
	cfg.AS.Legacy.Enabled = false
	p2, err := NewRegistryProvider(cfg, zap.NewNop())
	require.NoError(t, err)
	require.NoError(t, p2.Start(context.Background()))
	t.Cleanup(func() { _ = p2.Close() })
	assert.Equal(t, http.StatusUnauthorized, doRegistryGet(t, p2, "Bearer "+regHMAC(t)))
	assert.Equal(t, http.StatusOK, doRegistryGet(t, p2, "Bearer "+as.token(t, []string{"wallet-registry"})))
}

func TestRegistryProvider_UnauthenticatedModeAndSetters(t *testing.T) {
	cfg := registryTestConfig(t) // require_auth=false, no AS configured
	cfg.JWT.Secret = ""
	p, err := NewRegistryProvider(cfg, zap.NewNop())
	require.NoError(t, err)
	assert.Nil(t, p.validator, "nothing to validate tokens with")
	require.NoError(t, p.Start(context.Background()))
	t.Cleanup(func() { _ = p.Close() })

	assert.Equal(t, http.StatusOK, doRegistryGet(t, p, ""))
	assert.Equal(t, http.StatusOK, doRegistryGet(t, p, "Bearer junk"))

	p.SetTenantLookup(nil)
	p.SetTokenBlacklist(nil)
	assert.NoError(t, p.CheckReady(context.Background()))
	assert.Equal(t, "registry", p.Name())
	assert.Equal(t, TransportHTTP, p.Transport())
}

func TestRegistryNeedsValidator(t *testing.T) {
	c := baseRegistryConfig(t)
	c.AS.Legacy.Enabled = true
	c.JWT.Secret = ""
	assert.False(t, registryNeedsValidator(c))
	c.JWT.Secret = regTestSecret
	assert.True(t, registryNeedsValidator(c))
	c.JWT.Secret = ""
	c.AS.ExternalURL = "https://as.example.org"
	assert.True(t, registryNeedsValidator(c))
	c.AS.ExternalURL = ""
	c.Registry.RequireAuth = true
	assert.True(t, registryNeedsValidator(c))
}

// The registry's validator is built through the same guarded path as the other
// roles; this pins the legacy HMAC settings it derives from the config.
func TestRegistryProvider_BuildValidatorLegacy(t *testing.T) {
	c := registryTestConfig(t)
	c.Registry.RequireAuth = true
	c.AS.Legacy.Enabled = true
	c.Server.RPID = regTestRPID

	// Legacy HMAC is never validated against an empty key.
	c.JWT.Secret = ""
	p, err := NewRegistryProvider(c, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	_, err = p.validator.Validate(context.Background(), regHMAC(t))
	assert.Error(t, err)

	// An empty jwt.issuer with a secret would accept any issuer: refused.
	c.JWT.Secret = regTestSecret
	c.JWT.Issuer = ""
	_, err = NewRegistryProvider(c, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwt.issuer")

	c.JWT.Issuer = "wallet-backend"
	p2, err := NewRegistryProvider(c, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p2.Close() })
	_, err = p2.validator.Validate(context.Background(), regHMAC(t))
	assert.NoError(t, err)

	// as.legacy.enabled=false (as #429 defines it) refuses HMAC even with a secret.
	c.AS.Legacy.Enabled = false
	c.AS.ExternalURL = "http://127.0.0.1:1"
	p3, err := NewRegistryProvider(c, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p3.Close() })
	_, err = p3.validator.Validate(context.Background(), regHMAC(t))
	assert.Error(t, err)
}

func TestRegistryProvider_RootAliases(t *testing.T) {
	get := func(p *RegistryProvider, path string) int {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		p.RegisterRoutes(r)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w.Code
	}
	cfg := registryTestConfig(t)
	cfg.Registry.RequireAuth = true
	cfg.AS.ExternalURL = "http://127.0.0.1:1"
	cfg.AS.Legacy.Enabled = false
	p, err := NewRegistryProvider(cfg, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })

	// without aliases only /registry/* exists
	assert.Equal(t, http.StatusNotFound, get(p, "/type-metadata?vct=x"))
	assert.Equal(t, http.StatusUnauthorized, get(p, "/registry/type-metadata?vct=x"))

	// with aliases the retired binary's root paths work, under the same auth
	p.SetRootAliases(true)
	assert.Equal(t, http.StatusUnauthorized, get(p, "/type-metadata?vct=x"))
	assert.Equal(t, http.StatusUnauthorized, get(p, "/credentials"))
	assert.Equal(t, http.StatusUnauthorized, get(p, "/registry/credentials"))

	// unauthenticated mode serves them
	cfg2 := registryTestConfig(t)
	p2, err := NewRegistryProvider(cfg2, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p2.Close() })
	p2.SetRootAliases(true)
	assert.Equal(t, http.StatusOK, get(p2, "/credentials"))
	assert.Equal(t, http.StatusBadRequest, get(p2, "/type-metadata"), "handler reached (vct required)")
}

func TestRegistryProvider_InProcessHandler(t *testing.T) {
	cfg := registryTestConfig(t)
	cfg.Registry.RequireAuth = true // in-process callers are trusted: no auth, no rate limit
	cfg.AS.ExternalURL = "http://127.0.0.1:1"
	cfg.AS.Legacy.Enabled = false
	p, err := NewRegistryProvider(cfg, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	h := p.InProcessHandler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/registry/type-metadata", nil))
	assert.Equal(t, http.StatusBadRequest, w.Code, "handler reached without a token")

	// EngineProvider wiring
	ep := &EngineProvider{manager: wsengine.NewManager(cfg, zap.NewNop())}
	ep.SetRegistryHandler(h)
}
