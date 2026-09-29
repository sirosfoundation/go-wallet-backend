package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const dualSecret = "0123456789abcdef0123456789abcdef"

type dualEnv struct {
	key     *ecdsa.PrivateKey
	jwksURL string
}

func newDualEnv(t *testing.T) *dualEnv {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	return &dualEnv{key: key, jwksURL: srv.URL}
}

func (e *dualEnv) es256(t *testing.T, key *ecdsa.PrivateKey, iss string, exp time.Duration, tenant string) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	require.NoError(t, err)
	raw, err := gojosejwt.Signed(sig).Claims(map[string]any{
		"iss": iss, "sub": "user-1", "aud": []string{"wallet-registry"}, "tenant_id": tenant, "tac": "r",
		"iat": time.Now().Unix(), "nbf": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(exp).Unix(),
	}).Serialize()
	require.NoError(t, err)
	return raw
}

func hmacTok(t *testing.T, secret, iss string, exp time.Duration) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": iss, "user_id": "u", "tenant_id": "acme", "exp": time.Now().Add(exp).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func doReq(t *testing.T, cfg JWTConfig, token string) (int, bool, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(JWTMiddleware(cfg, zap.NewNop()))
	var authed bool
	var tenant string
	r.GET("/x", func(c *gin.Context) {
		authed = c.GetBool(string(AuthenticatedKey))
		tenant = c.GetString(string(TenantIDKey))
		c.Status(200)
	})
	req := httptest.NewRequest("GET", "/x", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, authed, tenant
}

func TestJWTMiddleware_ES256ViaJWKS(t *testing.T) {
	e := newDualEnv(t)
	cfg := JWTConfig{Secret: dualSecret, Issuer: "legacy-iss", ASIssuer: "as-iss", JWKSURL: e.jwksURL, RequireAuth: true, Audiences: []string{"wallet-registry"}}

	code, authed, tenant := doReq(t, cfg, e.es256(t, e.key, "as-iss", time.Minute, "acme"))
	assert.Equal(t, 200, code)
	assert.True(t, authed)
	assert.Equal(t, "acme", tenant)

	// expired
	code, _, _ = doReq(t, cfg, e.es256(t, e.key, "as-iss", -time.Hour, "acme"))
	assert.Equal(t, 401, code)
	// wrong issuer
	code, _, _ = doReq(t, cfg, e.es256(t, e.key, "evil", time.Minute, "acme"))
	assert.Equal(t, 401, code)
	// forged: valid kid, signed by another key
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	code, _, _ = doReq(t, cfg, e.es256(t, other, "as-iss", time.Minute, "acme"))
	assert.Equal(t, 401, code)
}

func TestJWTMiddleware_ASIssuerDefaultsToIssuer(t *testing.T) {
	e := newDualEnv(t)
	cfg := JWTConfig{Issuer: "same", JWKSURL: e.jwksURL, RequireAuth: true}
	code, _, _ := doReq(t, cfg, e.es256(t, e.key, "same", time.Minute, ""))
	assert.Equal(t, 200, code)
}

func TestJWTMiddleware_HMACOnlyWhileLegacy(t *testing.T) {
	e := newDualEnv(t)
	base := JWTConfig{Secret: dualSecret, Issuer: "iss", JWKSURL: e.jwksURL, RequireAuth: true}
	tok := hmacTok(t, dualSecret, "iss", time.Minute)

	code, authed, tenant := doReq(t, base, tok)
	assert.Equal(t, 200, code)
	assert.True(t, authed)
	assert.Equal(t, "acme", tenant)

	off := false
	disabled := base
	disabled.LegacyEnabled = &off
	code, _, _ = doReq(t, disabled, tok)
	assert.Equal(t, 401, code)

	past := base
	past.LegacySunsetDate = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	code, _, _ = doReq(t, past, tok)
	assert.Equal(t, 401, code)

	future := base
	future.LegacySunsetDate = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	code, _, _ = doReq(t, future, tok)
	assert.Equal(t, 200, code)

	bad := base
	bad.LegacySunsetDate = "not-a-date"
	code, _, _ = doReq(t, bad, tok)
	assert.Equal(t, 401, code, "malformed sunset must fail closed")

	// forged / expired / wrong issuer HMAC
	code, _, _ = doReq(t, base, hmacTok(t, "another-secret-another-secret-xxxx", "iss", time.Minute))
	assert.Equal(t, 401, code)
	code, _, _ = doReq(t, base, hmacTok(t, dualSecret, "iss", -time.Hour))
	assert.Equal(t, 401, code)
	code, _, _ = doReq(t, base, hmacTok(t, dualSecret, "other", time.Minute))
	assert.Equal(t, 401, code)
}

func TestJWTMiddleware_RejectsNoneAndUnsupportedAlg(t *testing.T) {
	e := newDualEnv(t)
	cfg := JWTConfig{Secret: dualSecret, Issuer: "iss", JWKSURL: e.jwksURL, RequireAuth: true}
	enc := base64.RawURLEncoding
	none := enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		enc.EncodeToString([]byte(`{"iss":"iss","user_id":"u","exp":`+jsonInt(time.Now().Add(time.Hour).Unix())+`}`)) + "."
	code, _, _ := doReq(t, cfg, none)
	assert.Equal(t, 401, code)

	rs := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString([]byte(`{"iss":"iss"}`)) + ".c2ln"
	code, _, _ = doReq(t, cfg, rs)
	assert.Equal(t, 401, code)
}

func jsonInt(i int64) string { b, _ := json.Marshal(i); return string(b) }

func TestJWTMiddleware_HMACWithoutSecretNeverAccepted(t *testing.T) {
	e := newDualEnv(t)
	// JWKS only, no secret: an HMAC token signed with the empty key must fail.
	cfg := JWTConfig{Issuer: "iss", JWKSURL: e.jwksURL, RequireAuth: true}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": "iss", "user_id": "u", "exp": time.Now().Add(time.Hour).Unix()})
	s, err := tok.SignedString([]byte(""))
	require.NoError(t, err)
	code, _, _ := doReq(t, cfg, s)
	assert.Equal(t, 401, code)
}

func TestJWTMiddleware_ES256WithoutJWKSRejected(t *testing.T) {
	e := newDualEnv(t)
	cfg := JWTConfig{Secret: dualSecret, Issuer: "iss", RequireAuth: true}
	code, _, _ := doReq(t, cfg, e.es256(t, e.key, "iss", time.Minute, ""))
	assert.Equal(t, 401, code)
}

func TestJWTMiddleware_OptionalMode(t *testing.T) {
	e := newDualEnv(t)
	cfg := JWTConfig{Secret: dualSecret, Issuer: "iss", JWKSURL: e.jwksURL}
	code, authed, _ := doReq(t, cfg, "garbage")
	assert.Equal(t, 200, code)
	assert.False(t, authed)
	off := false
	cfg.LegacyEnabled = &off
	code, authed, _ = doReq(t, cfg, hmacTok(t, dualSecret, "iss", time.Minute))
	assert.Equal(t, 200, code)
	assert.False(t, authed)
}

func TestJWTConfig_LegacyActive(t *testing.T) {
	sunset := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	j := JWTConfig{Secret: "s", LegacySunsetDate: sunset.Format(time.RFC3339)}
	assert.True(t, j.legacyActive(sunset.Add(-time.Nanosecond)))
	assert.False(t, j.legacyActive(sunset), "the sunset instant itself is already past")
	assert.False(t, JWTConfig{}.legacyActive(sunset))
	assert.True(t, JWTConfig{Secret: "s"}.legacyActive(sunset))
}

func TestJWTConfig_LogLegacyStatus(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	off := false
	cases := []struct {
		name string
		j    JWTConfig
		msg  string
		lvl  string
	}{
		{"disabled", JWTConfig{Secret: "s", LegacyEnabled: &off}, "disabled", "info"},
		{"passed", JWTConfig{Secret: "s", LegacySunsetDate: now.Add(-time.Hour).Format(time.RFC3339)}, "DISABLED", "warn"},
		{"soon", JWTConfig{Secret: "s", LegacySunsetDate: now.Add(29 * 24 * time.Hour).Format(time.RFC3339)}, "DEPRECATION", "warn"},
		{"far", JWTConfig{Secret: "s", LegacySunsetDate: now.Add(90 * 24 * time.Hour).Format(time.RFC3339)}, "enabled", "info"},
		{"nosunset", JWTConfig{Secret: "s"}, "enabled", "info"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)
			tc.j.LogLegacyStatus(zap.New(core), now)
			require.Equal(t, 1, logs.Len())
			e := logs.All()[0]
			assert.Contains(t, e.Message, tc.msg)
			assert.Equal(t, tc.lvl, e.Level.String())
		})
	}
}

func TestConfig_Validate_JWTDual(t *testing.T) {
	newCfg := func() *Config {
		c := DefaultConfig()
		c.Cache.Path = t.TempDir() + "/c.json"
		return c
	}
	c := newCfg()
	c.JWT.LegacySunsetDate = "tomorrow"
	assert.ErrorContains(t, c.Validate(), "legacy_sunset_date")

	c = newCfg()
	c.JWT.JWKSURL = "ftp://x/y"
	assert.ErrorContains(t, c.Validate(), "jwks_url")

	c = newCfg()
	c.JWT.JWKSURL = "https://wallet.example.com/auth/.well-known/jwks.json"
	c.JWT.RequireAuth = true // JWKS alone satisfies RequireAuth (no shared secret needed)
	assert.NoError(t, c.Validate())

	off := false
	c = newCfg()
	c.JWT.RequireAuth = true
	c.JWT.Secret = "s"
	c.JWT.LegacyEnabled = &off
	assert.ErrorContains(t, c.Validate(), "no token could ever validate")

	c = newCfg()
	c.JWT.LegacySunsetDate = "2027-10-01T00:00:00Z"
	assert.NoError(t, c.Validate())
}
