package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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
	return e.es256aud(t, key, iss, exp, tenant, "wallet-registry")
}

func (e *dualEnv) es256aud(t *testing.T, key *ecdsa.PrivateKey, iss string, exp time.Duration, tenant, aud string) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	require.NoError(t, err)
	raw, err := gojosejwt.Signed(sig).Claims(map[string]any{
		"iss": iss, "sub": "user-1", "aud": []string{aud}, "tenant_id": tenant, "tac": "r",
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
	r.Use(JWTMiddleware(cfg, zap.NewNop(), WithJWTAllowPlaintext(true)))
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
	cfg := JWTConfig{Secret: dualSecret, Issuer: "legacy-iss", ASIssuer: "as-iss", JWKSURL: e.jwksURL, RequireAuth: true}

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

func TestJWTMiddleware_HMACOnlyWhileLegacyEnabled(t *testing.T) {
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

func TestJWTConfig_LogLegacyStatus(t *testing.T) {
	off := false
	for name, tc := range map[string]struct {
		j   JWTConfig
		msg string
	}{
		"enabled":  {JWTConfig{Secret: "s"}, "is enabled"},
		"disabled": {JWTConfig{Secret: "s", LegacyEnabled: &off}, "is disabled"},
		"nosecret": {JWTConfig{}, "is disabled"},
	} {
		t.Run(name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)
			tc.j.LogLegacyStatus(zap.New(core))
			require.Equal(t, 1, logs.Len())
			assert.Contains(t, logs.All()[0].Message, tc.msg)
		})
	}
}

// Audience: legacy HMAC tokens (aud = RP ID) are never filtered; ES256 tokens
// must carry the registry audience (default wallet-registry) in both modes.
func TestJWTMiddleware_AudienceSemantics(t *testing.T) {
	e := newDualEnv(t)
	rpTok := func() string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "iss", "user_id": "u", "aud": "rp.example.com", "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString([]byte(dualSecret))
		require.NoError(t, err)
		return s
	}()
	off := false
	for _, legacyOff := range []bool{false, true} {
		cfg := JWTConfig{Secret: dualSecret, Issuer: "iss", JWKSURL: e.jwksURL, RequireAuth: true, Audiences: []string{"wallet-registry", "extra"}}
		if legacyOff {
			cfg.LegacyEnabled = &off
		}
		code, _, _ := doReq(t, cfg, e.es256aud(t, e.key, "iss", time.Minute, "", "wallet-backend"))
		assert.Equal(t, 401, code, "ES256 token for another audience must be rejected (legacyOff=%v)", legacyOff)
		code, _, _ = doReq(t, cfg, e.es256aud(t, e.key, "iss", time.Minute, "", "extra"))
		assert.Equal(t, 200, code)
		code, _, _ = doReq(t, cfg, rpTok)
		if legacyOff {
			assert.Equal(t, 401, code)
		} else {
			assert.Equal(t, 200, code, "HMAC token with RP-ID aud must be accepted while legacy is enabled")
		}
	}

	// No list configured: default wallet-registry.
	cfg := JWTConfig{Secret: dualSecret, Issuer: "iss", JWKSURL: e.jwksURL, RequireAuth: true}
	code, _, _ := doReq(t, cfg, e.es256aud(t, e.key, "iss", time.Minute, "", "wallet-backend"))
	assert.Equal(t, 401, code, "default audience must exclude other services")
	code, _, _ = doReq(t, cfg, e.es256aud(t, e.key, "iss", time.Minute, "", "wallet-registry"))
	assert.Equal(t, 200, code)
	code, _, _ = doReq(t, cfg, rpTok)
	assert.Equal(t, 200, code)
}

func TestJWTMiddleware_PlaintextJWKSRefusedByDefault(t *testing.T) {
	e := newDualEnv(t) // http:// test server
	cfg := JWTConfig{Issuer: "iss", JWKSURL: e.jwksURL, RequireAuth: true}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(JWTMiddleware(cfg, zap.NewNop())) // no plaintext opt-in
	r.GET("/x", func(c *gin.Context) { c.Status(200) })
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+e.es256(t, e.key, "iss", time.Minute, ""))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, 401, w.Code, "http JWKS URL must fail closed without opt-in")
}

// asServer serves AS metadata; hits/mode control failure behaviour.
type asServer struct {
	srv    *httptest.Server
	fail   atomic.Bool
	issuer func(base string) string
	jwks   func(base string) string
}

func newASServer(t *testing.T, e *dualEnv) *asServer {
	t.Helper()
	a := &asServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		if a.fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		base := a.srv.URL + "/auth"
		iss, jwks := base, base+"/.well-known/jwks.json"
		if a.issuer != nil {
			iss = a.issuer(base)
		}
		if a.jwks != nil {
			jwks = a.jwks(base)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": jwks})
	})
	mux.HandleFunc("/auth/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &e.key.PublicKey, KeyID: "k1", Algorithm: "ES256", Use: "sig"}}}
		_ = json.NewEncoder(w).Encode(set)
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

func TestDiscovery_Success(t *testing.T) {
	e := newDualEnv(t)
	a := newASServer(t, e)
	cfg := JWTConfig{Secret: dualSecret, Issuer: "legacy", ASURL: a.srv.URL + "/auth/", RequireAuth: true}
	tok := e.es256(t, e.key, a.srv.URL+"/auth", time.Minute, "acme")
	// The first request may race the background discovery: poll briefly.
	var code int
	var tenant string
	require.Eventually(t, func() bool {
		code, _, tenant = doReq(t, cfg, tok)
		return code == 200
	}, 3*time.Second, 20*time.Millisecond)
	assert.Equal(t, "acme", tenant)
	// HMAC still works alongside.
	code, _, _ = doReq(t, cfg, hmacTok(t, dualSecret, "legacy", time.Minute))
	assert.Equal(t, 200, code)
}

func TestDiscovery_OpaqueIssuerAndOverride(t *testing.T) {
	e := newDualEnv(t)
	a := newASServer(t, e)
	a.issuer = func(string) string { return "wallet-backend" } // opaque, non-URL issuer
	cfg := JWTConfig{Issuer: "legacy", ASURL: a.srv.URL + "/auth", RequireAuth: true}
	tok := e.es256(t, e.key, "wallet-backend", time.Minute, "")
	require.Eventually(t, func() bool { c, _, _ := doReq(t, cfg, tok); return c == 200 }, 3*time.Second, 20*time.Millisecond)

	// as_issuer override must match the metadata issuer.
	cfg.ASIssuer = "something-else"
	sv := newSessionValidator(cfg, nil, zap.NewNop(), true)
	sv.tryDiscover(context.Background())
	assert.False(t, sv.ready(), "override mismatch must not be adopted")
}

func TestDiscovery_IssuerMismatchRejected(t *testing.T) {
	e := newDualEnv(t)
	a := newASServer(t, e)
	a.issuer = func(string) string { return "https://evil.example/auth" }
	cfg := JWTConfig{ASURL: a.srv.URL + "/auth", Issuer: "x"}
	_, _, err := discoverAS(context.Background(), http.DefaultClient, cfg.ASURL, "", true)
	assert.ErrorContains(t, err, "does not match requested")

	code, _, _ := doReq(t, JWTConfig{ASURL: a.srv.URL + "/auth", Issuer: "x", RequireAuth: true}, e.es256(t, e.key, "https://evil.example/auth", time.Minute, ""))
	assert.Equal(t, 401, code)
}

func TestDiscovery_JWKSURIMustBeSameOriginAndHTTPS(t *testing.T) {
	e := newDualEnv(t)
	a := newASServer(t, e)
	a.jwks = func(string) string { return "https://evil.example/jwks.json" }
	_, _, err := discoverAS(context.Background(), http.DefaultClient, a.srv.URL+"/auth", "", true)
	assert.ErrorContains(t, err, "same-origin")

	a.jwks = nil
	// plaintext not allowed: as_url itself is http
	_, _, err = discoverAS(context.Background(), http.DefaultClient, a.srv.URL+"/auth", "", false)
	assert.ErrorContains(t, err, "https")
}

func TestDiscovery_BadMetadata(t *testing.T) {
	for name, body := range map[string]string{
		"not json":     "nope",
		"missing":      `{"issuer":"x"}`,
		"empty issuer": `{"issuer":"","jwks_uri":"http://x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer srv.Close()
			_, _, err := discoverAS(context.Background(), http.DefaultClient, srv.URL, "", true)
			assert.Error(t, err)
		})
	}
	_, _, err := discoverAS(context.Background(), http.DefaultClient, "://bad", "", true)
	assert.Error(t, err)
}

func TestDiscovery_FailClosedThenRecovers(t *testing.T) {
	e := newDualEnv(t)
	a := newASServer(t, e)
	a.fail.Store(true)
	cfg := JWTConfig{Secret: dualSecret, Issuer: "legacy", ASURL: a.srv.URL + "/auth", RequireAuth: true}
	tok := e.es256(t, e.key, a.srv.URL+"/auth", time.Minute, "")

	sv := newSessionValidator(cfg, nil, zap.NewNop(), true)
	sv.backoff = time.Millisecond // fast retries for the test
	_, err := sv.validate(context.Background(), tok)
	assert.Error(t, err, "ES256 must be refused while discovery has not succeeded")
	assert.False(t, sv.ready())
	// HMAC works meanwhile (legacy enabled).
	_, err = sv.validate(context.Background(), hmacTok(t, dualSecret, "legacy", time.Minute))
	assert.NoError(t, err)
	// backoff gate: an immediate retry does not hit the AS again
	assert.Greater(t, sv.tryDiscover(context.Background()), time.Duration(0))

	a.fail.Store(false)
	require.Eventually(t, func() bool {
		_, err := sv.validate(context.Background(), tok)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "must recover once the AS is reachable")
	assert.True(t, sv.ready())
	assert.Equal(t, time.Duration(0), sv.tryDiscover(context.Background()))
}

func TestDiscovery_UsesInjectedHTTPClient(t *testing.T) {
	e := newDualEnv(t)
	a := newASServer(t, e)
	used := atomic.Bool{}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used.Store(true)
		return http.DefaultTransport.RoundTrip(r)
	})}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(JWTMiddleware(JWTConfig{Issuer: "x", ASURL: a.srv.URL + "/auth", RequireAuth: true}, zap.NewNop(),
		WithJWTHTTPClient(client), WithJWTAllowPlaintext(true)))
	r.GET("/x", func(c *gin.Context) { c.Status(200) })
	tok := e.es256(t, e.key, a.srv.URL+"/auth", time.Minute, "")
	require.Eventually(t, func() bool {
		req := httptest.NewRequest("GET", "/x", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code == 200
	}, 3*time.Second, 20*time.Millisecond)
	assert.True(t, used.Load())
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDiscovery_ExplicitOverrideSkipsDiscovery(t *testing.T) {
	e := newDualEnv(t)
	// as_url points nowhere; jwks_url wins, so no discovery is attempted.
	cfg := JWTConfig{Issuer: "iss", ASURL: "http://127.0.0.1:1", JWKSURL: e.jwksURL, RequireAuth: true}
	code, _, _ := doReq(t, cfg, e.es256(t, e.key, "iss", time.Minute, ""))
	assert.Equal(t, 200, code)
}

func TestDiscovery_ExplicitIssuerOverrideWithDiscovery(t *testing.T) {
	e := newDualEnv(t)
	a := newASServer(t, e)
	cfg := JWTConfig{Issuer: "legacy", ASURL: a.srv.URL + "/auth", ASIssuer: a.srv.URL + "/auth", RequireAuth: true}
	tok := e.es256(t, e.key, a.srv.URL+"/auth", time.Minute, "")
	require.Eventually(t, func() bool { c, _, _ := doReq(t, cfg, tok); return c == 200 }, 3*time.Second, 20*time.Millisecond)
}

func TestConfig_Validate_JWTDual(t *testing.T) {
	newCfg := func() *Config {
		c := DefaultConfig()
		c.Cache.Path = t.TempDir() + "/c.json"
		return c
	}
	c := newCfg()
	c.JWT.JWKSURL = "ftp://x/y"
	assert.ErrorContains(t, c.Validate(), "jwks_url")

	c = newCfg()
	c.JWT.JWKSURL = "http://wallet.example.com/jwks.json"
	assert.ErrorContains(t, c.Validate(), "must use https")
	c.HTTPClient.AllowHTTP = true
	assert.NoError(t, c.Validate())

	c = newCfg()
	c.JWT.ASURL = "http://wallet.example.com/auth"
	assert.ErrorContains(t, c.Validate(), "jwt.as_url")

	for _, mut := range []func(*JWTConfig){
		func(j *JWTConfig) { j.JWKSURL = "https://wallet.example.com/auth/.well-known/jwks.json" },
		func(j *JWTConfig) { j.ASURL = "https://wallet.example.com/auth" },
		func(j *JWTConfig) { j.Secret = "s" },
	} {
		c = newCfg()
		c.JWT.RequireAuth = true
		mut(&c.JWT)
		assert.NoError(t, c.Validate(), "require_auth is satisfied by secret, jwks_url or as_url")
	}

	off := false
	c = newCfg()
	c.JWT.RequireAuth = true
	c.JWT.Secret = "s"
	c.JWT.LegacyEnabled = &off
	assert.ErrorContains(t, c.Validate(), "no token could ever validate")
	c.JWT.ASURL = "https://wallet.example.com/auth"
	assert.NoError(t, c.Validate())
}
