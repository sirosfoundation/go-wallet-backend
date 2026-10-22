package server

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

	"github.com/go-jose/go-jose/v4"
	gojosejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewStandaloneEngineTokenValidator(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	es := func() string {
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		require.NoError(t, err)
		raw, err := gojosejwt.Signed(sig).Claims(map[string]any{
			"iss": "as-issuer", "sub": "u", "tenant_id": "t", "aud": []string{"wallet-backend"},
			"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
		}).Serialize()
		require.NoError(t, err)
		return raw
	}()
	// HS256 signed with jwt.secret, jwt.issuer as iss and the RP ID as aud.
	hm, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "u", "tenant_id": "t", "iss": "legacy", "aud": "rp.example",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	require.NoError(t, err)

	base := func() *config.Config {
		c := &config.Config{JWT: config.JWTConfig{Secret: secret, Issuer: "legacy"}}
		c.AS.Enabled = true
		c.AS.Issuer = "as-issuer"
		c.AS.Audiences = []string{"wallet-backend", "rp.example", "any-rp-id"}
		c.AS.ExternalURL = srv.URL + "/"
		return c
	}

	t.Run("ES256 accepted, HMAC refused", func(t *testing.T) {
		v, err := NewStandaloneEngineTokenValidator(base(), zap.NewNop(), nil)
		require.NoError(t, err)
		require.NotNil(t, v)
		defer func() { _ = v.Close() }()
		require.Eventually(t, func() bool {
			_, err := v.Validate(context.Background(), es)
			return err == nil
		}, 3*time.Second, 20*time.Millisecond)
		_, err = v.Validate(context.Background(), hm)
		assert.Error(t, err, "an HMAC token signed with jwt.secret must be refused")
	})

	t.Run("invalid external_url", func(t *testing.T) {
		c := base()
		c.AS.ExternalURL = "ftp://x"
		_, err := asJWKSURL(c)
		assert.Error(t, err)
	})

	t.Run("without external_url: refuse to start", func(t *testing.T) {
		c := base()
		c.AS.ExternalURL = ""
		v, err := NewStandaloneEngineTokenValidator(c, zap.NewNop(), nil)
		assert.ErrorContains(t, err, "as.external_url")
		assert.Nil(t, v)
	})
}

func TestRemoteASIssuerRefusesEmpty(t *testing.T) {
	c := &config.Config{}
	c.AS.ExternalURL = "https://as.example.com"

	v, err := NewStandaloneEngineTokenValidator(c, zap.NewNop(), nil)
	assert.ErrorContains(t, err, "expected issuer is required")
	assert.Nil(t, v)

	_, err = remoteASIssuer(c, "x")
	assert.Error(t, err)

	c.JWT.Issuer = "jwt-iss"
	iss, err := remoteASIssuer(c, "x")
	require.NoError(t, err)
	assert.Equal(t, "jwt-iss", iss)

	c.AS.Issuer = "as-iss"
	iss, err = remoteASIssuer(c, "x")
	require.NoError(t, err)
	assert.Equal(t, "as-iss", iss)
}

func TestNewStandaloneEngineTokenValidator_WarnsNoRevocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{})
	}))
	defer srv.Close()
	c := &config.Config{JWT: config.JWTConfig{Secret: "0123456789abcdef0123456789abcdef", Issuer: "legacy"}}
	c.AS.Enabled = true
	c.AS.Issuer = "as-issuer"
	c.AS.ExternalURL = srv.URL
	c.HTTPClient = config.HTTPClientConfig{AllowHTTP: true, AllowPrivateIPs: true}

	core, logs := observer.New(zap.WarnLevel)
	v, err := NewStandaloneEngineTokenValidator(c, zap.New(core), nil)
	require.NoError(t, err)
	require.NotNil(t, v)
	defer func() { _ = v.Close() }()

	warns := logs.FilterMessageSnippet("no token revocation source").All()
	require.Len(t, warns, 1)
	assert.Equal(t, zap.WarnLevel, warns[0].Level)
}

func TestASJWKSURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://as.example.com":                "https://as.example.com/auth/.well-known/jwks.json",
		"https://as.example.com/":               "https://as.example.com/auth/.well-known/jwks.json",
		"http://backend.ns.svc:8080/":           "http://backend.ns.svc:8080/auth/.well-known/jwks.json",
		"http://backend.ns.svc:8080/base/path/": "http://backend.ns.svc:8080/base/path/auth/.well-known/jwks.json",
	} {
		c := &config.Config{}
		c.AS.ExternalURL = in
		got, err := asJWKSURL(c)
		require.NoError(t, err, in)
		assert.Equal(t, want, got)
	}
	c := &config.Config{}
	c.AS.ExternalURL = "ftp://x"
	_, err := asJWKSURL(c)
	assert.Error(t, err)
}

type downRevocationStore struct{}

func (downRevocationStore) Add(context.Context, string, time.Time) error { return assert.AnError }
func (downRevocationStore) Has(context.Context, string) (bool, error)    { return false, assert.AnError }
func (downRevocationStore) RevokeUser(context.Context, string) error     { return assert.AnError }
func (downRevocationStore) IsUserRevoked(context.Context, string) (bool, error) {
	return false, assert.AnError
}

// With the shared blacklist the standalone validator rejects a revoked jti
// (anonymous tokens included, which have no user to check) and refuses when
// the store cannot answer; without a revoked jti the same token is accepted.
func TestNewStandaloneEngineTokenValidator_ChecksJTIRevocation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	token := func(jti string) string {
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		require.NoError(t, err)
		raw, err := gojosejwt.Signed(sig).Claims(map[string]any{
			"iss": "as-issuer", "jti": jti, "tenant_id": "t", "aud": []string{"wallet-backend"}, // no sub: anonymous
			"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
		}).Serialize()
		require.NoError(t, err)
		return raw
	}
	cfg := func() *config.Config {
		c := &config.Config{}
		c.AS.Enabled = true
		c.AS.Issuer = "as-issuer"
		c.AS.Audiences = []string{"wallet-backend"}
		c.AS.ExternalURL = srv.URL
		c.HTTPClient = config.HTTPClientConfig{AllowHTTP: true, AllowPrivateIPs: true}
		return c
	}
	start := func(t *testing.T, bl *service.TokenBlacklist) (*StandaloneValidator, *observer.ObservedLogs) {
		core, logs := observer.New(zap.WarnLevel)
		v, err := NewStandaloneEngineTokenValidator(cfg(), zap.New(core), bl)
		require.NoError(t, err)
		t.Cleanup(func() { _ = v.Close() })
		require.Eventually(t, func() bool {
			_, err := v.Validate(context.Background(), token("probe"))
			return err == nil || bl != nil // a blacklist may reject the probe; JWKS is then loaded by the next call
		}, 3*time.Second, 20*time.Millisecond)
		return v, logs
	}
	enabled := config.TokenBlacklistConfig{Enabled: true}

	t.Run("revoked jti is rejected, other jti accepted, no warning", func(t *testing.T) {
		bl := service.NewTokenBlacklist(enabled, zap.NewNop())
		require.NoError(t, bl.Add(context.Background(), "revoked", time.Now().Add(time.Hour)))
		v, logs := start(t, bl)
		require.Eventually(t, func() bool {
			_, err := v.Validate(context.Background(), token("fine"))
			return err == nil
		}, 3*time.Second, 20*time.Millisecond, "positive control")
		_, err := v.Validate(context.Background(), token("revoked"))
		assert.Error(t, err)
		assert.Zero(t, logs.FilterMessageSnippet("no token revocation source").Len())
	})

	t.Run("store outage rejects", func(t *testing.T) {
		bl := service.NewTokenBlacklistWithStore(enabled, zap.NewNop(), downRevocationStore{})
		v, _ := start(t, bl)
		time.Sleep(200 * time.Millisecond) // let the JWKS load
		_, err := v.Validate(context.Background(), token("any"))
		assert.Error(t, err)
	})

	t.Run("without a blacklist the revoked jti is accepted (documented gap, warned)", func(t *testing.T) {
		v, logs := start(t, nil)
		_, err := v.Validate(context.Background(), token("revoked"))
		assert.NoError(t, err)
		assert.Equal(t, 1, logs.FilterMessageSnippet("no token revocation source").Len())
	})
}
