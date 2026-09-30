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
	hm, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "u", "tenant_id": "t", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	require.NoError(t, err)

	base := func(legacy bool) *config.Config {
		c := &config.Config{JWT: config.JWTConfig{Secret: secret, Issuer: "legacy"}}
		c.AS.Enabled = true // unloaded config: the switch is honoured with the AS on
		c.AS.Legacy.Enabled = legacy
		c.AS.Issuer = "as-issuer"
		c.AS.ExternalURL = srv.URL + "/"
		return c
	}

	t.Run("legacy off: ES256 accepted, HMAC refused", func(t *testing.T) {
		v, err := NewStandaloneEngineTokenValidator(base(false), zap.NewNop())
		require.NoError(t, err)
		require.NotNil(t, v)
		defer func() { _ = v.Close() }()
		require.Eventually(t, func() bool {
			_, err := v.Validate(context.Background(), es)
			return err == nil
		}, 3*time.Second, 20*time.Millisecond)
		_, err = v.Validate(context.Background(), hm)
		assert.Error(t, err)
	})

	t.Run("legacy on: both accepted", func(t *testing.T) {
		v, err := NewStandaloneEngineTokenValidator(base(true), zap.NewNop())
		require.NoError(t, err)
		defer func() { _ = v.Close() }()
		_, err = v.Validate(context.Background(), hm)
		assert.NoError(t, err)
	})

	t.Run("legacy off without external_url: refuse to start", func(t *testing.T) {
		c := base(false)
		c.AS.ExternalURL = ""
		v, err := NewStandaloneEngineTokenValidator(c, zap.NewNop())
		assert.Error(t, err)
		assert.Nil(t, v)
	})

	t.Run("legacy on without external_url: HMAC fallback, no validator", func(t *testing.T) {
		c := base(true)
		c.AS.ExternalURL = ""
		v, err := NewStandaloneEngineTokenValidator(c, zap.NewNop())
		assert.NoError(t, err)
		assert.Nil(t, v)
	})
}
