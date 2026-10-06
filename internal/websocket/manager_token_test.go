package websocket

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

	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const wsHMACSecret = "0123456789abcdef0123456789abcdef"

func wsValidator(t *testing.T) (*tokenvalidator.Validator, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	v := tokenvalidator.New(tokenvalidator.Config{
		JWKSURL:   srv.URL,
		Issuer:    "as",
		Audiences: []string{"wallet-backend", "wallet-registry"},
	})
	v.Start(context.Background())
	t.Cleanup(v.Stop)
	return v, key
}

func wsES256(t *testing.T, key *ecdsa.PrivateKey, sub string, exp time.Duration) string {
	t.Helper()
	return wsES256Aud(t, key, sub, exp, "wallet-backend")
}

func wsES256Aud(t *testing.T, key *ecdsa.PrivateKey, sub string, exp time.Duration, aud ...string) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	require.NoError(t, err)
	claims := map[string]any{"iss": "as", "tenant_id": "default", "tac": "r",
		"iat": time.Now().Unix(), "exp": time.Now().Add(exp).Unix()}
	if sub != "" {
		claims["sub"] = sub
	}
	if len(aud) > 0 {
		claims["aud"] = aud
	}
	raw, err := gojosejwt.Signed(sig).Claims(claims).Serialize()
	require.NoError(t, err)
	return raw
}

// wsHMAC signs an HS256 token the way the removed legacy AS did.
func wsHMAC(t *testing.T, secret string) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":     "as",
		"user_id": "legacy-user", "tenant_id": "default", "aud": "wallet-backend", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func TestManager_validateToken(t *testing.T) {
	v, key := wsValidator(t)
	m := NewManager(&config.Config{}, zap.NewNop())
	m.SetTokenValidator(v)

	uid, err := m.validateToken(wsES256(t, key, "es-user", time.Minute))
	require.NoError(t, err)
	assert.Equal(t, "es-user", uid)

	// expired, forged, anonymous, none-alg, garbage
	_, err = m.validateToken(wsES256(t, key, "es-user", -time.Hour))
	assert.Error(t, err)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = m.validateToken(wsES256(t, other, "es-user", time.Minute))
	assert.Error(t, err)
	_, err = m.validateToken(wsES256(t, key, "", time.Minute))
	assert.Error(t, err, "anonymous token has no user to bind the keystore socket to")
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"user_id": "x", "exp": time.Now().Add(time.Hour).Unix()}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	_, err = m.validateToken(none)
	assert.Error(t, err)
	_, err = m.validateToken("garbage")
	assert.Error(t, err)
}

// The legacy HMAC AS is gone: an HS256 token - whatever its secret, issuer or
// audience - is refused, with a validator wired or not.
func TestManager_validateToken_HMACRefused(t *testing.T) {
	v, key := wsValidator(t)
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: wsHMACSecret, Issuer: "as"}}, zap.NewNop())
	m.SetTokenValidator(v)
	_, err := m.validateToken(wsHMAC(t, wsHMACSecret))
	assert.Error(t, err, "an HMAC token signed with jwt.secret must be refused")
	_, err = m.validateToken(wsES256(t, key, "u", time.Minute))
	assert.NoError(t, err)
}

func TestManager_validateToken_NoValidatorFailsClosed(t *testing.T) {
	m := NewManager(&config.Config{JWT: config.JWTConfig{Secret: wsHMACSecret, Issuer: "as"}}, zap.NewNop())
	_, err := m.validateToken(wsHMAC(t, wsHMACSecret))
	assert.ErrorContains(t, err, "no token validator")
}

func TestManager_validateToken_RequiresWalletBackendAudience(t *testing.T) {
	v, key := wsValidator(t)
	// as.audiences empty and as.audiences containing wallet-registry must both
	// still require wallet-backend.
	for _, auds := range [][]string{nil, {"wallet-registry"}} {
		cfg := &config.Config{}
		cfg.AS.Audiences = auds
		m := NewManager(cfg, zap.NewNop())
		m.SetTokenValidator(v)

		uid, err := m.validateToken(wsES256Aud(t, key, "u", time.Minute, "wallet-backend", "wallet-registry"))
		require.NoError(t, err)
		assert.Equal(t, "u", uid)

		_, err = m.validateToken(wsES256Aud(t, key, "u", time.Minute, "wallet-registry"))
		assert.ErrorContains(t, err, "audience", "registry-only token must not open the keystore socket")

		_, err = m.validateToken(wsES256Aud(t, key, "u", time.Minute))
		assert.ErrorContains(t, err, "audience", "token with no audience must be refused")
	}
}
