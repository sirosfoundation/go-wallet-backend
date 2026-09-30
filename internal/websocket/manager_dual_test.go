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

const wsDualSecret = "0123456789abcdef0123456789abcdef"

func wsValidator(t *testing.T, legacy bool) (*tokenvalidator.Validator, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "ES256"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)
	v := tokenvalidator.New(tokenvalidator.Config{
		JWKSURL: srv.URL,
		Issuer:  "as",
		Legacy:  tokenvalidator.LegacyConfig{Enabled: legacy, HMACSecret: []byte(wsDualSecret)},
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

func wsHMAC(t *testing.T, secret string) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":     "test-issuer",
		"user_id": "legacy-user", "tenant_id": "default", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func wsCfg(asEnabled, legacyEnabled bool) *config.Config {
	c := &config.Config{JWT: config.JWTConfig{Secret: wsDualSecret, Issuer: "test-issuer"}}
	c.AS.Enabled = asEnabled
	c.AS.Legacy = config.ASLegacyConfig{Enabled: legacyEnabled}
	return c
}

func TestManager_validateToken_Dual(t *testing.T) {
	v, key := wsValidator(t, true)
	m := NewManager(wsCfg(true, true), zap.NewNop())
	m.SetTokenValidator(v)

	uid, err := m.validateToken(wsES256(t, key, "es-user", time.Minute))
	require.NoError(t, err)
	assert.Equal(t, "es-user", uid)

	uid, err = m.validateToken(wsHMAC(t, wsDualSecret))
	require.NoError(t, err)
	assert.Equal(t, "legacy-user", uid)

	// expired, forged, anonymous, none-alg, garbage
	_, err = m.validateToken(wsES256(t, key, "es-user", -time.Hour))
	assert.Error(t, err)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = m.validateToken(wsES256(t, other, "es-user", time.Minute))
	assert.Error(t, err)
	_, err = m.validateToken(wsES256(t, key, "", time.Minute))
	assert.Error(t, err, "anonymous token has no user to bind the keystore socket to")
	_, err = m.validateToken(wsHMAC(t, "wrong-secret-wrong-secret-wrong-xx"))
	assert.Error(t, err)
	none, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"user_id": "x", "exp": time.Now().Add(time.Hour).Unix()}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	_, err = m.validateToken(none)
	assert.Error(t, err)
	_, err = m.validateToken("garbage")
	assert.Error(t, err)
}

func TestManager_validateToken_LegacyDisabledInValidator(t *testing.T) {
	v, key := wsValidator(t, false)
	m := NewManager(wsCfg(true, true), zap.NewNop())
	m.SetTokenValidator(v)
	_, err := m.validateToken(wsHMAC(t, wsDualSecret))
	assert.Error(t, err)
	_, err = m.validateToken(wsES256(t, key, "u", time.Minute))
	assert.NoError(t, err)
}

func TestManager_validateToken_LegacyDisabled(t *testing.T) {
	// Without a validator: HMAC refused when the AS is enabled with legacy off.
	m := NewManager(wsCfg(true, false), zap.NewNop())
	_, err := m.validateToken(wsHMAC(t, wsDualSecret))
	assert.ErrorContains(t, err, "disabled")
	// Legacy on: allowed.
	m = NewManager(wsCfg(true, true), zap.NewNop())
	_, err = m.validateToken(wsHMAC(t, wsDualSecret))
	assert.NoError(t, err)
}

func TestManager_validateToken_AudienceNewStyleOnly(t *testing.T) {
	v, key := wsValidator(t, true)
	cfg := wsCfg(true, true)
	cfg.AS.Audiences = []string{"wallet-backend"}
	m := NewManager(cfg, zap.NewNop())
	m.SetTokenValidator(v)

	// Legacy HMAC token carries the RP ID as aud: never filtered.
	hm, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":     "test-issuer",
		"user_id": "legacy-user", "aud": "rp.example.com", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(wsDualSecret))
	require.NoError(t, err)
	uid, err := m.validateToken(hm)
	require.NoError(t, err)
	assert.Equal(t, "legacy-user", uid)

	// New-style token without the configured audience is refused.
	_, err = m.validateToken(wsES256Aud(t, key, "u", time.Minute, "wallet-registry"))
	assert.ErrorContains(t, err, "audience")
}

func TestManager_validateToken_RequiresWalletBackendAudience(t *testing.T) {
	v, key := wsValidator(t, true)
	// as.audiences empty and as.audiences containing wallet-registry must both
	// still require wallet-backend for new-style tokens.
	for _, auds := range [][]string{nil, {"wallet-registry"}} {
		cfg := wsCfg(true, true)
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

		uid, err = m.validateToken(wsHMAC(t, wsDualSecret))
		require.NoError(t, err, "legacy token exempt from audience checks")
		assert.Equal(t, "legacy-user", uid)
	}
}

func TestManager_validateToken_EmptySecretRefused(t *testing.T) {
	cfg := wsCfg(false, true)
	cfg.JWT.Secret = ""
	m := NewManager(cfg, zap.NewNop())
	_, err := m.validateToken(wsHMAC(t, ""))
	assert.Error(t, err)
}

func TestManager_validateToken_LegacyIssuerPinned(t *testing.T) {
	mint := func(claims jwt.MapClaims) string {
		claims["user_id"], claims["tenant_id"], claims["exp"] = "legacy-user", "default", time.Now().Add(time.Hour).Unix()
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(wsDualSecret))
		require.NoError(t, err)
		return s
	}
	m := NewManager(wsCfg(false, true), zap.NewNop())
	uid, err := m.validateToken(mint(jwt.MapClaims{"iss": "test-issuer"}))
	require.NoError(t, err)
	assert.Equal(t, "legacy-user", uid)
	_, err = m.validateToken(mint(jwt.MapClaims{}))
	assert.Error(t, err, "missing iss")
	_, err = m.validateToken(mint(jwt.MapClaims{"iss": "someone-else"}))
	assert.Error(t, err, "mismatched iss")

	cfg := wsCfg(false, true)
	cfg.JWT.Issuer = ""
	m = NewManager(cfg, zap.NewNop())
	_, err = m.validateToken(mint(jwt.MapClaims{"iss": ""}))
	assert.Error(t, err, "empty jwt.issuer must fail closed")
}
