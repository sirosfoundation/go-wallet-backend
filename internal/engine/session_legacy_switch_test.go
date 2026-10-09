package engine

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

const legacySwitchSecret = "0123456789abcdef0123456789abcdef"

func legacySwitchToken(t *testing.T, aud string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":     "test-issuer",
		"user_id": "u", "tenant_id": "t", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(legacySwitchSecret))
	require.NoError(t, err)
	return tok
}

func legacySwitchCfg(asEnabled, legacy bool) *config.Config {
	cfg := &config.Config{JWT: config.JWTConfig{Secret: legacySwitchSecret, Issuer: "test-issuer"}}
	cfg.AS.Enabled = asEnabled
	cfg.AS.Legacy.Enabled = legacy
	return cfg
}

// Without a validator the HMAC fallback honours as.legacy.enabled=false.
func TestManager_validateToken_StandaloneFallbackHonoursLegacySwitch(t *testing.T) {
	tok := legacySwitchToken(t, "rp.example.com")

	m := NewManager(legacySwitchCfg(true, false), zap.NewNop())
	_, _, _, err := m.validateToken(context.Background(), tok)
	assert.ErrorContains(t, err, "disabled")

	m = NewManager(legacySwitchCfg(true, true), zap.NewNop())
	uid, _, _, err := m.validateToken(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, "u", uid)
}

// Legacy HMAC tokens (aud = RP ID) are exempt from audience restrictions.
func TestManager_validateToken_LegacyExemptFromAudience(t *testing.T) {
	cfg := legacySwitchCfg(true, true)
	cfg.AS.Audiences = []string{"wallet-backend"}
	m := NewManager(cfg, zap.NewNop())
	m.SetTokenValidator(tokenvalidator.New(tokenvalidator.Config{
		Audiences: []string{"wallet-backend", "rp.example.com"},
		Legacy:    tokenvalidator.LegacyConfig{Enabled: true, HMACSecret: []byte(legacySwitchSecret), Issuers: []string{"test-issuer"}},
	}))
	uid, _, _, err := m.validateToken(context.Background(), legacySwitchToken(t, "rp.example.com"))
	require.NoError(t, err)
	assert.Equal(t, "u", uid)

	// Legacy disabled in the validator: refused.
	m.SetTokenValidator(tokenvalidator.New(tokenvalidator.Config{Audiences: []string{"wallet-backend", "rp.example.com"}}))
	_, _, _, err = m.validateToken(context.Background(), legacySwitchToken(t, "rp.example.com"))
	assert.Error(t, err)
}

func TestManager_validateToken_LegacyIssuerPinned(t *testing.T) {
	mint := func(claims jwt.MapClaims) string {
		claims["user_id"], claims["tenant_id"], claims["exp"] = "u", "t", time.Now().Add(time.Hour).Unix()
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(legacySwitchSecret))
		require.NoError(t, err)
		return tok
	}
	m := NewManager(legacySwitchCfg(false, true), zap.NewNop())
	uid, _, _, err := m.validateToken(context.Background(), mint(jwt.MapClaims{"iss": "test-issuer"}))
	require.NoError(t, err)
	assert.Equal(t, "u", uid)
	_, _, _, err = m.validateToken(context.Background(), mint(jwt.MapClaims{}))
	assert.Error(t, err, "missing iss")
	_, _, _, err = m.validateToken(context.Background(), mint(jwt.MapClaims{"iss": "someone-else"}))
	assert.Error(t, err, "mismatched iss")

	cfg := legacySwitchCfg(false, true)
	cfg.JWT.Issuer = ""
	m = NewManager(cfg, zap.NewNop())
	_, _, _, err = m.validateToken(context.Background(), mint(jwt.MapClaims{"iss": ""}))
	assert.Error(t, err, "empty jwt.issuer must fail closed")
}
