package engine

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestManager_validateToken_LegacyRefusedAfterSunset(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": "u", "tenant_id": "t", "aud": "wallet-backend", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(secret))
	require.NoError(t, err)

	mk := func(sunset string) *Manager {
		cfg := &config.Config{JWT: config.JWTConfig{Secret: secret}}
		cfg.AS.Enabled = true
		cfg.AS.Legacy = config.ASLegacyConfig{Enabled: true, SunsetDate: sunset}
		m := NewManager(cfg, zap.NewNop())
		// Validator built before the sunset: legacy still enabled inside it.
		m.SetTokenValidator(tokenvalidator.New(tokenvalidator.Config{
			Legacy: tokenvalidator.LegacyConfig{Enabled: true, HMACSecret: []byte(secret)},
		}))
		return m
	}

	uid, _, _, err := mk(time.Now().Add(time.Hour).UTC().Format(time.RFC3339)).validateToken(tok)
	require.NoError(t, err)
	assert.Equal(t, "u", uid)

	_, _, _, err = mk(time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)).validateToken(tok)
	assert.ErrorContains(t, err, "sunset_date")
}
