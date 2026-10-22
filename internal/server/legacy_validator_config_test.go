package server

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// legacyValidatorConfig pins the accepted legacy issuer for every constructor.
func TestLegacyValidatorConfig_PinsJWTIssuer(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	cfg := &config.Config{JWT: config.JWTConfig{Secret: secret, Issuer: "jwt-issuer"}}
	cfg.AS.Issuer = "as-issuer" // differs from jwt.issuer on purpose

	lc := legacyValidatorConfig(cfg, true)
	assert.True(t, lc.Enabled)
	assert.Equal(t, []string{"jwt-issuer"}, lc.Issuers)
	assert.False(t, legacyValidatorConfig(cfg, false).Enabled)

	// Mirror the constructors: top-level Issuer is the AS issuer, and the
	// audience list (which includes the RP ID while legacy is on) is passed.
	v := tokenvalidator.New(tokenvalidator.Config{Issuer: cfg.AS.Issuer, Audiences: []string{"rp.example.org"}, Legacy: lc})
	mint := func(claims jwt.MapClaims) string {
		claims["user_id"], claims["tenant_id"] = "u", "t"
		claims["exp"] = time.Now().Add(time.Hour).Unix()
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		require.NoError(t, err)
		return raw
	}

	_, err := v.Validate(context.Background(), mint(jwt.MapClaims{"iss": "as-issuer"}))
	assert.Error(t, err, "wrong issuer")
	_, err = v.Validate(context.Background(), mint(jwt.MapClaims{"iss": "evil"}))
	assert.Error(t, err, "wrong issuer")
	_, err = v.Validate(context.Background(), mint(jwt.MapClaims{}))
	assert.Error(t, err, "missing issuer")
	_, err = v.Validate(context.Background(), mint(jwt.MapClaims{"iss": "jwt-issuer", "aud": "rp.example.org"}))
	assert.NoError(t, err, "correct issuer accepted, and its RP-ID audience is in the list")
}
