package middleware

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func hmacLegacyToken(t *testing.T, secret []byte) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"user_id": "u1", "tenant_id": "default", "exp": time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
