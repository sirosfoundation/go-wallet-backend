package middleware

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func gojwtSigned(t *testing.T, secret []byte, claims map[string]any) string {
	t.Helper()
	m := gojwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range claims {
		m[k] = v
	}
	s, err := gojwt.NewWithClaims(gojwt.SigningMethodHS256, m).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
