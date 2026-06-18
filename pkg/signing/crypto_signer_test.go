package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestCryptoSignerES256_SignToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewCryptoSignerES256(key)
	if err != nil {
		t.Fatal(err)
	}

	claims := jwt.MapClaims{
		"sub":  "test-subject",
		"name": "Test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "test+jwt"

	tokenString, err := signer.SignToken(token)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	if tokenString == "" {
		t.Fatal("empty token string")
	}

	// Verify the token with the public key
	parsed, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !parsed.Valid {
		t.Fatal("token not valid")
	}

	parsedClaims := parsed.Claims.(jwt.MapClaims)
	if parsedClaims["sub"] != "test-subject" {
		t.Errorf("sub = %v, want test-subject", parsedClaims["sub"])
	}
}

func TestCryptoSignerES256_RejectsNonP256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, err := NewCryptoSignerES256(key)
	if err == nil {
		t.Fatal("should reject P-384 key")
	}
}

func TestCryptoSignerES256_RejectsNonNilKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewCryptoSignerES256(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = signer.Sign("test-string", "unexpected-key")
	if err == nil {
		t.Fatal("Sign should reject non-nil key")
	}
}
