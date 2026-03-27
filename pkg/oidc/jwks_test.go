package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestJWK_rsaPublicKey_ValidExponent(t *testing.T) {
	// Generate a real RSA key to get valid modulus
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwk := &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
	}

	key, err := jwk.rsaPublicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.E != privateKey.E {
		t.Errorf("expected exponent %d, got %d", privateKey.E, key.E)
	}
}

func TestJWK_rsaPublicKey_ExponentTooSmall(t *testing.T) {
	// Generate a real RSA key to get valid modulus
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Exponent of 1 is invalid for RSA
	jwk := &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()), // Invalid
	}

	_, err = jwk.rsaPublicKey()
	if err == nil {
		t.Error("expected error for exponent < 3, got nil")
	}
}

func TestJWK_rsaPublicKey_ExponentThree(t *testing.T) {
	// Generate a real RSA key to get valid modulus
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Exponent of 3 is valid (though weak)
	jwk := &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(3).Bytes()), // Valid but weak
	}

	key, err := jwk.rsaPublicKey()
	if err != nil {
		t.Fatalf("unexpected error for exponent 3: %v", err)
	}

	if key.E != 3 {
		t.Errorf("expected exponent 3, got %d", key.E)
	}
}

func TestJWK_rsaPublicKey_ExponentOverflow(t *testing.T) {
	// Generate a real RSA key to get valid modulus
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Very large exponent that exceeds int32 max
	largeExp := new(big.Int).SetInt64(1 << 40) // > MaxInt32
	jwk := &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(largeExp.Bytes()),
	}

	_, err = jwk.rsaPublicKey()
	if err == nil {
		t.Error("expected error for exponent overflow, got nil")
	}
}

func TestJWK_rsaPublicKey_EmptyExponent(t *testing.T) {
	// Generate a real RSA key to get valid modulus
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Empty exponent decodes to 0 bytes, which results in 0 value
	jwk := &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
		E:   "", // Empty = 0, which is invalid
	}

	_, err = jwk.rsaPublicKey()
	if err == nil {
		t.Error("expected error for empty/zero exponent, got nil")
	}
}
