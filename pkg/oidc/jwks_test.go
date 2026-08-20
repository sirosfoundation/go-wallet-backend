package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

func TestJWK_ecPublicKey_ValidP256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	xBytes := make([]byte, 32)
	privateKey.PublicKey.X.FillBytes(xBytes)
	yBytes := make([]byte, 32)
	privateKey.PublicKey.Y.FillBytes(yBytes)

	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	key, err := jwk.ecPublicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.X.Cmp(privateKey.PublicKey.X) != 0 || key.Y.Cmp(privateKey.PublicKey.Y) != 0 {
		t.Error("parsed public key does not match the original")
	}
}

func TestJWK_ecPublicKey_UnsupportedCurve(t *testing.T) {
	jwk := &JWK{
		Kty: "EC",
		Crv: "P-192",
		X:   "test",
		Y:   "test",
	}

	_, err := jwk.ecPublicKey()
	if err == nil {
		t.Error("expected error for unsupported curve, got nil")
	}
}

func TestJWK_ecPublicKey_InvalidXBase64(t *testing.T) {
	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   "!!!invalid!!!",
		Y:   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	_, err := jwk.ecPublicKey()
	if err == nil {
		t.Error("expected error for invalid x coordinate, got nil")
	}
}

func TestJWK_ecPublicKey_InvalidYBase64(t *testing.T) {
	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Y:   "!!!invalid!!!",
	}

	_, err := jwk.ecPublicKey()
	if err == nil {
		t.Error("expected error for invalid y coordinate, got nil")
	}
}

func TestJWK_ecPublicKey_OversizedCoordinate(t *testing.T) {
	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(make([]byte, 33)), // too long
		Y:   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}

	_, err := jwk.ecPublicKey()
	if err == nil {
		t.Error("expected error for oversized x/y coordinate, got nil")
	}
}

func TestJWK_ecPublicKey_ShortCoordinateIsLeftPadded(t *testing.T) {
	// Real-world producers sometimes omit a coordinate's leading zero byte
	// rather than following RFC 7518 §6.2.1.2's fixed-length encoding -
	// find a key whose X has one (~1/256 of keys) and confirm the
	// shortened form still parses to the same point, matching this
	// codebase's other EC JWK parser (pkg/jwk.parseECJWK).
	var shortKey *ecdsa.PrivateKey
	var shortXBytes []byte
	for i := 0; i < 4096; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		full := make([]byte, 32)
		k.PublicKey.X.FillBytes(full)
		if full[0] == 0 {
			shortKey = k
			shortXBytes = full[1:]
			break
		}
	}
	if shortKey == nil {
		t.Fatal("failed to find a P-256 key with a leading-zero X coordinate after 4096 attempts")
	}
	fullYBytes := make([]byte, 32)
	shortKey.PublicKey.Y.FillBytes(fullYBytes)

	jwk := &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(shortXBytes), // 31 bytes
		Y:   base64.RawURLEncoding.EncodeToString(fullYBytes),
	}

	key, err := jwk.ecPublicKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key.X.Cmp(shortKey.PublicKey.X) != 0 || key.Y.Cmp(shortKey.PublicKey.Y) != 0 {
		t.Error("left-padded coordinate did not reconstruct the original point")
	}
}
