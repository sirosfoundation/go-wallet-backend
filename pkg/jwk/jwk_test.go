package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestThumbprint(t *testing.T) {
	// Known test vector
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x-value",
		"y":   "test-y-value",
	}

	jkt, err := Thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}

	if jkt == "" {
		t.Fatal("JKT should not be empty")
	}

	// Verify deterministic
	jkt2, _ := Thumbprint(jwk)
	if jkt != jkt2 {
		t.Fatal("JKT should be deterministic")
	}
}

func TestThumbprint_UnsupportedKeyType(t *testing.T) {
	_, err := Thumbprint(map[string]interface{}{
		"kty": "RSA",
		"n":   "test",
	})
	if err == nil {
		t.Error("expected error for RSA key type")
	}
}

func TestThumbprint_IncompleteJWK(t *testing.T) {
	_, err := Thumbprint(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		// missing x and y
	})
	if err == nil {
		t.Error("expected error for incomplete EC JWK")
	}
}

func TestParseECPublicKey(t *testing.T) {
	// Generate a key and round-trip through JWK
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}

	parsed, err := ParseECPublicKey(jwk)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.X.Cmp(key.PublicKey.X) != 0 || parsed.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("parsed key doesn't match original")
	}
}

func TestParseECPublicKey_InvalidCurve(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-999",
		"x":   base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		"y":   base64.RawURLEncoding.EncodeToString([]byte{4, 5, 6}),
	}
	_, err := ParseECPublicKey(jwk)
	if err == nil {
		t.Error("expected error for unsupported curve")
	}
}

func TestParseECPublicKey_MissingFields(t *testing.T) {
	// Missing x
	_, err := ParseECPublicKey(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"y":   "AAAA",
	})
	if err == nil {
		t.Error("expected error for missing x")
	}

	// Missing crv
	_, err = ParseECPublicKey(map[string]interface{}{
		"kty": "EC",
		"x":   "AAAA",
		"y":   "BBBB",
	})
	if err == nil {
		t.Error("expected error for missing crv")
	}
}

func TestParseECPublicKey_WrongKeyType(t *testing.T) {
	_, err := ParseECPublicKey(map[string]interface{}{
		"kty": "RSA",
	})
	if err == nil {
		t.Error("expected error for RSA key type")
	}
}

func TestCurveForName(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CurveForName(tt.name)
			if got != tt.curve {
				t.Errorf("CurveForName(%q) mismatch", tt.name)
			}
		})
	}
	// Unsupported curves should return nil
	for _, name := range []string{"P-384", "P-521", "unsupported"} {
		if c := CurveForName(name); c != nil {
			t.Errorf("expected nil for %q curve", name)
		}
	}
}
