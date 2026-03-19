package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestExtractKeyMaterialFromJWT(t *testing.T) {
	tests := []struct {
		name     string
		jwtStr   string
		wantType string
		wantNil  bool
	}{
		{
			name:    "invalid JWT format - no parts",
			jwtStr:  "notajwt",
			wantNil: true,
		},
		{
			name:    "invalid JWT format - only one part",
			jwtStr:  "header",
			wantNil: true,
		},
		{
			name:    "invalid header base64",
			jwtStr:  "!!!invalid!!!.payload.signature",
			wantNil: true,
		},
		{
			name:    "invalid header JSON",
			jwtStr:  base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".payload.signature",
			wantNil: true,
		},
		{
			name:    "no key material in header",
			jwtStr:  base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + ".payload.signature",
			wantNil: true,
		},
		{
			name:     "with x5c header",
			jwtStr:   base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","x5c":["MIIBIjANBg"]}`)) + ".payload.signature",
			wantType: "x5c",
		},
		{
			name:     "with jwk header",
			jwtStr:   base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"test","y":"test"}}`)) + ".payload.signature",
			wantType: "jwk",
		},
		{
			name:     "x5c takes precedence over jwk",
			jwtStr:   base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","x5c":["cert"],"jwk":{"kty":"EC"}}`)) + ".payload.signature",
			wantType: "x5c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractKeyMaterialFromJWT(tt.jwtStr)
			if tt.wantNil {
				if result != nil {
					t.Errorf("ExtractKeyMaterialFromJWT() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatal("ExtractKeyMaterialFromJWT() = nil, want non-nil")
			}
			if result.Type != tt.wantType {
				t.Errorf("ExtractKeyMaterialFromJWT().Type = %q, want %q", result.Type, tt.wantType)
			}
		})
	}
}

func TestVerifyJWTWithEmbeddedKey(t *testing.T) {
	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a valid JWT with embedded JWK
	jwk := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
	}

	t.Run("invalid JWT format", func(t *testing.T) {
		_, err := VerifyJWTWithEmbeddedKey("not.a.valid.jwt")
		if err == nil {
			t.Error("Expected error for invalid JWT format")
		}
	})

	t.Run("missing key material", func(t *testing.T) {
		// Create a JWT without embedded key
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "test"})
		tokenStr, _ := token.SignedString(privateKey)
		_, err := VerifyJWTWithEmbeddedKey(tokenStr)
		if err == nil {
			t.Error("Expected error for JWT without embedded key")
		}
	})

	t.Run("JWT with embedded JWK", func(t *testing.T) {
		// Create a JWT with embedded JWK in header
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "test"})
		token.Header["jwk"] = jwk

		tokenStr, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		result, err := VerifyJWTWithEmbeddedKey(tokenStr)
		if err != nil {
			t.Fatalf("VerifyJWTWithEmbeddedKey() error = %v", err)
		}
		if result.Type != "jwk" {
			t.Errorf("VerifyJWTWithEmbeddedKey().Type = %q, want %q", result.Type, "jwk")
		}
	})

	t.Run("signature verification failure", func(t *testing.T) {
		// Create a JWT signed with one key but with a different key in header
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherJWK := map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(otherKey.PublicKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(otherKey.PublicKey.Y.Bytes()),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "test"})
		token.Header["jwk"] = otherJWK // Different key in header

		// Sign with original key (mismatch)
		tokenStr, _ := token.SignedString(privateKey)

		_, err := VerifyJWTWithEmbeddedKey(tokenStr)
		if err == nil {
			t.Error("Expected signature verification failure")
		}
	})
}

func TestEcJWKToPublicKey(t *testing.T) {
	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	t.Run("valid P-256 key", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
		}

		key, err := ecJWKToPublicKey(jwk)
		if err != nil {
			t.Fatalf("ecJWKToPublicKey() error = %v", err)
		}
		if key == nil {
			t.Error("ecJWKToPublicKey() returned nil key")
		}
	})

	t.Run("missing curve", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "EC",
			"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
		}

		_, err := ecJWKToPublicKey(jwk)
		if err == nil {
			t.Error("Expected error for missing curve")
		}
	})

	t.Run("unsupported curve", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "EC",
			"crv": "P-192", // Unsupported curve
			"x":   "test",
			"y":   "test",
		}

		_, err := ecJWKToPublicKey(jwk)
		if err == nil {
			t.Error("Expected error for unsupported curve")
		}
	})

	t.Run("invalid x coordinate", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   "!!!invalid!!!",
			"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
		}

		_, err := ecJWKToPublicKey(jwk)
		if err == nil {
			t.Error("Expected error for invalid x coordinate")
		}
	})
}

func TestJwkToPublicKey(t *testing.T) {
	t.Run("unsupported key type", func(t *testing.T) {
		jwk := map[string]any{
			"kty": "unknown",
		}

		_, err := jwkToPublicKey(jwk)
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
	})

	t.Run("missing key type", func(t *testing.T) {
		jwk := map[string]any{}

		_, err := jwkToPublicKey(jwk)
		if err == nil {
			t.Error("Expected error for missing key type")
		}
	})
}

func makeTestJWTHeader(claims map[string]any) string {
	headerBytes, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(headerBytes)
}
