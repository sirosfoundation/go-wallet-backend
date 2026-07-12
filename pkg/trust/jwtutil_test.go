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

func TestExtractTrustChainFromJWT(t *testing.T) {
	makeJWT := func(header map[string]any) string {
		headerStr := makeTestJWTHeader(header)
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"test"}`))
		return headerStr + "." + payload + ".fakesig"
	}

	t.Run("JWT with trust_chain", func(t *testing.T) {
		jwt := makeJWT(map[string]any{
			"alg":         "ES256",
			"trust_chain": []string{"eyJleaf...", "eyJintermediate...", "eyJanchor..."},
		})
		chain := ExtractTrustChainFromJWT(jwt)
		if len(chain) != 3 {
			t.Fatalf("expected 3 elements, got %d", len(chain))
		}
		if chain[0] != "eyJleaf..." {
			t.Errorf("expected first element eyJleaf..., got %s", chain[0])
		}
	})

	t.Run("JWT without trust_chain", func(t *testing.T) {
		jwt := makeJWT(map[string]any{"alg": "ES256"})
		chain := ExtractTrustChainFromJWT(jwt)
		if chain != nil {
			t.Errorf("expected nil, got %v", chain)
		}
	})

	t.Run("JWT with empty trust_chain", func(t *testing.T) {
		jwt := makeJWT(map[string]any{"alg": "ES256", "trust_chain": []string{}})
		chain := ExtractTrustChainFromJWT(jwt)
		if chain != nil {
			t.Errorf("expected nil for empty chain, got %v", chain)
		}
	})

	t.Run("invalid JWT", func(t *testing.T) {
		chain := ExtractTrustChainFromJWT("not-a-jwt")
		if chain != nil {
			t.Errorf("expected nil, got %v", chain)
		}
	})
}

func TestVerifyJWTWithResolvedKeys(t *testing.T) {
	// Generate test keys
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	makeJWK := func(k *ecdsa.PublicKey, kid string) map[string]interface{} {
		jwk := map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
		}
		if kid != "" {
			jwk["kid"] = kid
		}
		return jwk
	}

	signJWT := func(key *ecdsa.PrivateKey, kid string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "test"})
		if kid != "" {
			token.Header["kid"] = kid
		}
		tokenStr, _ := token.SignedString(key)
		return tokenStr
	}

	t.Run("matching key without kid", func(t *testing.T) {
		tokenStr := signJWT(key1, "")
		keys := []interface{}{makeJWK(&key1.PublicKey, "")}

		matched, err := VerifyJWTWithResolvedKeys(tokenStr, keys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if matched == nil {
			t.Fatal("expected matched key, got nil")
		}
	})

	t.Run("matching key with kid", func(t *testing.T) {
		tokenStr := signJWT(key1, "key-1")
		keys := []interface{}{
			makeJWK(&key2.PublicKey, "key-2"),
			makeJWK(&key1.PublicKey, "key-1"),
		}

		matched, err := VerifyJWTWithResolvedKeys(tokenStr, keys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if kid, _ := matched["kid"].(string); kid != "key-1" {
			t.Errorf("expected kid=key-1, got %s", kid)
		}
	})

	t.Run("second key matches (no kid)", func(t *testing.T) {
		tokenStr := signJWT(key2, "")
		keys := []interface{}{
			makeJWK(&key1.PublicKey, ""),
			makeJWK(&key2.PublicKey, ""),
		}

		_, err := VerifyJWTWithResolvedKeys(tokenStr, keys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no matching key", func(t *testing.T) {
		tokenStr := signJWT(key1, "")
		keys := []interface{}{makeJWK(&key2.PublicKey, "")}

		_, err := VerifyJWTWithResolvedKeys(tokenStr, keys)
		if err == nil {
			t.Error("expected error for non-matching key")
		}
	})

	t.Run("empty keys", func(t *testing.T) {
		tokenStr := signJWT(key1, "")
		_, err := VerifyJWTWithResolvedKeys(tokenStr, nil)
		if err == nil {
			t.Error("expected error for empty keys")
		}
	})

	t.Run("invalid JWT", func(t *testing.T) {
		_, err := VerifyJWTWithResolvedKeys("not.a.jwt", []interface{}{makeJWK(&key1.PublicKey, "")})
		if err == nil {
			t.Error("expected error for invalid JWT")
		}
	})
}

func TestExtractKeysFromTrustMetadata(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		keys := extractKeysFromTrustMetadata(nil)
		if keys != nil {
			t.Errorf("expected nil, got %v", keys)
		}
	})

	t.Run("DID document with verification methods", func(t *testing.T) {
		metadata := map[string]interface{}{
			"id": "did:web:example.com",
			"verificationMethod": []interface{}{
				map[string]interface{}{
					"id":         "did:web:example.com#key-1",
					"type":       "JsonWebKey2020",
					"controller": "did:web:example.com",
					"publicKeyJwk": map[string]interface{}{
						"kty": "EC",
						"crv": "P-256",
						"x":   "test-x",
						"y":   "test-y",
					},
				},
			},
		}

		keys := extractKeysFromTrustMetadata(metadata)
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}

		jwk, ok := keys[0].(map[string]interface{})
		if !ok {
			t.Fatal("expected map[string]interface{}")
		}
		if jwk["kid"] != "did:web:example.com#key-1" {
			t.Errorf("expected kid from verification method id, got %v", jwk["kid"])
		}
	})

	t.Run("DID document without verification methods", func(t *testing.T) {
		metadata := map[string]interface{}{
			"id": "did:web:example.com",
		}
		keys := extractKeysFromTrustMetadata(metadata)
		if keys != nil {
			t.Errorf("expected nil, got %v", keys)
		}
	})

	t.Run("preserves existing kid on JWK", func(t *testing.T) {
		metadata := map[string]interface{}{
			"verificationMethod": []interface{}{
				map[string]interface{}{
					"id": "did:web:example.com#key-1",
					"publicKeyJwk": map[string]interface{}{
						"kty": "EC",
						"kid": "existing-kid",
					},
				},
			},
		}

		keys := extractKeysFromTrustMetadata(metadata)
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		jwk := keys[0].(map[string]interface{})
		if jwk["kid"] != "existing-kid" {
			t.Errorf("expected existing-kid preserved, got %v", jwk["kid"])
		}
	})
}

func TestExtractVerifierAttestation(t *testing.T) {
	// Generate keys: one for the verifier, one for the attestation issuer
	verifierKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate verifier key: %v", err)
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate issuer key: %v", err)
	}

	verifierJWK := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(verifierKey.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(verifierKey.PublicKey.Y.Bytes()),
	}

	// Create attestation JWT signed by issuer
	makeAttestationJWT := func(iss, sub string, cnfJWK map[string]interface{}) string {
		issuerJWK := map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(issuerKey.PublicKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(issuerKey.PublicKey.Y.Bytes()),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": iss,
			"sub": sub,
			"exp": float64(9999999999),
			"cnf": map[string]interface{}{"jwk": cnfJWK},
		})
		token.Header["typ"] = "verifier-attestation+jwt"
		token.Header["jwk"] = issuerJWK
		tokenStr, _ := token.SignedString(issuerKey)
		return tokenStr
	}

	// Create request JWT signed by verifier, with attestation in "jwt" header
	makeRequestJWT := func(attestationJWT string) string {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"client_id":     "verifier_attestation:verifier.example",
			"response_type": "vp_token",
		})
		token.Header["jwt"] = attestationJWT
		tokenStr, _ := token.SignedString(verifierKey)
		return tokenStr
	}

	t.Run("valid attestation", func(t *testing.T) {
		attestJWT := makeAttestationJWT("https://trust-framework.example", "verifier.example", verifierJWK)
		reqJWT := makeRequestJWT(attestJWT)

		att, err := ExtractVerifierAttestation(reqJWT)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if att == nil {
			t.Fatal("expected attestation, got nil")
		}
		if att.Issuer != "https://trust-framework.example" {
			t.Errorf("expected issuer https://trust-framework.example, got %s", att.Issuer)
		}
		if att.Subject != "verifier.example" {
			t.Errorf("expected subject verifier.example, got %s", att.Subject)
		}
		if att.AttestationKeyMaterial == nil || att.AttestationKeyMaterial.Type != "jwk" {
			t.Error("expected attestation key material with type jwk")
		}
	})

	t.Run("no jwt header", func(t *testing.T) {
		// Request JWT without "jwt" header
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "test"})
		tokenStr, _ := token.SignedString(verifierKey)

		att, err := ExtractVerifierAttestation(tokenStr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if att != nil {
			t.Error("expected nil attestation when no jwt header")
		}
	})

	t.Run("signature mismatch", func(t *testing.T) {
		// Attestation cnf points to a different key than what signed the request
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherJWK := map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(otherKey.PublicKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(otherKey.PublicKey.Y.Bytes()),
		}
		attestJWT := makeAttestationJWT("https://issuer.example", "verifier.example", otherJWK)
		reqJWT := makeRequestJWT(attestJWT)

		_, err := ExtractVerifierAttestation(reqJWT)
		if err == nil {
			t.Error("expected error for signature mismatch")
		}
	})

	t.Run("missing cnf claim", func(t *testing.T) {
		// Create attestation without cnf
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": "https://issuer.example",
			"sub": "verifier.example",
		})
		token.Header["typ"] = "verifier-attestation+jwt"
		attestStr, _ := token.SignedString(issuerKey)

		reqToken := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "test"})
		reqToken.Header["jwt"] = attestStr
		reqStr, _ := reqToken.SignedString(verifierKey)

		_, err := ExtractVerifierAttestation(reqStr)
		if err == nil {
			t.Error("expected error for missing cnf")
		}
	})
}
