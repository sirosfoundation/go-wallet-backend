package trust

import (
	"testing"
)

func TestNormalizeJWKS_Nil(t *testing.T) {
	result := NormalizeJWKS(nil)
	if result != nil {
		t.Errorf("NormalizeJWKS(nil) = %v, want nil", result)
	}
}

func TestNormalizeJWKS_SingleJWK(t *testing.T) {
	// A single JWK map (no "keys" wrapper)
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "test-y",
	}

	result := NormalizeJWKS(jwk)
	if len(result) != 1 {
		t.Fatalf("NormalizeJWKS(singleJWK) returned %d elements, want 1", len(result))
	}
	if _, ok := result[0].(map[string]interface{}); !ok {
		t.Errorf("result[0] type = %T, want map[string]interface{}", result[0])
	}
}

func TestNormalizeJWKS_JWKSWrapper(t *testing.T) {
	// A JWKS object with a "keys" array containing two JWKs
	jwks := map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "key1-x",
				"y":   "key1-y",
				"kid": "key1",
			},
			map[string]interface{}{
				"kty": "RSA",
				"n":   "test-n",
				"e":   "AQAB",
				"kid": "key2",
			},
		},
	}

	result := NormalizeJWKS(jwks)
	if len(result) != 2 {
		t.Fatalf("NormalizeJWKS(jwks) returned %d elements, want 2", len(result))
	}

	// Verify first key
	key1, ok := result[0].(map[string]interface{})
	if !ok {
		t.Fatalf("result[0] type = %T, want map[string]interface{}", result[0])
	}
	if key1["kid"] != "key1" {
		t.Errorf("result[0].kid = %v, want key1", key1["kid"])
	}

	// Verify second key
	key2, ok := result[1].(map[string]interface{})
	if !ok {
		t.Fatalf("result[1] type = %T, want map[string]interface{}", result[1])
	}
	if key2["kid"] != "key2" {
		t.Errorf("result[1].kid = %v, want key2", key2["kid"])
	}
}

func TestNormalizeJWKS_EmptyKeysArray(t *testing.T) {
	// JWKS with empty keys array — treated as a single JWK (the map itself)
	jwks := map[string]interface{}{
		"keys": []interface{}{},
	}

	result := NormalizeJWKS(jwks)
	if len(result) != 1 {
		t.Fatalf("NormalizeJWKS(empty keys) returned %d elements, want 1", len(result))
	}
}

func TestNormalizeJWKS_AlreadyNormalized(t *testing.T) {
	// Already a []interface{} of JWK maps
	keys := []interface{}{
		map[string]interface{}{"kty": "EC", "kid": "a"},
		map[string]interface{}{"kty": "RSA", "kid": "b"},
	}

	result := NormalizeJWKS(keys)
	if len(result) != 2 {
		t.Fatalf("NormalizeJWKS([]interface{}) returned %d elements, want 2", len(result))
	}
}

func TestNormalizeJWKS_UnknownType(t *testing.T) {
	// Unknown type — wrapped as single element
	result := NormalizeJWKS("some-string")
	if len(result) != 1 {
		t.Fatalf("NormalizeJWKS(string) returned %d elements, want 1", len(result))
	}
}

func TestKeyMaterial_CredentialType(t *testing.T) {
	km := &KeyMaterial{
		Type:           "jwk",
		JWK:            map[string]interface{}{"kty": "EC"},
		CredentialType: "urn:eu.europa.ec.eudi:pid:1",
	}

	if km.CredentialType != "urn:eu.europa.ec.eudi:pid:1" {
		t.Errorf("CredentialType = %v, want urn:eu.europa.ec.eudi:pid:1", km.CredentialType)
	}
}
