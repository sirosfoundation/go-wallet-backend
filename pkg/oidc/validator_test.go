package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap/zaptest"
)

// createTestRSAKey creates an RSA key pair for testing
func createTestRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Create JWK representation
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	return privateKey, fmt.Sprintf(`{"kty":"RSA","kid":"test-key","use":"sig","alg":"RS256","n":"%s","e":"%s"}`, n, e)
}

// createTestECDSAKey creates an ECDSA key pair for testing
func createTestECDSAKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Create JWK representation
	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	return privateKey, fmt.Sprintf(`{"kty":"EC","kid":"ec-key","use":"sig","alg":"ES256","crv":"P-256","x":"%s","y":"%s"}`, x, y)
}

// createTestToken creates a signed JWT token for testing
func createTestToken(t *testing.T, key interface{}, claims jwt.MapClaims, method jwt.SigningMethod, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return tokenString
}

// createTestJWKSServer creates a test server that serves JWKS
func createTestJWKSServer(t *testing.T, jwkJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			// Use http:// scheme for the test server's jwks_uri
			baseURL := "http://" + r.Host
			config := fmt.Sprintf(`{"issuer":"%s","jwks_uri":"%s/jwks"}`, "https://test-issuer.example.com", baseURL)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(config))
		case "/jwks":
			jwks := fmt.Sprintf(`{"keys":[%s]}`, jwkJSON)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(jwks))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestValidator_ValidateRSA(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestRSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	// Create validator
	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	// Create valid token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://test-issuer.example.com",
		"aud": "test-client",
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodRS256, "test-key")

	// Validate
	ctx := context.Background()
	result, err := v.Validate(ctx, tokenString)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if result.Subject != "user123" {
		t.Errorf("expected subject 'user123', got '%s'", result.Subject)
	}
	if result.Issuer != "https://test-issuer.example.com" {
		t.Errorf("expected issuer 'https://test-issuer.example.com', got '%s'", result.Issuer)
	}
}

func TestValidator_ValidateECDSA(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestECDSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	// Create validator
	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	// Create valid token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://test-issuer.example.com",
		"aud": "test-client",
		"sub": "user456",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodES256, "ec-key")

	// Validate
	ctx := context.Background()
	result, err := v.Validate(ctx, tokenString)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if result.Subject != "user456" {
		t.Errorf("expected subject 'user456', got '%s'", result.Subject)
	}
}

func TestValidator_ExpiredToken(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestRSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	// Create expired token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://test-issuer.example.com",
		"aud": "test-client",
		"sub": "user123",
		"exp": now.Add(-time.Hour).Unix(), // Expired 1 hour ago
		"iat": now.Add(-2 * time.Hour).Unix(),
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodRS256, "test-key")

	ctx := context.Background()
	_, err := v.Validate(ctx, tokenString)
	if err == nil {
		t.Fatal("expected validation error for expired token")
	}
}

func TestValidator_WrongIssuer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestRSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	// Create token with wrong issuer
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://wrong-issuer.example.com",
		"aud": "test-client",
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodRS256, "test-key")

	ctx := context.Background()
	_, err := v.Validate(ctx, tokenString)
	if err == nil {
		t.Fatal("expected validation error for wrong issuer")
	}
}

func TestValidator_WrongAudience(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestRSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	// Create token with wrong audience
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://test-issuer.example.com",
		"aud": "wrong-client",
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodRS256, "test-key")

	ctx := context.Background()
	_, err := v.Validate(ctx, tokenString)
	if err == nil {
		t.Fatal("expected validation error for wrong audience")
	}
}

func TestValidator_MissingSubject(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestRSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	// Create token without subject
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://test-issuer.example.com",
		"aud": "test-client",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodRS256, "test-key")

	ctx := context.Background()
	_, err := v.Validate(ctx, tokenString)
	if err == nil {
		t.Fatal("expected validation error for missing subject")
	}
}

func TestValidator_InvalidToken(t *testing.T) {
	logger := zaptest.NewLogger(t)
	_, jwkJSON := createTestRSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	ctx := context.Background()

	// Test invalid token formats
	invalidTokens := []string{
		"",
		"not-a-jwt",
		"header.payload.signature",
		"eyJhbGciOiJSUzI1NiJ9.invalid.invalid",
	}

	for _, token := range invalidTokens {
		_, err := v.Validate(ctx, token)
		if err == nil {
			t.Errorf("expected validation error for invalid token: %s", token)
		}
	}
}

func TestValidator_MultipleAudiences(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestRSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	// Create token with multiple audiences
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": "https://test-issuer.example.com",
		"aud": []string{"other-client", "test-client"}, // test-client is in the list
		"sub": "user123",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodRS256, "test-key")

	ctx := context.Background()
	result, err := v.Validate(ctx, tokenString)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if result.Subject != "user123" {
		t.Errorf("expected subject 'user123', got '%s'", result.Subject)
	}
}

func TestValidator_CustomClaims(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestRSAKey(t)

	server := createTestJWKSServer(t, jwkJSON)
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:   "https://test-issuer.example.com",
		Audience: "test-client",
		JWKSURI:  server.URL + "/jwks",
	}, nil, logger)

	// Create token with custom claims
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":          "https://test-issuer.example.com",
		"aud":          "test-client",
		"sub":          "user123",
		"exp":          now.Add(time.Hour).Unix(),
		"iat":          now.Unix(),
		"email":        "user@example.com",
		"groups":       []string{"admin", "users"},
		"custom_claim": "custom_value",
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodRS256, "test-key")

	ctx := context.Background()
	result, err := v.Validate(ctx, tokenString)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	// Check custom claims are available
	if email, ok := result.Claims["email"].(string); !ok || email != "user@example.com" {
		t.Error("expected email claim to be present")
	}

	if customVal, ok := result.Claims["custom_claim"].(string); !ok || customVal != "custom_value" {
		t.Error("expected custom_claim to be present")
	}
}

func TestDiscoverProvider(t *testing.T) {
	// Test OIDC discovery
	_, jwkJSON := createTestRSAKey(t)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]string{
				"issuer":   "https://test-issuer.example.com",
				"jwks_uri": server.URL + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)
		} else if r.URL.Path == "/jwks" {
			jwks := fmt.Sprintf(`{"keys":[%s]}`, jwkJSON)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(jwks))
		}
	}))
	defer server.Close()

	ctx := context.Background()
	discovery, err := DiscoverProvider(ctx, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to discover provider: %v", err)
	}

	if discovery.Issuer != "https://test-issuer.example.com" {
		t.Errorf("expected issuer 'https://test-issuer.example.com', got '%s'", discovery.Issuer)
	}

	if discovery.JWKSURI != server.URL+"/jwks" {
		t.Errorf("unexpected JWKS URI: %s", discovery.JWKSURI)
	}
}
