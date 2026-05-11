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
			// Build baseURL from r.Host and add the http scheme, since r.Host does
			// not include a scheme. The issuer field uses a fixed value for backward
			// compatibility with existing tests that validate against
			// https://test-issuer.example.com.
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

// discoveryTestServer wraps an httptest.Server with request counters
// for verifying that discovery and JWKS endpoints were actually called.
type discoveryTestServer struct {
	*httptest.Server
	DiscoveryHits int
	JWKSHits      int
}

// createTestJWKSServerWithDiscovery creates a test server that supports OIDC discovery.
// Unlike createTestJWKSServer, this server returns its own URL as the issuer,
// enabling tests that exercise the discovery-based JWKS path.
// Request counters are exposed via DiscoveryHits and JWKSHits for assertions.
func createTestJWKSServerWithDiscovery(t *testing.T, jwkJSON string) *discoveryTestServer {
	t.Helper()
	ds := &discoveryTestServer{}
	var serverURL string

	ds.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			ds.DiscoveryHits++
			// Use the actual server URL as issuer (self-referential)
			config := fmt.Sprintf(`{"issuer":"%s","jwks_uri":"%s/jwks"}`, serverURL, serverURL)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(config))
		case "/jwks":
			ds.JWKSHits++
			jwks := fmt.Sprintf(`{"keys":[%s]}`, jwkJSON)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(jwks))
		default:
			http.NotFound(w, r)
		}
	}))

	serverURL = ds.Server.URL
	return ds
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

// TestValidator_ValidateWithDiscovery tests token validation using discovery-based JWKS.
// This exercises the code path where JWKSURI is not configured and the validator
// must discover it from the issuer's openid-configuration endpoint.
// Covers issue #62: Add test for discovery-based JWKS path
func TestValidator_ValidateWithDiscovery(t *testing.T) {
	logger := zaptest.NewLogger(t)
	privateKey, jwkJSON := createTestRSAKey(t)

	// Use the discovery-aware test server
	server := createTestJWKSServerWithDiscovery(t, jwkJSON)
	defer server.Close()

	// Create validator WITHOUT explicit JWKSURI - this forces discovery
	v := NewValidator(ValidatorConfig{
		Issuer:   server.URL, // Use the test server URL as issuer
		Audience: "test-client",
		// JWKSURI intentionally left empty to trigger discovery path
	}, nil, logger)

	// Create valid token with issuer matching the test server
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": server.URL, // Must match ValidatorConfig.Issuer
		"aud": "test-client",
		"sub": "discovery-user",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	}

	tokenString := createTestToken(t, privateKey, claims, jwt.SigningMethodRS256, "test-key")

	// Validate - this should:
	// 1. See JWKSURI is empty
	// 2. Fetch /.well-known/openid-configuration from server.URL
	// 3. Extract jwks_uri from discovery document
	// 4. Fetch JWKS from that URI
	// 5. Validate the token
	ctx := context.Background()
	result, err := v.Validate(ctx, tokenString)
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	if result.Subject != "discovery-user" {
		t.Errorf("expected subject 'discovery-user', got '%s'", result.Subject)
	}

	if result.Issuer != server.URL {
		t.Errorf("expected issuer '%s', got '%s'", server.URL, result.Issuer)
	}

	// Verify the discovery and JWKS endpoints were actually called
	if server.DiscoveryHits == 0 {
		t.Error("expected at least one hit to /.well-known/openid-configuration, got 0")
	}
	if server.JWKSHits == 0 {
		t.Error("expected at least one hit to /jwks, got 0")
	}
}

// =============================================================================
// Retry and circuit breaker tests
// =============================================================================

// TestValidator_JWKS_RetryOnTransientFailure verifies that fetchJWKSWithRetry
// retries on transient (5xx) failures and succeeds when the IdP recovers.
func TestValidator_JWKS_RetryOnTransientFailure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	_, jwkJSON := createTestRSAKey(t)

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			// Fail the first two attempts with 503.
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, jwkJSON)
	}))
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:         "https://issuer.example.com",
		Audience:       "client-id",
		JWKSURI:        server.URL + "/jwks",
		JWKSMaxRetries: 3,
	}, server.Client(), logger)

	ctx := context.Background()
	jwks, err := v.fetchJWKSWithRetry(ctx, server.URL+"/jwks")
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestValidator_JWKS_NoRetryOn4xx verifies that 4xx errors are not retried.
func TestValidator_JWKS_NoRetryOn4xx(t *testing.T) {
	logger := zaptest.NewLogger(t)

	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:         "https://issuer.example.com",
		Audience:       "client-id",
		JWKSURI:        server.URL + "/jwks",
		JWKSMaxRetries: 3,
	}, server.Client(), logger)

	ctx := context.Background()
	_, err := v.fetchJWKSWithRetry(ctx, server.URL+"/jwks")
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if attempts != 1 {
		t.Errorf("expected exactly 1 attempt (no retry on 404), got %d", attempts)
	}
}

// TestValidator_JWKS_StaleCacheOnFailure verifies that a stale cached JWKS is
// returned when a fresh fetch fails and no circuit breaker is involved.
func TestValidator_JWKS_StaleCacheOnFailure(t *testing.T) {
	logger := zaptest.NewLogger(t)
	_, jwkJSON := createTestRSAKey(t)

	// First request succeeds; subsequent ones fail.
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"keys":[%s]}`, jwkJSON)
			return
		}
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	v := NewValidator(ValidatorConfig{
		Issuer:         "https://issuer.example.com",
		Audience:       "client-id",
		JWKSURI:        server.URL + "/jwks",
		JWKSCacheTTL:   1 * time.Millisecond, // expire almost immediately
		JWKSMaxRetries: 1,
	}, server.Client(), logger)

	ctx := context.Background()

	// Warm the cache.
	jwks1, err := v.getJWKS(ctx)
	if err != nil || len(jwks1.Keys) == 0 {
		t.Fatalf("initial JWKS fetch failed: %v", err)
	}

	// Let the cache expire.
	time.Sleep(5 * time.Millisecond)

	// Second call should fail the fetch but return stale cache.
	jwks2, err := v.getJWKS(ctx)
	if err != nil {
		t.Fatalf("expected stale cache fallback, got error: %v", err)
	}
	if len(jwks2.Keys) == 0 {
		t.Error("expected stale JWKS to be returned")
	}
}

// TestValidator_JWKS_CircuitBreaker verifies that the circuit opens after the
// threshold of consecutive failures and returns stale cache while open.
func TestValidator_JWKS_CircuitBreaker(t *testing.T) {
	logger := zaptest.NewLogger(t)
	_, jwkJSON := createTestRSAKey(t)

	alwaysFail := false
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if alwaysFail {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, jwkJSON)
	}))
	defer server.Close()

	const threshold = 3
	v := NewValidator(ValidatorConfig{
		Issuer:                      "https://issuer.example.com",
		Audience:                    "client-id",
		JWKSURI:                     server.URL + "/jwks",
		JWKSCacheTTL:                1 * time.Millisecond,
		JWKSMaxRetries:              1, // one attempt per getJWKS call
		JWKSCircuitBreakerThreshold: threshold,
		JWKSCircuitBreakerCooldown:  10 * time.Second, // long enough to stay open during test
	}, server.Client(), logger)

	ctx := context.Background()

	// Prime the cache.
	if _, err := v.getJWKS(ctx); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	// Switch IdP to always fail.
	alwaysFail = true
	time.Sleep(5 * time.Millisecond) // let cache expire

	requestsBefore := requestCount
	// Exhaust the threshold — each call tries the fetch, fails, increments counter.
	for i := 0; i < threshold; i++ {
		jwks, err := v.getJWKS(ctx)
		if err != nil {
			t.Fatalf("expected stale cache at failure %d, got error: %v", i+1, err)
		}
		if len(jwks.Keys) == 0 {
			t.Errorf("failure %d: expected stale JWKS", i+1)
		}
	}

	// Circuit should now be open — getJWKS must not make more HTTP requests.
	requestsMidway := requestCount
	jwks, err := v.getJWKS(ctx)
	if err != nil {
		t.Fatalf("expected stale cache while circuit open, got error: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Error("expected stale JWKS while circuit open")
	}
	if requestCount != requestsMidway {
		t.Errorf("circuit open: expected no new HTTP requests (had %d before, %d after)",
			requestsMidway, requestCount)
	}
	_ = requestsBefore
}

// TestValidator_JWKS_CircuitBreakerReset verifies the circuit closes after cooldown.
func TestValidator_JWKS_CircuitBreakerReset(t *testing.T) {
	logger := zaptest.NewLogger(t)
	_, jwkJSON := createTestRSAKey(t)

	alwaysFail := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if alwaysFail {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[%s]}`, jwkJSON)
	}))
	defer server.Close()

	const threshold = 2
	cooldown := 20 * time.Millisecond
	v := NewValidator(ValidatorConfig{
		Issuer:                      "https://issuer.example.com",
		Audience:                    "client-id",
		JWKSURI:                     server.URL + "/jwks",
		JWKSCacheTTL:                1 * time.Millisecond,
		JWKSMaxRetries:              1,
		JWKSCircuitBreakerThreshold: threshold,
		JWKSCircuitBreakerCooldown:  cooldown,
	}, server.Client(), logger)

	ctx := context.Background()

	// Prime cache.
	if _, err := v.getJWKS(ctx); err != nil {
		t.Fatalf("prime: %v", err)
	}

	alwaysFail = true
	time.Sleep(5 * time.Millisecond)

	// Trigger threshold failures to open circuit.
	for i := 0; i < threshold; i++ {
		v.getJWKS(ctx) //nolint:errcheck
	}

	// Verify circuit is open.
	v.jwksMu.RLock()
	open := !v.jwksCircuitOpen.IsZero()
	v.jwksMu.RUnlock()
	if !open {
		t.Fatal("expected circuit to be open")
	}

	// Wait for cooldown to elapse.
	time.Sleep(cooldown + 10*time.Millisecond)

	// IdP recovers.
	alwaysFail = false

	// After cooldown, a probe attempt should succeed and close the circuit.
	jwks, err := v.getJWKS(ctx)
	if err != nil {
		t.Fatalf("expected circuit reset to allow fetch: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Error("expected fresh JWKS after circuit reset")
	}

	v.jwksMu.RLock()
	failures := v.jwksFailures
	circuitOpen := v.jwksCircuitOpen
	v.jwksMu.RUnlock()
	if failures != 0 {
		t.Errorf("expected failure counter reset to 0, got %d", failures)
	}
	if !circuitOpen.IsZero() {
		t.Error("expected circuit to be closed after successful fetch")
	}
}
