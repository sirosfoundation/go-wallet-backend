package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

func newTestWIAService(t *testing.T) (*WIAService, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate test signing key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed cert for x5c
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	certB64 := base64.StdEncoding.EncodeToString(certDER)

	cfg := &config.Config{}
	cfg.WalletProvider.WIA = config.WIAConfig{
		Enabled:             true,
		WalletName:          "Test Wallet",
		WalletVersion:       "1.0.0",
		WalletLink:          "https://example.com",
		MaxExpirySeconds:    86400,
		ChallengeTTLSeconds: 300,
	}
	cfg.WalletProvider.Attestation = config.AttestationConfig{
		LifetimeSeconds: 3600,
		StatusListMode:  "never",
	}

	logger := zap.NewNop()
	jwtSigner, err := signing.NewCryptoSignerES256(privKey)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewWIAService(cfg, logger, jwtSigner, []string{certB64})

	return svc, privKey
}

// createTestPop creates a WIA-PoP JWT for testing.
func createTestPop(t *testing.T, nonce string) (string, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate instance key
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Build JWK for the public key
	xBytes := instanceKey.PublicKey.X.Bytes()
	yBytes := instanceKey.PublicKey.Y.Bytes()
	// Pad to 32 bytes for P-256
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

	claims := &WIAPopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "urn:wallet:instance:test-123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: nonce,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-client-attestation-pop+jwt"
	token.Header["jwk"] = jwk

	popStr, err := token.SignedString(instanceKey)
	if err != nil {
		t.Fatal(err)
	}

	return popStr, instanceKey
}

func TestWIAService_CreateChallenge(t *testing.T) {
	svc, _ := newTestWIAService(t)

	challenge, expiresAt, err := svc.CreateChallenge(context.Background())
	if err != nil {
		t.Fatalf("CreateChallenge failed: %v", err)
	}

	if challenge == "" {
		t.Fatal("challenge should not be empty")
	}
	if expiresAt.Before(time.Now()) {
		t.Fatal("expiresAt should be in the future")
	}
}

func TestWIAService_GenerateWIA_Success(t *testing.T) {
	svc, _ := newTestWIAService(t)

	// Create challenge
	challenge, _, err := svc.CreateChallenge(context.Background())
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	// Create PoP with the challenge nonce
	pop, _ := createTestPop(t, challenge)

	// Generate WIA
	wiaJWT, err := svc.GenerateWIA(context.Background(), &WIARequest{
		Pop:       pop,
		Challenge: challenge,
	})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	if wiaJWT == "" {
		t.Fatal("WIA JWT should not be empty")
	}

	// Parse and validate WIA
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wiaJWT, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Parse WIA: %v", err)
	}

	// Check typ
	if token.Header["typ"] != "oauth-client-attestation+jwt" {
		t.Errorf("typ = %v, want oauth-client-attestation+jwt", token.Header["typ"])
	}

	// Check x5c present
	if token.Header["x5c"] == nil {
		t.Error("x5c header missing")
	}

	// Check claims
	claims := token.Claims.(jwt.MapClaims)
	if claims["wallet_name"] != "Test Wallet" {
		t.Errorf("wallet_name = %v, want Test Wallet", claims["wallet_name"])
	}
	if claims["wallet_version"] != "1.0.0" {
		t.Errorf("wallet_version = %v, want 1.0.0", claims["wallet_version"])
	}
	if claims["attestation_source"] != "backend_attested" {
		t.Errorf("attestation_source = %v, want backend_attested", claims["attestation_source"])
	}

	// Check cnf
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		t.Fatal("cnf claim missing or not an object")
	}
	if cnf["jwk"] == nil {
		t.Error("cnf.jwk missing")
	}
	if cnf["jkt"] == nil {
		t.Error("cnf.jkt missing")
	}

	// No iss per EC TS03 §2.2.1
	if claims["iss"] != nil {
		t.Error("WIA should not have iss claim (identity from x5c)")
	}
}

func TestWIAService_ChallengeIsSingleUse(t *testing.T) {
	svc, _ := newTestWIAService(t)

	challenge, _, err := svc.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	pop, _ := createTestPop(t, challenge)

	// First use should succeed
	_, err = svc.GenerateWIA(context.Background(), &WIARequest{
		Pop:       pop,
		Challenge: challenge,
	})
	if err != nil {
		t.Fatalf("first GenerateWIA: %v", err)
	}

	// Second use should fail (single-use)
	pop2, _ := createTestPop(t, challenge)
	_, err = svc.GenerateWIA(context.Background(), &WIARequest{
		Pop:       pop2,
		Challenge: challenge,
	})
	if err == nil {
		t.Fatal("second GenerateWIA should fail (challenge consumed)")
	}
}

func TestWIAService_InvalidNonce(t *testing.T) {
	svc, _ := newTestWIAService(t)

	challenge, _, _ := svc.CreateChallenge(context.Background())

	// PoP with wrong nonce
	pop, _ := createTestPop(t, "wrong-nonce")

	_, err := svc.GenerateWIA(context.Background(), &WIARequest{
		Pop:       pop,
		Challenge: challenge,
	})
	if err == nil {
		t.Fatal("should fail with wrong nonce")
	}
}

func TestWIAService_ChallengeCapacityLimit(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.ChallengeTTLSeconds = 300

	// Fill up the challenge store
	for i := 0; i < maxChallenges; i++ {
		_, _, err := svc.CreateChallenge(context.Background())
		if err != nil {
			t.Fatalf("CreateChallenge(%d) failed: %v", i, err)
		}
	}

	// Next one should fail
	_, _, err := svc.CreateChallenge(context.Background())
	if err == nil {
		t.Fatal("should fail when capacity exceeded")
	}
}

func TestWIAService_ExpiredChallenge(t *testing.T) {
	svc, _ := newTestWIAService(t)

	// Set TTL to 1 second
	svc.cfg.WalletProvider.WIA.ChallengeTTLSeconds = 1

	challenge, _, _ := svc.CreateChallenge(context.Background())

	// Manually expire the challenge
	svc.mu.Lock()
	svc.challenges[challenge].ExpiresAt = time.Now().Add(-1 * time.Second)
	svc.mu.Unlock()

	pop, _ := createTestPop(t, challenge)

	_, err := svc.GenerateWIA(context.Background(), &WIARequest{
		Pop:       pop,
		Challenge: challenge,
	})
	if err == nil {
		t.Fatal("should fail with expired challenge")
	}
}

func TestComputeJKT(t *testing.T) {
	// Known test vector
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x-value",
		"y":   "test-y-value",
	}

	jkt, err := computeJKT(jwk)
	if err != nil {
		t.Fatal(err)
	}

	if jkt == "" {
		t.Fatal("JKT should not be empty")
	}

	// Verify deterministic
	jkt2, _ := computeJKT(jwk)
	if jkt != jkt2 {
		t.Fatal("JKT should be deterministic")
	}
}

func TestParseECPublicKeyFromJWK(t *testing.T) {
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

	parsed, err := parseECPublicKeyFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.X.Cmp(key.PublicKey.X) != 0 || parsed.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("parsed key doesn't match original")
	}
}
