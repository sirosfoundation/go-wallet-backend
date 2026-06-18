package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
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
	svc.challenges.mu.Lock()
	svc.challenges.items[challenge].ExpiresAt = time.Now().Add(-1 * time.Second)
	svc.challenges.mu.Unlock()

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

func TestEllipticCurveForName(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ellipticCurveForName(tt.name)
			if got != tt.curve {
				t.Errorf("ellipticCurveForName(%q) mismatch", tt.name)
			}
		})
	}
	// Unsupported curves should return nil
	for _, name := range []string{"P-384", "P-521", "unsupported"} {
		if c := ellipticCurveForName(name); c != nil {
			t.Errorf("expected nil for %q curve", name)
		}
	}
}

func TestChallengeStoreLen(t *testing.T) {
	svc, _ := newTestWIAService(t)

	if svc.challenges.len() != 0 {
		t.Errorf("initial len = %d, want 0", svc.challenges.len())
	}

	// Create a challenge
	ctx := context.Background()
	_, _, err := svc.CreateChallenge(ctx)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if svc.challenges.len() != 1 {
		t.Errorf("after create len = %d, want 1", svc.challenges.len())
	}
}

func TestCleanupExpiredChallenges(t *testing.T) {
	svc, _ := newTestWIAService(t)

	// Insert a challenge, then immediately clean up (shouldn't remove it since it's not expired)
	ctx := context.Background()
	_, _, err := svc.CreateChallenge(ctx)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	svc.CleanupExpiredChallenges()
	if svc.challenges.len() != 1 {
		t.Errorf("non-expired challenge removed; len = %d", svc.challenges.len())
	}
}

func TestWIAChallenge_Success(t *testing.T) {
	svc, _ := newTestWIAService(t)

	ctx := context.Background()
	challenge, expiresAt, err := svc.CreateChallenge(ctx)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if challenge == "" {
		t.Error("challenge is empty")
	}
	if expiresAt.Before(time.Now()) {
		t.Error("expiresAt is in the past")
	}
}

func TestWIAIsSupported(t *testing.T) {
	svc, _ := newTestWIAService(t)
	if !svc.IsSupported() {
		t.Error("IsSupported() = false, want true")
	}
}

func TestWIAGenerateEndToEnd(t *testing.T) {
	svc, privKey := newTestWIAService(t)
	ctx := context.Background()

	// 1) Create challenge
	challenge, _, err := svc.CreateChallenge(ctx)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	// 2) Build a valid PoP JWT signed by a fresh key
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	xBytes := walletKey.PublicKey.X.Bytes()
	yBytes := walletKey.PublicKey.Y.Bytes()
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

	popToken := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":   "test-wallet-instance",
		"aud":   svc.cfg.WalletProvider.WIA.WalletName,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"nonce": challenge,
	})
	popToken.Header["typ"] = "oauth-client-attestation-pop+jwt"
	popToken.Header["jwk"] = jwk
	popString, err := popToken.SignedString(walletKey)
	if err != nil {
		t.Fatalf("sign PoP: %v", err)
	}

	// 3) Generate WIA
	wia, err := svc.GenerateWIA(ctx, &WIARequest{
		Pop:       popString,
		Challenge: challenge,
	})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}
	if wia == "" {
		t.Fatal("WIA is empty")
	}

	// 4) Parse and verify the WIA JWT
	parsed, err := jwt.Parse(wia, func(token *jwt.Token) (interface{}, error) {
		return &privKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		t.Fatalf("parse WIA: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("WIA token is invalid")
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if claims["cnf"] == nil {
		t.Error("WIA missing cnf claim")
	}
}

func TestWIAGenerateDuplicateChallenge(t *testing.T) {
	svc, _ := newTestWIAService(t)
	ctx := context.Background()

	challenge, _, err := svc.CreateChallenge(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// First consume should succeed (via internal consume)
	_, ok := svc.challenges.consume(challenge)
	if !ok {
		t.Fatal("first consume should succeed")
	}

	// Second consume should fail
	_, ok = svc.challenges.consume(challenge)
	if ok {
		t.Fatal("expected failure on second consume")
	}
}

func TestParseECPublicKeyFromJWK_InvalidCurve(t *testing.T) {
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-999",
		"x":   base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		"y":   base64.RawURLEncoding.EncodeToString([]byte{4, 5, 6}),
	}
	_, err := parseECPublicKeyFromJWK(jwk)
	if err == nil {
		t.Error("expected error for unsupported curve")
	}
}

func TestParseECPublicKeyFromJWK_MissingFields(t *testing.T) {
	// Missing x
	_, err := parseECPublicKeyFromJWK(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"y":   "AAAA",
	})
	if err == nil {
		t.Error("expected error for missing x")
	}

	// Missing crv
	_, err = parseECPublicKeyFromJWK(map[string]interface{}{
		"kty": "EC",
		"x":   "AAAA",
		"y":   "BBBB",
	})
	if err == nil {
		t.Error("expected error for missing crv")
	}
}

// testPopBuilder builds customized WIA-PoP JWTs for negative test paths.
type testPopBuilder struct {
	t          *testing.T
	key        *ecdsa.PrivateKey
	jwk        map[string]interface{}
	claims     *WIAPopClaims
	typ        string
	includeJWK bool
}

func newTestPopBuilder(t *testing.T, nonce string) *testPopBuilder {
	t.Helper()
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
	return &testPopBuilder{
		t:   t,
		key: key,
		jwk: map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(xBytes),
			"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		},
		claims: &WIAPopClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "urn:wallet:instance:test-123",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Nonce: nonce,
		},
		typ:        "oauth-client-attestation-pop+jwt",
		includeJWK: true,
	}
}

func (b *testPopBuilder) withTyp(typ string) *testPopBuilder { b.typ = typ; return b }
func (b *testPopBuilder) withoutJWK() *testPopBuilder        { b.includeJWK = false; return b }
func (b *testPopBuilder) withoutIssuer() *testPopBuilder     { b.claims.Issuer = ""; return b }
func (b *testPopBuilder) withoutIssuedAt() *testPopBuilder   { b.claims.IssuedAt = nil; return b }
func (b *testPopBuilder) withoutExpiresAt() *testPopBuilder  { b.claims.ExpiresAt = nil; return b }
func (b *testPopBuilder) withAudience(aud ...string) *testPopBuilder {
	b.claims.Audience = aud
	return b
}
func (b *testPopBuilder) withIssuedAt(t time.Time) *testPopBuilder {
	b.claims.IssuedAt = jwt.NewNumericDate(t)
	return b
}
func (b *testPopBuilder) withExpiresAt(t time.Time) *testPopBuilder {
	b.claims.ExpiresAt = jwt.NewNumericDate(t)
	return b
}

func (b *testPopBuilder) build() string {
	b.t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, b.claims)
	token.Header["typ"] = b.typ
	if b.includeJWK {
		token.Header["jwk"] = b.jwk
	}
	s, err := token.SignedString(b.key)
	if err != nil {
		b.t.Fatal(err)
	}
	return s
}

func TestValidatePop_MissingIat(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	pop := newTestPopBuilder(t, challenge).withoutIssuedAt().build()
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for missing iat")
	}
	if !errors.Is(err, ErrWIAPopInvalid) {
		t.Errorf("expected ErrWIAPopInvalid, got %v", err)
	}
}

func TestValidatePop_IatTooOld(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	pop := newTestPopBuilder(t, challenge).withIssuedAt(time.Now().Add(-15 * time.Minute)).build()
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for old iat")
	}
}

func TestValidatePop_ExpTooFarFuture(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	pop := newTestPopBuilder(t, challenge).withExpiresAt(time.Now().Add(30 * time.Minute)).build()
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for exp too far in future")
	}
}

func TestValidatePop_MissingExp(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	pop := newTestPopBuilder(t, challenge).withoutExpiresAt().build()
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for missing exp")
	}
}

func TestValidatePop_MissingIssuer(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	pop := newTestPopBuilder(t, challenge).withoutIssuer().build()
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestValidatePop_InvalidTyp(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	pop := newTestPopBuilder(t, challenge).withTyp("wrong-typ").build()
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for wrong typ")
	}
}

func TestValidatePop_MissingJWK(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	pop := newTestPopBuilder(t, challenge).withoutJWK().build()
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for missing jwk header")
	}
}

func TestValidatePop_AudValidation(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.WalletProviderURI = "https://wallet.example.com"

	t.Run("missing aud when required", func(t *testing.T) {
		challenge, _, _ := svc.CreateChallenge(context.Background())
		pop := newTestPopBuilder(t, challenge).build() // no aud set
		_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
		if err == nil {
			t.Fatal("expected error for missing aud")
		}
	})

	t.Run("wrong aud", func(t *testing.T) {
		challenge, _, _ := svc.CreateChallenge(context.Background())
		pop := newTestPopBuilder(t, challenge).withAudience("https://wrong.example.com").build()
		_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
		if err == nil {
			t.Fatal("expected error for wrong aud")
		}
	})

	t.Run("correct aud", func(t *testing.T) {
		challenge, _, _ := svc.CreateChallenge(context.Background())
		pop := newTestPopBuilder(t, challenge).withAudience("https://wallet.example.com").build()
		_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
		if err != nil {
			t.Fatalf("should succeed with correct aud: %v", err)
		}
	})

	t.Run("correct aud among multiple", func(t *testing.T) {
		challenge, _, _ := svc.CreateChallenge(context.Background())
		pop := newTestPopBuilder(t, challenge).withAudience("https://other.example.com", "https://wallet.example.com").build()
		_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
		if err != nil {
			t.Fatalf("should succeed with correct aud in list: %v", err)
		}
	})
}

func TestValidatePop_AudSkippedWhenNotConfigured(t *testing.T) {
	svc, _ := newTestWIAService(t)
	// WalletProviderURI not set — aud validation should be skipped

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop := newTestPopBuilder(t, challenge).build() // no aud
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("should succeed without aud when not configured: %v", err)
	}
}

func TestGenerateWIA_NotSupported(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.jwtSigner = nil // make unsupported

	_, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: "x", Challenge: "y"})
	if !errors.Is(err, ErrWIANotSupported) {
		t.Errorf("expected ErrWIANotSupported, got %v", err)
	}
}

func TestGenerateWIA_NativeAttestationFailure(t *testing.T) {
	svc, _ := newTestWIAService(t)
	// Enable native attestation with Apple config
	svc.cfg.WalletProvider.Attestation.NativeAttestation.Enabled = true
	svc.cfg.WalletProvider.Attestation.NativeAttestation.AppleAppID = "com.example.app"
	svc.nativeAttSvc = NewNativeAttestationService(svc.cfg, zap.NewNop())

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	// Native attestation with invalid token should fail (not silently fallback)
	_, err := svc.GenerateWIA(context.Background(), &WIARequest{
		Pop:       pop,
		Challenge: challenge,
		NativeAttestation: &NativeAttestationRequest{
			Type:      NativeAttestationAppleAppAttest,
			Challenge: challenge,
			Token:     "invalid-cbor-data",
			KeyID:     "test-key-id",
		},
	})
	if err == nil {
		t.Fatal("expected error when native attestation fails")
	}
}

func TestGenerateWIA_NativeAttestationChallengeMismatch(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.Attestation.NativeAttestation.Enabled = true
	svc.nativeAttSvc = NewNativeAttestationService(svc.cfg, zap.NewNop())

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	_, err := svc.GenerateWIA(context.Background(), &WIARequest{
		Pop:       pop,
		Challenge: challenge,
		NativeAttestation: &NativeAttestationRequest{
			Type:      NativeAttestationAppleAppAttest,
			Challenge: "different-challenge",
			Token:     "some-token",
			KeyID:     "test-key-id",
		},
	})
	if err == nil {
		t.Fatal("expected error for challenge mismatch")
	}
}

func TestSignWIA_EmptyWalletNameVersion(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.WalletName = ""
	svc.cfg.WalletProvider.WIA.WalletVersion = ""
	svc.cfg.WalletProvider.WIA.WalletLink = ""

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	// Parse and verify empty fields are omitted
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wia, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	if _, ok := claims["wallet_name"]; ok {
		t.Error("wallet_name should be omitted when empty")
	}
	if _, ok := claims["wallet_version"]; ok {
		t.Error("wallet_version should be omitted when empty")
	}
	if _, ok := claims["wallet_link"]; ok {
		t.Error("wallet_link should be omitted when empty")
	}
}

func TestSignWIA_StatusListAlways(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.Attestation.StatusListMode = "always"
	svc.cfg.WalletProvider.Attestation.StatusListURL = "https://status.example.com/list"

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(wia, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	status, ok := claims["status"].(map[string]interface{})
	if !ok {
		t.Fatal("status claim missing when StatusListMode=always")
	}
	sl, ok := status["status_list"].(map[string]interface{})
	if !ok {
		t.Fatal("status_list missing")
	}
	if sl["uri"] != "https://status.example.com/list" {
		t.Errorf("status_list.uri = %v", sl["uri"])
	}
}

func TestSignWIA_MaxExpiryDefault(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.MaxExpirySeconds = 0 // trigger default
	svc.cfg.WalletProvider.Attestation.LifetimeSeconds = 0

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(wia, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	lifetime := exp - iat
	// Should default to 24h = 86400s
	if lifetime != 86400 {
		t.Errorf("default lifetime = %d, want 86400", lifetime)
	}
}

func TestWIAService_StartStop(t *testing.T) {
	svc, _ := newTestWIAService(t)

	// Start the cleanup goroutine
	svc.Start()

	// Create a challenge and manually expire it
	challenge, _, _ := svc.CreateChallenge(context.Background())
	svc.challenges.mu.Lock()
	svc.challenges.items[challenge].ExpiresAt = time.Now().Add(-1 * time.Second)
	svc.challenges.mu.Unlock()

	// Manually trigger cleanup (the ticker will also do this, but we verify the method)
	svc.CleanupExpiredChallenges()
	if svc.challenges.len() != 0 {
		t.Errorf("expired challenge should be cleaned up, len = %d", svc.challenges.len())
	}

	// Stop should not panic
	svc.Stop()
}

func TestComputeJKT_UnsupportedKeyType(t *testing.T) {
	_, err := computeJKT(map[string]interface{}{
		"kty": "RSA",
		"n":   "test",
	})
	if err == nil {
		t.Error("expected error for RSA key type")
	}
}

func TestComputeJKT_IncompleteJWK(t *testing.T) {
	_, err := computeJKT(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		// missing x and y
	})
	if err == nil {
		t.Error("expected error for incomplete EC JWK")
	}
}

func TestParseECPublicKeyFromJWK_WrongKeyType(t *testing.T) {
	_, err := parseECPublicKeyFromJWK(map[string]interface{}{
		"kty": "RSA",
	})
	if err == nil {
		t.Error("expected error for RSA key type")
	}
}

func TestCreateChallenge_NotSupported(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.jwtSigner = nil

	_, _, err := svc.CreateChallenge(context.Background())
	if !errors.Is(err, ErrWIANotSupported) {
		t.Errorf("expected ErrWIANotSupported, got %v", err)
	}
}

func TestCreateChallenge_DefaultTTL(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.ChallengeTTLSeconds = 0 // trigger default 5min

	_, expiresAt, err := svc.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Should expire ~5min from now
	expected := time.Now().Add(5 * time.Minute)
	diff := expiresAt.Sub(expected)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("default TTL should be ~5min, got expiry diff %v", diff)
	}
}
