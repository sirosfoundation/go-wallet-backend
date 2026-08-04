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

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
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
	svc := NewWIAService(cfg, logger, jwtSigner, []string{certB64}, nil, nil, nil)

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

	// Manually expire the challenge (test-only: access in-memory store directly)
	memStore := svc.challenges.(*memoryWIAChallengeStore)
	memStore.store.mu.Lock()
	memStore.store.items[challenge].ExpiresAt = time.Now().Add(-1 * time.Second)
	memStore.store.mu.Unlock()

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
	ctx := context.Background()

	n, _ := svc.challenges.Len(ctx)
	if n != 0 {
		t.Errorf("initial len = %d, want 0", n)
	}

	// Create a challenge
	_, _, err := svc.CreateChallenge(ctx)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	n, _ = svc.challenges.Len(ctx)
	if n != 1 {
		t.Errorf("after create len = %d, want 1", n)
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
	n, _ := svc.challenges.Len(ctx)
	if n != 1 {
		t.Errorf("non-expired challenge removed; len = %d", n)
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
	ok, _ := svc.challenges.Consume(ctx, challenge)
	if !ok {
		t.Fatal("first consume should succeed")
	}

	// Second consume should fail
	ok, _ = svc.challenges.Consume(ctx, challenge)
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

func TestSignWIA_CertificationInfo(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.CertificationInfo = map[string]interface{}{
		"scheme":          "EUCC",
		"assurance_level": "substantial",
	}

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(wia, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	certInfo, ok := claims["wallet_solution_certification_information"].(map[string]interface{})
	if !ok {
		t.Fatal("wallet_solution_certification_information claim missing")
	}
	if certInfo["scheme"] != "EUCC" {
		t.Errorf("scheme = %v, want EUCC", certInfo["scheme"])
	}
	if certInfo["assurance_level"] != "substantial" {
		t.Errorf("assurance_level = %v, want substantial", certInfo["assurance_level"])
	}
}

func TestSignWIA_CertificationInfoOmittedWhenEmpty(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.CertificationInfo = nil

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(wia, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	if _, ok := claims["wallet_solution_certification_information"]; ok {
		t.Error("wallet_solution_certification_information should be omitted when not configured")
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

	clientStatus, ok := claims["client_status"].(map[string]interface{})
	if !ok {
		t.Fatal("client_status claim missing when StatusListMode=always")
	}
	statusObj, ok := clientStatus["status"].(map[string]interface{})
	if !ok {
		t.Fatal("client_status.status missing")
	}
	sl, ok := statusObj["status_list"].(map[string]interface{})
	if !ok {
		t.Fatal("client_status.status.status_list missing")
	}
	if sl["uri"] != "https://status.example.com/list" {
		t.Errorf("status_list.uri = %v", sl["uri"])
	}
}

func TestSignWIA_StatusListAlwaysWithExpiry(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.Attestation.StatusListMode = "always"
	svc.cfg.WalletProvider.Attestation.StatusListURL = "https://status.example.com/list"
	svc.cfg.WalletProvider.Attestation.StatusListExpiry = 3600

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(wia, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	clientStatus, ok := claims["client_status"].(map[string]interface{})
	if !ok {
		t.Fatal("client_status claim missing")
	}
	if _, ok := clientStatus["exp"]; !ok {
		t.Error("client_status.exp should be present when StatusListExpiry > 0")
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
	memStore := svc.challenges.(*memoryWIAChallengeStore)
	memStore.store.mu.Lock()
	memStore.store.items[challenge].ExpiresAt = time.Now().Add(-1 * time.Second)
	memStore.store.mu.Unlock()

	// Manually trigger cleanup (the ticker will also do this, but we verify the method)
	svc.CleanupExpiredChallenges()
	n, _ := svc.challenges.Len(context.Background())
	if n != 0 {
		t.Errorf("expired challenge should be cleaned up, len = %d", n)
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

// TestWscdTypeFromAttestation covers all branches of wscdTypeFromAttestation,
// which maps an attestation_source string to the WSCD type recorded on the
// wallet instance.
func TestWscdTypeFromAttestation(t *testing.T) {
	tests := []struct {
		source string
		want   domain.WSCDType
	}{
		{"ios_app_attest", domain.WSCDTypeNativeIOS},
		{"android_play_integrity", domain.WSCDTypeNativeAndroid},
		{"backend_attested", domain.WSCDTypeWebCrypto},
		{"", domain.WSCDTypeWebCrypto},
		{"some_unrecognized_source", domain.WSCDTypeWebCrypto},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			if got := wscdTypeFromAttestation(tt.source); got != tt.want {
				t.Errorf("wscdTypeFromAttestation(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

// TestChallengeStore_RemoveMiddleNode exercises removeLocked with a node that
// has both a non-nil prev and a non-nil next, hitting the link-repair branches
// on both sides in a single call (existing tests only ever remove the sole
// remaining item, where both prev and next are nil).
func TestChallengeStore_RemoveMiddleNode(t *testing.T) {
	cs := newChallengeStore(10)
	base := time.Now().Add(time.Hour)

	c1 := &WIAChallenge{Challenge: "c1", ExpiresAt: base}
	c2 := &WIAChallenge{Challenge: "c2", ExpiresAt: base.Add(time.Second)}
	c3 := &WIAChallenge{Challenge: "c3", ExpiresAt: base.Add(2 * time.Second)}

	if !cs.put(c1) || !cs.put(c2) || !cs.put(c3) {
		t.Fatal("put failed")
	}

	got, ok := cs.consume("c2")
	if !ok || got == nil {
		t.Fatal("expected to consume middle challenge")
	}

	if n := cs.len(); n != 2 {
		t.Fatalf("len = %d, want 2", n)
	}
	if cs.head != c1 || cs.tail != c3 {
		t.Fatal("head/tail not as expected after middle removal")
	}
	if c1.next != c3 || c3.prev != c1 {
		t.Fatal("linked list not repaired around removed middle node")
	}
}

// TestNewWIAService_WiresNativeAttestation covers the constructor branch that
// wires up the native attestation service when configured.
func TestNewWIAService_WiresNativeAttestation(t *testing.T) {
	cfg := &config.Config{}
	cfg.WalletProvider.Attestation.NativeAttestation.Enabled = true

	svc := NewWIAService(cfg, zap.NewNop(), nil, nil, nil, nil, nil)
	if svc.nativeAttSvc == nil {
		t.Fatal("expected nativeAttSvc to be wired when NativeAttestation.Enabled=true")
	}
}

// fakeChallengeStore is a configurable WIAChallengeStore used to exercise
// store-error paths in CreateChallenge/consumeChallenge that the real
// in-memory store can't easily produce.
type fakeChallengeStore struct {
	putOK      bool
	putErr     error
	consumeOK  bool
	consumeErr error
	lenVal     int
	lenErr     error
}

func (f *fakeChallengeStore) Put(_ context.Context, _ string, _ time.Time) (bool, error) {
	return f.putOK, f.putErr
}

func (f *fakeChallengeStore) Consume(_ context.Context, _ string) (bool, error) {
	return f.consumeOK, f.consumeErr
}

func (f *fakeChallengeStore) Len(_ context.Context) (int, error) {
	return f.lenVal, f.lenErr
}

func TestCreateChallenge_StoreError(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.challenges = &fakeChallengeStore{putErr: errors.New("store unavailable")}

	_, _, err := svc.CreateChallenge(context.Background())
	if err == nil {
		t.Fatal("expected error when challenge store Put fails")
	}
	if errors.Is(err, ErrWIAChallengeCapacityMax) {
		t.Error("a store error should not be reported as capacity exceeded")
	}
}

func TestConsumeChallenge_StoreError(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.challenges = &fakeChallengeStore{consumeErr: errors.New("store unavailable")}

	err := svc.consumeChallenge(context.Background(), "any-challenge")
	if err == nil {
		t.Fatal("expected error when challenge store Consume fails")
	}
	if errors.Is(err, ErrWIAChallengeExpired) {
		t.Error("a store error should not be reported as an expired challenge")
	}
}

// ecJWKFromKey builds a JWK map for the public half of an ECDSA P-256 key,
// zero-padding x/y to 32 bytes as a compliant encoder would.
func ecJWKFromKey(pub *ecdsa.PublicKey) map[string]interface{} {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

func TestValidatePop_UnparseableJWT(t *testing.T) {
	svc, _ := newTestWIAService(t)

	_, err := svc.validatePop("this-is-not-a-jwt", "challenge")
	if err == nil {
		t.Fatal("expected error for a pop that isn't a parseable JWT")
	}
}

func TestValidatePop_JWKHeaderNotObject(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := &WIAPopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "urn:wallet:instance:test",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: challenge,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-client-attestation-pop+jwt"
	token.Header["jwk"] = "not-an-object" // present but not a JSON object
	pop, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.validatePop(pop, challenge)
	if err == nil {
		t.Fatal("expected error when jwk header is not a JSON object")
	}
}

func TestValidatePop_EmbeddedJWKFailsToParse(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	b := newTestPopBuilder(t, challenge)
	b.jwk["crv"] = "P-384" // unsupported curve; parseECPublicKeyFromJWK will reject it
	pop := b.build()

	_, err := svc.validatePop(pop, challenge)
	if err == nil {
		t.Fatal("expected error when the embedded JWK fails to parse")
	}
}

func TestValidatePop_SignatureMismatch(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background())

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := &WIAPopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "urn:wallet:instance:test",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: challenge,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-client-attestation-pop+jwt"
	// The header advertises otherKey's public JWK, but the token is actually
	// signed with signingKey — signature verification must fail.
	token.Header["jwk"] = ecJWKFromKey(&otherKey.PublicKey)
	pop, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.validatePop(pop, challenge)
	if err == nil {
		t.Fatal("expected signature verification failure when jwk header key doesn't match the signing key")
	}
}

func TestSignWIA_ComputeJKTError(t *testing.T) {
	svc, _ := newTestWIAService(t)

	_, err := svc.signWIA(map[string]interface{}{"kty": "RSA"}, "backend_attested")
	if err == nil {
		t.Fatal("expected error when cnf JWK fails JKT computation")
	}
}

// TestSignWIA_SignTokenError exercises signWIA's SignToken error path (e.g.
// an HSM/PKCS#11-backed signer that becomes unavailable). Reuses the
// failingSigner helper defined in wallet_provider_test.go.
func TestSignWIA_SignTokenError(t *testing.T) {
	svc, _ := newTestWIAService(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badSigner, err := signing.NewCryptoSignerES256(&failingSigner{pub: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	svc.jwtSigner = badSigner

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	_, err = svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error when jwtSigner.SignToken fails")
	}
}

// testAuditEmitter builds a real audit.Emitter backed by an ephemeral ES256
// key, mirroring the pattern used in internal/api tests.
func testAuditEmitter(t *testing.T) *audit.Emitter {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return audit.New("test-issuer", signer, nil)
}

// TestGenerateWIA_RecordsWalletInstanceAndAudit covers signWIA's wallet
// instance upsert and audit-emission blocks, which are skipped entirely by
// every other test in this file because they construct the service with
// instances=nil and audit=nil.
func TestGenerateWIA_RecordsWalletInstanceAndAudit(t *testing.T) {
	svc, _ := newTestWIAService(t)
	store := memory.NewStore()
	svc.instances = store.WalletInstances()
	svc.audit = testAuditEmitter(t)

	challenge, _, err := svc.CreateChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wia, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		t.Fatal("cnf claim missing")
	}
	jkt, ok := cnf["jkt"].(string)
	if !ok || jkt == "" {
		t.Fatal("cnf.jkt missing")
	}

	instance, err := svc.instances.GetByID(context.Background(), jkt)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if instance == nil {
		t.Fatal("expected wallet instance to be recorded on successful WIA generation")
	}
	if instance.WSCDType != domain.WSCDTypeWebCrypto {
		t.Errorf("WSCDType = %v, want %v", instance.WSCDType, domain.WSCDTypeWebCrypto)
	}
	if instance.AttestationSource != "backend_attested" {
		t.Errorf("AttestationSource = %v, want backend_attested", instance.AttestationSource)
	}
}

// fakeFailingInstanceStore always fails Upsert, used to verify that a
// wallet-instance recording failure is logged but does not fail WIA
// generation.
type fakeFailingInstanceStore struct{}

func (fakeFailingInstanceStore) Upsert(context.Context, *domain.WalletInstance) error {
	return errors.New("db unavailable")
}
func (fakeFailingInstanceStore) GetByID(context.Context, string) (*domain.WalletInstance, error) {
	return nil, nil
}
func (fakeFailingInstanceStore) GetAllByTenant(context.Context, domain.TenantID) ([]*domain.WalletInstance, error) {
	return nil, nil
}
func (fakeFailingInstanceStore) GetByUser(context.Context, domain.TenantID, domain.UserID) ([]*domain.WalletInstance, error) {
	return nil, nil
}
func (fakeFailingInstanceStore) UpdateStatus(context.Context, string, domain.InstanceStatus, string) error {
	return nil
}
func (fakeFailingInstanceStore) IncrementAttestation(context.Context, string) error {
	return nil
}
func (fakeFailingInstanceStore) Delete(context.Context, string) error {
	return nil
}

func TestGenerateWIA_InstanceUpsertErrorIsNonFatal(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.instances = fakeFailingInstanceStore{}

	challenge, _, _ := svc.CreateChallenge(context.Background())
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA should succeed even if instance upsert fails: %v", err)
	}
	if wia == "" {
		t.Fatal("expected WIA JWT despite instance upsert failure")
	}
}

func TestParseECPublicKeyFromJWK_InvalidBase64(t *testing.T) {
	validComponent := base64.RawURLEncoding.EncodeToString(make([]byte, 32))

	t.Run("invalid x", func(t *testing.T) {
		_, err := parseECPublicKeyFromJWK(map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   "not valid base64!!",
			"y":   validComponent,
		})
		if err == nil {
			t.Error("expected error for invalid x base64")
		}
	})

	t.Run("invalid y", func(t *testing.T) {
		_, err := parseECPublicKeyFromJWK(map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"x":   validComponent,
			"y":   "not valid base64!!",
		})
		if err == nil {
			t.Error("expected error for invalid y base64")
		}
	})
}

// TestParseECPublicKeyFromJWK_ShortComponentIsPadded covers the zero-padding
// loops for x/y coordinates shorter than 32 bytes. Some JWK encoders omit the
// leading zero byte of a coordinate (since big.Int.Bytes() strips it), so
// parseECPublicKeyFromJWK must re-pad rather than reject such keys.
func TestParseECPublicKeyFromJWK_ShortComponentIsPadded(t *testing.T) {
	var key *ecdsa.PrivateKey
	for i := 0; i < 5000; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(k.PublicKey.X.Bytes()) < 32 || len(k.PublicKey.Y.Bytes()) < 32 {
			key = k
			break
		}
	}
	if key == nil {
		t.Fatal("could not find a P-256 key with a short X or Y coordinate")
	}

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		// Deliberately unpadded, as produced by big.Int.Bytes().
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}

	parsed, err := parseECPublicKeyFromJWK(jwk)
	if err != nil {
		t.Fatalf("parseECPublicKeyFromJWK: %v", err)
	}
	if parsed.X.Cmp(key.PublicKey.X) != 0 || parsed.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("parsed key doesn't match original after zero-padding")
	}
}

func TestParseECPublicKeyFromJWK_PointNotOnCurve(t *testing.T) {
	// 32 bytes of 0xFF exceeds the P-256 field prime and cannot be a valid
	// coordinate for any point on the curve.
	notOnCurve := make([]byte, 32)
	for i := range notOnCurve {
		notOnCurve[i] = 0xFF
	}
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(notOnCurve),
		"y":   base64.RawURLEncoding.EncodeToString(notOnCurve),
	}
	_, err := parseECPublicKeyFromJWK(jwk)
	if err == nil {
		t.Error("expected error for a point not on the curve")
	}
}
