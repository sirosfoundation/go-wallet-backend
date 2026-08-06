package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	jwkpkg "github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
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
	}

	logger := zap.NewNop()
	jwtSigner, err := signing.NewCryptoSignerES256(privKey)
	if err != nil {
		t.Fatal(err)
	}
	svc := NewWIAService(cfg, logger, jwtSigner, []string{certB64}, nil, nil, nil)

	return svc, privKey
}

// newTestWIAServiceWithInstances is like newTestWIAService but wires a real
// (in-memory) wallet instance store, needed for tests that exercise
// suspend/revoke enforcement.
func newTestWIAServiceWithInstances(t *testing.T) (*WIAService, storage.WalletInstanceStore) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
		MaxExpirySeconds:    86400,
		ChallengeTTLSeconds: 300,
	}
	cfg.WalletProvider.Attestation = config.AttestationConfig{
		LifetimeSeconds: 3600,
	}

	logger := zap.NewNop()
	jwtSigner, err := signing.NewCryptoSignerES256(privKey)
	if err != nil {
		t.Fatal(err)
	}
	instances := memory.NewStore().WalletInstances()
	svc := NewWIAService(cfg, logger, jwtSigner, []string{certB64}, instances, nil, nil)

	return svc, instances
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

	challenge, expiresAt, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
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
	challenge, _, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	// Create PoP with the challenge nonce
	pop, _ := createTestPop(t, challenge)

	// Generate WIA
	wiaJWT, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
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

	// sub falls back to the instance identifier (jkt) when no client_id is
	// supplied - draft-ietf-oauth-attestation-based-client-auth-10 only
	// requires sub=client_id when the WIA is actually used for OAuth client
	// authentication (see TestWIAService_GenerateWIA_SubEqualsClientID).
	jkt, _ := cnf["jkt"].(string)
	if claims["sub"] != jkt {
		t.Errorf("sub = %v, want jkt %v (no client_id supplied)", claims["sub"], jkt)
	}
}

// "ietf" mode lets a deployment opt into the IETF-draft iss/JWKS identity
// format instead of ETSI TS 119 472-3's x5c-derived identity - needed when
// relying parties can't resolve trust via a self-signed x5c chain but can
// fetch a JWKS from a real iss URL (see RegisterWalletProviderJWKSRoute).
func TestWIAService_GenerateWIA_IETFMode(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.Mode = config.WIAModeIETF
	svc.cfg.WalletProvider.WIA.Issuer = "https://wallet-provider.example"

	challenge, _, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, _ := createTestPop(t, challenge)

	wiaJWT, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
		Pop:       pop,
		Challenge: challenge,
	})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wiaJWT, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Parse WIA: %v", err)
	}

	if token.Header["x5c"] != nil {
		t.Error("x5c header should be omitted in ietf mode")
	}

	// Regression: without a kid header, a relying party has no self-contained
	// key material (no x5c, no embedded jwk) and no way to know which of the
	// wallet provider's published JWKS keys to use for signature
	// verification (confirmed against a real relying party: SUNET/vc's
	// pkg/trust JWT verification requires kid to resolve via JWKS). Must
	// match RegisterWalletProviderJWKSRoute's hardcoded KeyID.
	if token.Header["kid"] != "wallet-provider" {
		t.Errorf("kid = %v, want %q (must match RegisterWalletProviderJWKSRoute's KeyID)", token.Header["kid"], "wallet-provider")
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["iss"] != "https://wallet-provider.example" {
		t.Errorf("iss = %v, want https://wallet-provider.example", claims["iss"])
	}
}

// TestWIAService_GenerateWIA_ETSIMode is the mirror of the ietf-mode test
// above: the default ("etsi") mode must always carry x5c and never iss/kid.
func TestWIAService_GenerateWIA_ETSIMode(t *testing.T) {
	svc, _ := newTestWIAService(t)
	// Mode left at its zero value ("") — signWIA's mode switch treats that
	// the same as explicit "etsi" (config.Validate() would normalize it,
	// but these unit tests construct WIAService directly, bypassing Validate).

	challenge, _, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, _ := createTestPop(t, challenge)

	wiaJWT, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
		Pop:       pop,
		Challenge: challenge,
	})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wiaJWT, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Parse WIA: %v", err)
	}

	if token.Header["x5c"] == nil {
		t.Error("x5c header should be present in etsi mode")
	}
	if token.Header["kid"] != nil {
		t.Error("kid header should not be present in etsi mode")
	}
	claims := token.Claims.(jwt.MapClaims)
	if _, ok := claims["iss"]; ok {
		t.Errorf("iss should not be present in etsi mode, got %v", claims["iss"])
	}
}

// draft-ietf-oauth-attestation-based-client-auth-10: "the sub claim MUST
// specify client_id value of the OAuth Client" - when the caller (the OID4VCI
// engine, via BackendApiClient.generateWIA) supplies its client_id, the WIA's
// sub must reflect it instead of the instance identifier (jkt) - confirmed
// against a real geneva2026.mdoc.online conformance run that flagged sub=jkt
// as a FAIL ("must specify client_id value").
func TestWIAService_GenerateWIA_SubEqualsClientID(t *testing.T) {
	svc, _ := newTestWIAService(t)

	challenge, _, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, _ := createTestPop(t, challenge)

	wiaJWT, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
		Pop:       pop,
		Challenge: challenge,
		ClientID:  "siros-sample://callback",
	})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wiaJWT, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("Parse WIA: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)

	if claims["sub"] != "siros-sample://callback" {
		t.Errorf("sub = %v, want siros-sample://callback (the supplied client_id)", claims["sub"])
	}
}

// TestWIAService_GenerateWIA_RecordsUserID is a regression test: the
// WalletInstance.UserID field existed and was queryable via GetByUser /
// the admin ListWalletInstancesByUser endpoint, but nothing in the WIA
// issuance path ever populated it — so that endpoint always returned an
// empty list in practice. GenerateWIA must now record the caller's user ID
// on the resulting instance when the caller passes one.
func TestWIAService_GenerateWIA_RecordsUserID(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, _ := createTestPop(t, challenge)

	uid := domain.UserIDFromString("user-42")
	wiaJWT, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(wiaJWT, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse WIA: %v", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	cnf := claims["cnf"].(map[string]interface{})
	jkt := cnf["jkt"].(string)

	got, err := instances.GetByID(ctx, jkt)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.UserID == nil || *got.UserID != uid {
		t.Errorf("instance UserID = %v, want %v", got.UserID, uid)
	}

	byUser, err := instances.GetByUser(ctx, domain.DefaultTenantID, uid)
	if err != nil {
		t.Fatalf("GetByUser: %v", err)
	}
	if len(byUser) != 1 || byUser[0].ID != jkt {
		t.Errorf("GetByUser returned %v, want exactly the instance %q", byUser, jkt)
	}
}

// TestWIAService_GenerateWIA_RefusesRevokedInstance is a regression test for the
// bug where a revoked/suspended wallet instance could obtain a fresh, fully valid
// WIA simply by requesting a new challenge/PoP with the same instance key —
// silently bypassing admin revocation.
func TestWIAService_GenerateWIA_RefusesRevokedInstance(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()

	// First attestation succeeds and creates the wallet instance record.
	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, instanceKey := createTestPop(t, challenge)
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("first GenerateWIA: %v", err)
	}

	// Compute the same jkt the service would have used, to revoke that instance.
	xBytes := instanceKey.PublicKey.X.Bytes()
	yBytes := instanceKey.PublicKey.Y.Bytes()
	for len(xBytes) < 32 {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < 32 {
		yBytes = append([]byte{0}, yBytes...)
	}
	jwk := map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(xBytes),
		"y": base64.RawURLEncoding.EncodeToString(yBytes),
	}
	jkt, err := jwkpkg.Thumbprint(jwk)
	if err != nil {
		t.Fatalf("jwk.Thumbprint: %v", err)
	}
	if err := instances.UpdateStatus(ctx, jkt, domain.InstanceStatusRevoked, "compromised device"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	// Same instance key requests a fresh challenge/PoP — must be refused.
	challenge2, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge 2: %v", err)
	}
	// Sign pop2 with the SAME instance key as the first attestation.
	claims := &WIAPopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "urn:wallet:instance:test-123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: challenge2,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-client-attestation-pop+jwt"
	token.Header["jwk"] = jwk
	pop2, err := token.SignedString(instanceKey)
	if err != nil {
		t.Fatalf("sign pop2: %v", err)
	}

	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop2, Challenge: challenge2})
	if !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("GenerateWIA for revoked instance: got err=%v, want ErrWIAInstanceDeactivated", err)
	}

	got, err := instances.GetByID(ctx, jkt)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.InstanceStatusRevoked {
		t.Errorf("instance status = %s, want revoked (must not be reactivated by the refused attempt)", got.Status)
	}
}

func TestWIAService_ChallengeIsSingleUse(t *testing.T) {
	svc, _ := newTestWIAService(t)

	challenge, _, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}

	pop, _ := createTestPop(t, challenge)

	// First use should succeed
	_, err = svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
		Pop:       pop,
		Challenge: challenge,
	})
	if err != nil {
		t.Fatalf("first GenerateWIA: %v", err)
	}

	// Second use should fail (single-use)
	pop2, _ := createTestPop(t, challenge)
	_, err = svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
		Pop:       pop2,
		Challenge: challenge,
	})
	if err == nil {
		t.Fatal("second GenerateWIA should fail (challenge consumed)")
	}
}

func TestWIAService_InvalidNonce(t *testing.T) {
	svc, _ := newTestWIAService(t)

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	// PoP with wrong nonce
	pop, _ := createTestPop(t, "wrong-nonce")

	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
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

	// Fill up the global challenge store capacity, spread across enough
	// distinct tenants that no single tenant hits its own per-tenant cap
	// (maxChallengesPerTenant) first.
	tenantCount := maxChallenges / maxChallengesPerTenant
	for i := 0; i < maxChallenges; i++ {
		tenant := domain.TenantID(fmt.Sprintf("tenant-%d", i%tenantCount))
		_, _, err := svc.CreateChallenge(context.Background(), tenant)
		if err != nil {
			t.Fatalf("CreateChallenge(%d) failed: %v", i, err)
		}
	}

	// Next one, for yet another tenant with room in its own per-tenant cap,
	// should still fail because the global pool is full.
	_, _, err := svc.CreateChallenge(context.Background(), domain.TenantID("one-more-tenant"))
	if err == nil {
		t.Fatal("should fail when global capacity exceeded")
	}
}

// TestWIAService_ChallengeCapacityLimit_PerTenant is a regression test for
// issue #224's "bounded capacity per tenant to prevent abuse" acceptance
// criterion: a single tenant filling its own per-tenant cap must be rejected
// well before the global pool is full, and a different tenant must be
// unaffected.
func TestWIAService_ChallengeCapacityLimit_PerTenant(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.ChallengeTTLSeconds = 300

	busyTenant := domain.TenantID("busy-tenant")
	for i := 0; i < maxChallengesPerTenant; i++ {
		_, _, err := svc.CreateChallenge(context.Background(), busyTenant)
		if err != nil {
			t.Fatalf("CreateChallenge(%d) for busyTenant failed: %v", i, err)
		}
	}

	// busyTenant is now at its own cap — rejected, even though the global
	// pool (maxChallenges) is nowhere near full.
	_, _, err := svc.CreateChallenge(context.Background(), busyTenant)
	if err == nil {
		t.Fatal("should fail once a tenant is at its own per-tenant cap")
	}

	// A different tenant must be unaffected.
	_, _, err = svc.CreateChallenge(context.Background(), domain.TenantID("other-tenant"))
	if err != nil {
		t.Fatalf("a different tenant should not be blocked by busyTenant's cap: %v", err)
	}
}

func TestWIAService_ExpiredChallenge(t *testing.T) {
	svc, _ := newTestWIAService(t)

	// Set TTL to 1 second
	svc.cfg.WalletProvider.WIA.ChallengeTTLSeconds = 1

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	// Manually expire the challenge (test-only: access in-memory store directly)
	memStore := svc.challenges.(*memoryWIAChallengeStore)
	memStore.store.mu.Lock()
	memStore.store.items[challenge].ExpiresAt = time.Now().Add(-1 * time.Second)
	memStore.store.mu.Unlock()

	pop, _ := createTestPop(t, challenge)

	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
		Pop:       pop,
		Challenge: challenge,
	})
	if err == nil {
		t.Fatal("should fail with expired challenge")
	}
}

// computeJKT/parseECPublicKeyFromJWK/ellipticCurveForName moved to pkg/jwk
// (Thumbprint/ParseECPublicKey/CurveForName) — see pkg/jwk/jwk_test.go for
// their unit tests.

func TestChallengeStoreLen(t *testing.T) {
	svc, _ := newTestWIAService(t)
	ctx := context.Background()

	n, _ := svc.challenges.Len(ctx)
	if n != 0 {
		t.Errorf("initial len = %d, want 0", n)
	}

	// Create a challenge
	_, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
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
	_, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
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
	challenge, expiresAt, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
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
	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
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
	wia, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{
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

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
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
	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	pop := newTestPopBuilder(t, challenge).withoutIssuedAt().build()
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for missing iat")
	}
	if !errors.Is(err, ErrWIAPopInvalid) {
		t.Errorf("expected ErrWIAPopInvalid, got %v", err)
	}
}

func TestValidatePop_IatTooOld(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	pop := newTestPopBuilder(t, challenge).withIssuedAt(time.Now().Add(-15 * time.Minute)).build()
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for old iat")
	}
}

func TestValidatePop_ExpTooFarFuture(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	pop := newTestPopBuilder(t, challenge).withExpiresAt(time.Now().Add(30 * time.Minute)).build()
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for exp too far in future")
	}
}

func TestValidatePop_MissingExp(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	pop := newTestPopBuilder(t, challenge).withoutExpiresAt().build()
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for missing exp")
	}
}

func TestValidatePop_MissingIssuer(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	pop := newTestPopBuilder(t, challenge).withoutIssuer().build()
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestValidatePop_InvalidTyp(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	pop := newTestPopBuilder(t, challenge).withTyp("wrong-typ").build()
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for wrong typ")
	}
}

func TestValidatePop_MissingJWK(t *testing.T) {
	svc, _ := newTestWIAService(t)
	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)

	pop := newTestPopBuilder(t, challenge).withoutJWK().build()
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err == nil {
		t.Fatal("expected error for missing jwk header")
	}
}

func TestValidatePop_AudValidation(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.WalletProviderURI = "https://wallet.example.com"

	t.Run("missing aud when required", func(t *testing.T) {
		challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
		pop := newTestPopBuilder(t, challenge).build() // no aud set
		_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
		if err == nil {
			t.Fatal("expected error for missing aud")
		}
	})

	t.Run("wrong aud", func(t *testing.T) {
		challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
		pop := newTestPopBuilder(t, challenge).withAudience("https://wrong.example.com").build()
		_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
		if err == nil {
			t.Fatal("expected error for wrong aud")
		}
	})

	t.Run("correct aud", func(t *testing.T) {
		challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
		pop := newTestPopBuilder(t, challenge).withAudience("https://wallet.example.com").build()
		_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
		if err != nil {
			t.Fatalf("should succeed with correct aud: %v", err)
		}
	})

	t.Run("correct aud among multiple", func(t *testing.T) {
		challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
		pop := newTestPopBuilder(t, challenge).withAudience("https://other.example.com", "https://wallet.example.com").build()
		_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
		if err != nil {
			t.Fatalf("should succeed with correct aud in list: %v", err)
		}
	})
}

func TestValidatePop_AudSkippedWhenNotConfigured(t *testing.T) {
	svc, _ := newTestWIAService(t)
	// WalletProviderURI not set — aud validation should be skipped

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	pop := newTestPopBuilder(t, challenge).build() // no aud
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("should succeed without aud when not configured: %v", err)
	}
}

func TestGenerateWIA_NotSupported(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.jwtSigner = nil // make unsupported

	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: "x", Challenge: "y"})
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

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	pop, _ := createTestPop(t, challenge)

	// Native attestation with invalid token should fail (not silently fallback)
	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
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

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	pop, _ := createTestPop(t, challenge)

	_, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{
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

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
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

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
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

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
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

// TestSignWIA_NoClientStatus is a regression test for the no-revocation-
// chaining design (see AttestationConfig's type-level comment): a WIA must
// never carry a client_status claim — there is no config knob left that
// could re-enable it (StatusListMode/StatusListURL/StatusListExpiry were
// removed).
func TestSignWIA_NoClientStatus(t *testing.T) {
	svc, _ := newTestWIAService(t)

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
	if err != nil {
		t.Fatalf("GenerateWIA: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(wia, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	if _, ok := claims["client_status"]; ok {
		t.Error("client_status should never be present (no revocation-chaining support)")
	}
}

func TestSignWIA_MaxExpiryDefault(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.MaxExpirySeconds = 0 // trigger default
	svc.cfg.WalletProvider.Attestation.LifetimeSeconds = 0

	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	pop, _ := createTestPop(t, challenge)

	wia, err := svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge})
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
	challenge, _, _ := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
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

func TestCreateChallenge_NotSupported(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.jwtSigner = nil

	_, _, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if !errors.Is(err, ErrWIANotSupported) {
		t.Errorf("expected ErrWIANotSupported, got %v", err)
	}
}

func TestCreateChallenge_DefaultTTL(t *testing.T) {
	svc, _ := newTestWIAService(t)
	svc.cfg.WalletProvider.WIA.ChallengeTTLSeconds = 0 // trigger default 5min

	_, expiresAt, err := svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
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
