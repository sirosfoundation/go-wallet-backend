package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

func newTestWalletProviderService(t *testing.T) *WalletProviderService {
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
	cfg.Server.BaseURL = "https://wp.example.com"
	cfg.WalletProvider.Attestation = config.AttestationConfig{
		KAExpirySeconds: 15,
	}

	jwtSigner, err := signing.NewCryptoSignerES256(privKey)
	if err != nil {
		t.Fatal(err)
	}

	return &WalletProviderService{
		cfg:       cfg,
		logger:    zap.NewNop(),
		signer:    privKey,
		jwtSigner: jwtSigner,
		certChain: []string{certB64},
	}
}

// newTestWalletProviderServiceWithInstances is like newTestWalletProviderService
// but wires real (in-memory) wallet instance + key attestation stores, needed
// for tests that exercise the security-properties trust gate in
// GenerateKeyAttestation.
func newTestWalletProviderServiceWithInstances(t *testing.T) (*WalletProviderService, storage.WalletInstanceStore, storage.KeyAttestationStore) {
	t.Helper()
	svc := newTestWalletProviderService(t)
	store := memory.NewStore()
	svc.instances = store.WalletInstances()
	svc.keyAttestations = store.KeyAttestations()
	return svc, store.WalletInstances(), store.KeyAttestations()
}

// TestGenerateKeyAttestation_TopLevelSecurityProperties exercises the
// trusted path: the wallet instance already has a WIA proving native
// platform integrity, so the client's security_properties claim is
// honored (after normalization — already-prefixed iso_18045_* values pass
// through unchanged).
func TestGenerateKeyAttestation_TopLevelSecurityProperties(t *testing.T) {
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	instanceID := "test-instance-native"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{
		ID:                instanceID,
		AttestationSource: "ios_app_attest",
	}); err != nil {
		t.Fatal(err)
	}

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	secProps := &SecurityProperties{
		KeyStorage:         []string{"iso_18045_high"},
		UserAuthentication: []string{"iso_18045_high"},
		Certification: map[string]interface{}{
			"scheme":          "EUCC",
			"assurance_level": "substantial",
		},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, instanceID, "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(ka, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)

	// Security properties must be top-level claims (Annex C §C.3.1)
	ks, ok := claims["key_storage"]
	if !ok {
		t.Fatal("key_storage claim missing at top level")
	}
	ksArr, ok := ks.([]interface{})
	if !ok {
		t.Fatalf("key_storage should be array, got %T", ks)
	}
	if len(ksArr) != 1 || ksArr[0] != "iso_18045_high" {
		t.Errorf("key_storage = %v, want [iso_18045_high]", ksArr)
	}

	ua, ok := claims["user_authentication"]
	if !ok {
		t.Fatal("user_authentication claim missing at top level")
	}
	uaArr, ok := ua.([]interface{})
	if !ok || len(uaArr) != 1 || uaArr[0] != "iso_18045_high" {
		t.Errorf("user_authentication = %v, want [iso_18045_high]", ua)
	}

	cert, ok := claims["certification"].(map[string]interface{})
	if !ok {
		t.Fatal("certification claim missing or not an object")
	}
	if cert["scheme"] != "EUCC" {
		t.Errorf("certification.scheme = %v, want EUCC", cert["scheme"])
	}

	// attested_keys should NOT contain security properties
	keys, ok := claims["attested_keys"].([]interface{})
	if !ok || len(keys) != 1 {
		t.Fatal("attested_keys missing or wrong length")
	}
	keyMap, ok := keys[0].(map[string]interface{})
	if !ok {
		t.Fatal("attested_keys[0] not a map")
	}
	if _, exists := keyMap["key_storage"]; exists {
		t.Error("key_storage should not be inside attested_keys entries")
	}
	if _, exists := keyMap["certification"]; exists {
		t.Error("certification should not be inside attested_keys entries")
	}
}

// TestGenerateKeyAttestation_SecurityProperties_TrustedWhenAllBatchKeysHaveEvidence
// exercises the other half of keyAttestationTrustsBatch: an instance with no
// native-platform AttestationSource, but where EVERY key in the current KA
// request's jwks batch has a durably verified FIDO2 hardware-key attestation
// on file (see FIDO2AttestationService, KeyAttestationStore.MarkKeyAttested,
// keyed by JWK Thumbprint - NOT by wallet instance), must still be treated
// as trusted, not clamped.
func TestGenerateKeyAttestation_SecurityProperties_TrustedWhenAllBatchKeysHaveEvidence(t *testing.T) {
	svc, instances, keyAttestations := newTestWalletProviderServiceWithInstances(t)
	instanceID := "test-instance-fido2-hardware"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{
		ID: instanceID,
	}); err != nil {
		t.Fatal(err)
	}

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}
	thumbprint, err := jwk.Thumbprint(jwks[0])
	if err != nil {
		t.Fatalf("compute thumbprint: %v", err)
	}
	if err := keyAttestations.MarkKeyAttested(context.Background(), &domain.KeyAttestationRecord{
		KeyThumbprint:    thumbprint,
		WalletInstanceID: instanceID,
		VerifiedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatalf("MarkKeyAttested: %v", err)
	}

	secProps := &SecurityProperties{
		KeyStorage: []string{"iso_18045_high"},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, instanceID, "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(ka, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)

	ks, ok := claims["key_storage"].([]interface{})
	if !ok || len(ks) != 1 || ks[0] != "iso_18045_high" {
		t.Errorf("key_storage = %v, want [iso_18045_high] (batch with verified per-key evidence should not be clamped)", claims["key_storage"])
	}
}

// TestGenerateKeyAttestation_SecurityProperties_ClampedWhenOnlySomeBatchKeysHaveEvidence
// verifies the "all keys required" policy: a batch is only as trusted as its
// weakest member - if even one key in a multi-key batch lacks evidence, the
// whole batch clamps to the K3 floor, even though another key in the same
// batch IS verified.
func TestGenerateKeyAttestation_SecurityProperties_ClampedWhenOnlySomeBatchKeysHaveEvidence(t *testing.T) {
	svc, instances, keyAttestations := newTestWalletProviderServiceWithInstances(t)
	instanceID := "test-instance-mixed-batch"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: instanceID}); err != nil {
		t.Fatal(err)
	}

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "attested-x", "y": "attested-y"},
		{"kty": "EC", "crv": "P-256", "x": "unattested-x", "y": "unattested-y"},
	}
	attestedThumbprint, err := jwk.Thumbprint(jwks[0])
	if err != nil {
		t.Fatalf("compute thumbprint: %v", err)
	}
	if err := keyAttestations.MarkKeyAttested(context.Background(), &domain.KeyAttestationRecord{
		KeyThumbprint:    attestedThumbprint,
		WalletInstanceID: instanceID,
		VerifiedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatalf("MarkKeyAttested: %v", err)
	}
	// jwks[1] deliberately has no corresponding record.

	secProps := &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}
	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, instanceID, "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(ka, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)

	ks, ok := claims["key_storage"].([]interface{})
	if !ok || len(ks) != 1 || ks[0] != "iso_18045_basic" {
		t.Errorf("key_storage = %v, want [iso_18045_basic] (one unattested key in the batch must clamp the whole batch)", claims["key_storage"])
	}
	assertUserAuthentication(t, claims, "iso_18045_basic")
}

// TestGenerateKeyAttestation_SecurityProperties_UnrelatedPriorAttestationDoesNotLeak
// is the regression test for the original bug: a wallet instance that
// previously had a DIFFERENT, unrelated credential key verified as
// hardware-attested must NOT have that evidence leak into a later batch of
// entirely different (e.g. softkey-generated) keys for the same instance.
func TestGenerateKeyAttestation_SecurityProperties_UnrelatedPriorAttestationDoesNotLeak(t *testing.T) {
	svc, instances, keyAttestations := newTestWalletProviderServiceWithInstances(t)
	instanceID := "test-instance-plugin-switch"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: instanceID}); err != nil {
		t.Fatal(err)
	}

	// An earlier, unrelated key (e.g. this instance's identity key, or a
	// prior FIDO2-backed credential batch) was verified hardware-attested...
	priorJWK := map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "prior-x", "y": "prior-y"}
	priorThumbprint, err := jwk.Thumbprint(priorJWK)
	if err != nil {
		t.Fatalf("compute thumbprint: %v", err)
	}
	if err := keyAttestations.MarkKeyAttested(context.Background(), &domain.KeyAttestationRecord{
		KeyThumbprint:    priorThumbprint,
		WalletInstanceID: instanceID,
		VerifiedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatalf("MarkKeyAttested: %v", err)
	}

	// ...but THIS batch's keys (e.g. softkey-generated) are entirely
	// different and have no evidence of their own.
	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "new-batch-x", "y": "new-batch-y"},
	}
	secProps := &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, instanceID, "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(ka, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	claims := token.Claims.(jwt.MapClaims)

	ks, ok := claims["key_storage"].([]interface{})
	if !ok || len(ks) != 1 || ks[0] != "iso_18045_basic" {
		t.Errorf("key_storage = %v, want [iso_18045_basic] (an unrelated prior key's evidence must not leak into this batch)", claims["key_storage"])
	}
	assertUserAuthentication(t, claims, "iso_18045_basic")
}

func TestGenerateKeyAttestation_CertificationStringNone(t *testing.T) {
	svc := newTestWalletProviderService(t)

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	secProps := &SecurityProperties{
		KeyStorage:    []string{"iso_18045_basic"},
		Certification: "none",
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, "", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(ka, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	cert, ok := claims["certification"]
	if !ok {
		t.Fatal("certification claim missing")
	}
	if cert != "none" {
		t.Errorf("certification = %v, want \"none\"", cert)
	}
}

// TestGenerateKeyAttestation_SecurityProperties_ClampedWithoutInstance is a
// regression test for a review finding: without this, any caller could
// self-assert an arbitrary key_storage/certification claim (e.g.
// iso_18045_high) with no wallet_instance_id and no verification at all,
// and have it signed straight into the KA JWT. With no walletInstanceID to
// even attempt a lookup against, the claim must be clamped to the
// software/K3 floor. The floor still emits all three TS03-required claims
// (including user_authentication at iso_18045_basic): omitting it caused
// PID issuers to reject the KA as missing TS03 claims.
func TestGenerateKeyAttestation_SecurityProperties_ClampedWithoutInstance(t *testing.T) {
	svc := newTestWalletProviderService(t)

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}
	secProps := &SecurityProperties{
		KeyStorage:         []string{"iso_18045_high"},
		UserAuthentication: []string{"iso_18045_high"},
		Certification: map[string]interface{}{
			"scheme": "EUCC",
		},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, "", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	claims := parseKAClaims(t, ka)
	assertKeyStorage(t, claims, "iso_18045_basic")
	assertUserAuthentication(t, claims, "iso_18045_basic")
	if cert := claims["certification"]; cert != "none" {
		t.Errorf("certification = %v, want \"none\"", cert)
	}
}

// TestGenerateKeyAttestation_SecurityProperties_ClampedForBackendAttestedInstance
// covers the Tier 3 case: the wallet instance exists but its WIA was
// backend-attested only (no native platform integrity proof), so an
// elevated claim still must not be honored.
func TestGenerateKeyAttestation_SecurityProperties_ClampedForBackendAttestedInstance(t *testing.T) {
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	instanceID := "test-instance-backend-attested"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{
		ID:                instanceID,
		AttestationSource: "backend_attested",
	}); err != nil {
		t.Fatal(err)
	}

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	secProps := &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, instanceID, "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	claims := parseKAClaims(t, ka)
	assertKeyStorage(t, claims, "iso_18045_basic")
	assertUserAuthentication(t, claims, "iso_18045_basic")
}

// TestGenerateKeyAttestation_SecurityProperties_ClampedForUnknownInstance
// covers a wallet_instance_id that doesn't resolve to any known instance
// (storage.ErrNotFound) — must fail closed (clamp), not fail open.
func TestGenerateKeyAttestation_SecurityProperties_ClampedForUnknownInstance(t *testing.T) {
	svc, _, _ := newTestWalletProviderServiceWithInstances(t)

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	secProps := &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, "does-not-exist", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	claims := parseKAClaims(t, ka)
	assertKeyStorage(t, claims, "iso_18045_basic")
	assertUserAuthentication(t, claims, "iso_18045_basic")
}

// TestGenerateKeyAttestation_SecurityProperties_NormalizesRawVocabulary is a
// regression test for the other half of the same finding: the SDKs send
// their raw internal WSCD vocabulary ("software"/"hardware"/
// "trusted_execution"/"remote_hsm"), not the iso_18045_* enum the KA spec
// requires, and nothing was mapping it before this fix — even for a
// trusted (natively-attested) instance.
func TestGenerateKeyAttestation_SecurityProperties_NormalizesRawVocabulary(t *testing.T) {
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	instanceID := "test-instance-native-2"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{
		ID:                instanceID,
		AttestationSource: "android_play_integrity",
	}); err != nil {
		t.Fatal(err)
	}

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	secProps := &SecurityProperties{
		KeyStorage:         []string{"hardware"},
		UserAuthentication: []string{"none"},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, instanceID, "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	claims := parseKAClaims(t, ka)
	assertKeyStorage(t, claims, "iso_18045_moderate")
	// omitIfNone: a "none" user_authentication claim is dropped, not mapped
	// to a placeholder value.
	if _, ok := claims["user_authentication"]; ok {
		t.Errorf("user_authentication = %v, want omitted for \"none\"", claims["user_authentication"])
	}
}

// TestGenerateKeyAttestation_SecurityProperties_UnrecognizedValueDefaultsToBasic
// covers an unrecognized raw value (not already iso_18045_*, not a known
// internal vocabulary word) — must default to the safe floor rather than
// erroring or passing an invalid enum value through into the signed JWT.
func TestGenerateKeyAttestation_SecurityProperties_UnrecognizedValueDefaultsToBasic(t *testing.T) {
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	instanceID := "test-instance-native-3"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{
		ID:                instanceID,
		AttestationSource: "ios_app_attest",
	}); err != nil {
		t.Fatal(err)
	}

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	secProps := &SecurityProperties{KeyStorage: []string{"quantum_vault"}}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, instanceID, "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	assertKeyStorage(t, parseKAClaims(t, ka), "iso_18045_basic")
}

func parseKAClaims(t *testing.T, ka string) jwt.MapClaims {
	t.Helper()
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(ka, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	return token.Claims.(jwt.MapClaims)
}

func assertKeyStorage(t *testing.T, claims jwt.MapClaims, want string) {
	t.Helper()
	ks, ok := claims["key_storage"].([]interface{})
	if !ok || len(ks) != 1 || ks[0] != want {
		t.Errorf("key_storage = %v, want [%s]", claims["key_storage"], want)
	}
}

func assertUserAuthentication(t *testing.T, claims jwt.MapClaims, want string) {
	t.Helper()
	ua, ok := claims["user_authentication"].([]interface{})
	if !ok || len(ua) != 1 || ua[0] != want {
		t.Errorf("user_authentication = %v, want [%s]", claims["user_authentication"], want)
	}
}

// TestGenerateKeyAttestation_NoSecurityProperties is a regression for PID
// issuers that require TS03's key_storage / user_authentication /
// certification on every KA: omitting security_properties must still emit
// the software floor, not leave the claims absent.
func TestGenerateKeyAttestation_NoSecurityProperties(t *testing.T) {
	svc := newTestWalletProviderService(t)

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", nil, "", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	claims := parseKAClaims(t, ka)
	assertKeyStorage(t, claims, "iso_18045_basic")
	assertUserAuthentication(t, claims, "iso_18045_basic")
	if cert := claims["certification"]; cert != "none" {
		t.Errorf("certification = %v, want \"none\"", cert)
	}
}

// TestGenerateKeyAttestation_NoSecurityProperties_TrustedStillEmitsFloor
// verifies that native-platform trust does not invent elevated claims when
// the client never asserted security_properties.
func TestGenerateKeyAttestation_NoSecurityProperties_TrustedStillEmitsFloor(t *testing.T) {
	svc, instances, _ := newTestWalletProviderServiceWithInstances(t)
	instanceID := "test-instance-native-no-secprops"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{
		ID:                instanceID,
		AttestationSource: "ios_app_attest",
	}); err != nil {
		t.Fatal(err)
	}

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", nil, instanceID, "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	claims := parseKAClaims(t, ka)
	assertKeyStorage(t, claims, "iso_18045_basic")
	assertUserAuthentication(t, claims, "iso_18045_basic")
	if cert := claims["certification"]; cert != "none" {
		t.Errorf("certification = %v, want \"none\"", cert)
	}
}

func TestGenerateKeyAttestation_StandardClaims(t *testing.T) {
	svc := newTestWalletProviderService(t)

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "my-nonce", nil, "", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(ka, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	if _, ok := claims["iss"]; ok {
		t.Errorf("iss should not be present on a KA (EC TS03 v1.5.2 removed it), got %v", claims["iss"])
	}
	if claims["c_nonce"] != "my-nonce" {
		t.Errorf("c_nonce = %v, want my-nonce", claims["c_nonce"])
	}
	if claims["nonce"] != "my-nonce" {
		t.Errorf("nonce = %v, want my-nonce (sent alongside c_nonce for interop)", claims["nonce"])
	}

	// The JOSE "typ" short form of "application/key-attestation+jwt", the
	// media type OpenID4VCI 1.0 registers for a Key Attestation JWT. Issuers
	// pin this string exactly (vc's apigw uses an `eq` validation on it), so a
	// regression here - the hyphen above all - fails every credential request
	// that uses the "attestation" proof type.
	if token.Header["typ"] != "key-attestation+jwt" {
		t.Errorf("typ = %v, want key-attestation+jwt", token.Header["typ"])
	}

	if _, ok := claims["iat"]; !ok {
		t.Error("iat claim missing")
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("exp claim missing")
	}
}

func TestGenerateKeyAttestation_NotSupported(t *testing.T) {
	svc := &WalletProviderService{
		cfg:    &config.Config{},
		logger: zap.NewNop(),
		// No signer or certChain — not supported
	}

	_, err := svc.GenerateKeyAttestation(context.Background(), nil, "nonce", nil, "", "")
	if err != ErrKeyAttestationNotSupported {
		t.Errorf("expected ErrKeyAttestationNotSupported, got %v", err)
	}
}

// TestGenerateKeyAttestation_NoRevocationClaims is a regression test for the
// no-revocation-chaining design (see AttestationConfig's type-level comment):
// a KA must never carry key_storage_status or iss, regardless of config —
// there is no config knob left that could re-enable them.
func TestGenerateKeyAttestation_NoRevocationClaims(t *testing.T) {
	svc := newTestWalletProviderService(t)

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "nonce", nil, "", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(ka, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	if _, ok := claims["key_storage_status"]; ok {
		t.Error("key_storage_status should never be present (no revocation-chaining support)")
	}
	if _, ok := claims["iss"]; ok {
		t.Error("iss should never be present on a KA (EC TS03 v1.5.2 removed it; identity is x5c-only)")
	}
	if claims["c_nonce"] != "nonce" {
		t.Errorf("c_nonce = %v, want %q (TS03 §2.3.2 requires c_nonce, not nonce)", claims["c_nonce"], "nonce")
	}
	if claims["nonce"] != "nonce" {
		t.Errorf("nonce = %v, want %q (sent alongside c_nonce for interop with issuers expecting the base OpenID4VCI claim name)", claims["nonce"], "nonce")
	}
}

func TestParsePEMCertChain_Valid(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	tmpDir := t.TempDir()
	certPath := tmpDir + "/cert.pem"
	f, _ := os.Create(certPath)
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	f.Close()

	chain, err := parsePEMCertChain(certPath)
	if err != nil {
		t.Fatalf("parsePEMCertChain: %v", err)
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 cert, got %d", len(chain))
	}
}

func TestParsePEMCertChain_MultipleCerts(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tmpDir := t.TempDir()
	certPath := tmpDir + "/chain.pem"
	f, _ := os.Create(certPath)
	for i := 0; i < 3; i++ {
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1))}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	}
	f.Close()

	chain, err := parsePEMCertChain(certPath)
	if err != nil {
		t.Fatalf("parsePEMCertChain: %v", err)
	}
	if len(chain) != 3 {
		t.Errorf("expected 3 certs, got %d", len(chain))
	}
}

func TestParsePEMCertChain_NoCerts(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := tmpDir + "/empty.pem"
	_ = os.WriteFile(certPath, []byte("not a pem file"), 0600)

	_, err := parsePEMCertChain(certPath)
	if err == nil {
		t.Fatal("expected error for file with no certs")
	}
}

func TestParsePEMCertChain_FileNotFound(t *testing.T) {
	_, err := parsePEMCertChain("/nonexistent/path/cert.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadKeys_ValidECKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPath := tmpDir + "/cert.pem"
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	if err := svc.loadKeys(); err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	if svc.signer == nil {
		t.Error("signer should be set")
	}
	if svc.jwtSigner == nil {
		t.Error("jwtSigner should be set")
	}
	if len(svc.certChain) == 0 {
		t.Error("certChain should be set")
	}
}

func TestLoadKeys_PKCS8Key(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()

	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPath := tmpDir + "/cert.pem"
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	if err := svc.loadKeys(); err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	if svc.signer == nil {
		t.Error("signer should be set")
	}
}

func TestLoadKeys_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := tmpDir + "/key.pem"
	_ = os.WriteFile(keyPath, []byte("not a pem file"), 0600)

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	if err := svc.loadKeys(); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadKeys_BadPEMType(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")})
	kf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	err := svc.loadKeys()
	if err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

func TestLoadKeys_WithCACert(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPath := tmpDir + "/cert.pem"
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), IsCA: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	caPath := tmpDir + "/ca.pem"
	caf, _ := os.Create(caPath)
	_ = pem.Encode(caf, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.CACertPath = caPath
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	if err := svc.loadKeys(); err != nil {
		t.Fatalf("loadKeys: %v", err)
	}
	if len(svc.certChain) != 2 {
		t.Errorf("expected 2 certs in chain, got %d", len(svc.certChain))
	}
}

func TestLoadKeys_MissingKeyFile(t *testing.T) {
	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = "/nonexistent/key.pem"
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	if err := svc.loadKeys(); err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestNewWalletProviderService_FileKeys(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPath := tmpDir + "/cert.pem"
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath

	svc := NewWalletProviderService(cfg, zap.NewNop(), nil, nil)
	if !svc.IsSupported() {
		t.Error("service should be supported with valid keys")
	}
}

// TestNewWalletProviderService_PKCS11FailureFallsBackToFileKeys is a
// regression test: when PKCS#11 is configured but fails to load (here,
// because the test binary isn't built with -tags pkcs11, so
// signing.LoadKeyMaterial always errors), the service must still fall back
// to a configured file-based key instead of ending up unsupported. Before
// this fix, the if/else-if structure meant the file-key branch was never
// even attempted once the PKCS#11 branch was entered.
func TestNewWalletProviderService_PKCS11FailureFallsBackToFileKeys(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPath := tmpDir + "/cert.pem"
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.PKCS11 = &config.PKCS11SigningConfig{
		ModulePath: "/nonexistent/pkcs11.so", // fails to load regardless of build tags
	}

	svc := NewWalletProviderService(cfg, zap.NewNop(), nil, nil)
	if !svc.IsSupported() {
		t.Error("service should fall back to file-based keys when PKCS#11 fails to load")
	}
}

func TestNewWalletProviderService_NoKeys(t *testing.T) {
	cfg := &config.Config{}
	svc := NewWalletProviderService(cfg, zap.NewNop(), nil, nil)
	if svc.IsSupported() {
		t.Error("service should not be supported without keys")
	}
}

func TestWalletProviderService_PublicKey(t *testing.T) {
	svc := newTestWalletProviderService(t)

	pub := svc.PublicKey()
	if pub == nil {
		t.Fatal("expected non-nil public key when a signer is configured")
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	signerKey, ok := svc.signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected signer to be *ecdsa.PrivateKey, got %T", svc.signer)
	}
	if !ecPub.Equal(&signerKey.PublicKey) {
		t.Error("PublicKey() should return the signer's public key")
	}
}

func TestWalletProviderService_PublicKey_NilWithoutSigner(t *testing.T) {
	svc := &WalletProviderService{cfg: &config.Config{}}
	if pub := svc.PublicKey(); pub != nil {
		t.Errorf("expected nil PublicKey() without a configured signer, got %v", pub)
	}
}
