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

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
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
// but wires a real (in-memory) wallet instance store, needed for tests that
// exercise the security-properties trust gate in GenerateKeyAttestation.
func newTestWalletProviderServiceWithInstances(t *testing.T) (*WalletProviderService, storage.WalletInstanceStore) {
	t.Helper()
	svc := newTestWalletProviderService(t)
	instances := memory.NewStore().WalletInstances()
	svc.instances = instances
	return svc, instances
}

// TestGenerateKeyAttestation_TopLevelSecurityProperties exercises the
// trusted path: the wallet instance already has a WIA proving native
// platform integrity, so the client's security_properties claim is
// honored (after normalization — already-prefixed iso_18045_* values pass
// through unchanged).
func TestGenerateKeyAttestation_TopLevelSecurityProperties(t *testing.T) {
	svc, instances := newTestWalletProviderServiceWithInstances(t)
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
// software/K3 floor.
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
	if cert := claims["certification"]; cert != "none" {
		t.Errorf("certification = %v, want \"none\"", cert)
	}
	if _, ok := claims["user_authentication"]; ok {
		t.Error("user_authentication should be clamped away, not passed through")
	}
}

// TestGenerateKeyAttestation_SecurityProperties_ClampedForBackendAttestedInstance
// covers the Tier 3 case: the wallet instance exists but its WIA was
// backend-attested only (no native platform integrity proof), so an
// elevated claim still must not be honored.
func TestGenerateKeyAttestation_SecurityProperties_ClampedForBackendAttestedInstance(t *testing.T) {
	svc, instances := newTestWalletProviderServiceWithInstances(t)
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
	assertKeyStorage(t, parseKAClaims(t, ka), "iso_18045_basic")
}

// TestGenerateKeyAttestation_SecurityProperties_ClampedForUnknownInstance
// covers a wallet_instance_id that doesn't resolve to any known instance
// (storage.ErrNotFound) — must fail closed (clamp), not fail open.
func TestGenerateKeyAttestation_SecurityProperties_ClampedForUnknownInstance(t *testing.T) {
	svc, _ := newTestWalletProviderServiceWithInstances(t)

	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"}}
	secProps := &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, "does-not-exist", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}
	assertKeyStorage(t, parseKAClaims(t, ka), "iso_18045_basic")
}

// TestGenerateKeyAttestation_SecurityProperties_NormalizesRawVocabulary is a
// regression test for the other half of the same finding: the SDKs send
// their raw internal WSCD vocabulary ("software"/"hardware"/
// "trusted_execution"/"remote_hsm"), not the iso_18045_* enum the KA spec
// requires, and nothing was mapping it before this fix — even for a
// trusted (natively-attested) instance.
func TestGenerateKeyAttestation_SecurityProperties_NormalizesRawVocabulary(t *testing.T) {
	svc, instances := newTestWalletProviderServiceWithInstances(t)
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
	svc, instances := newTestWalletProviderServiceWithInstances(t)
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

func TestGenerateKeyAttestation_NoSecurityProperties(t *testing.T) {
	svc := newTestWalletProviderService(t)

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", nil, "", "")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(ka, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	if _, ok := claims["key_storage"]; ok {
		t.Error("key_storage should not be present when secProps is nil")
	}
	if _, ok := claims["user_authentication"]; ok {
		t.Error("user_authentication should not be present when secProps is nil")
	}
	if _, ok := claims["certification"]; ok {
		t.Error("certification should not be present when secProps is nil")
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

	if token.Header["typ"] != "keyattestation+jwt" {
		t.Errorf("typ = %v, want keyattestation+jwt", token.Header["typ"])
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

	svc := NewWalletProviderService(cfg, zap.NewNop(), nil)
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

	svc := NewWalletProviderService(cfg, zap.NewNop(), nil)
	if !svc.IsSupported() {
		t.Error("service should fall back to file-based keys when PKCS#11 fails to load")
	}
}

func TestNewWalletProviderService_NoKeys(t *testing.T) {
	cfg := &config.Config{}
	svc := NewWalletProviderService(cfg, zap.NewNop(), nil)
	if svc.IsSupported() {
		t.Error("service should not be supported without keys")
	}
}
