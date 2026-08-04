package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

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
		StatusListMode:  "never",
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

func TestGenerateKeyAttestation_TopLevelSecurityProperties(t *testing.T) {
	svc := newTestWalletProviderService(t)

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

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "test-nonce", secProps, "", "")
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

	if claims["iss"] != "https://wp.example.com" {
		t.Errorf("iss = %v, want https://wp.example.com", claims["iss"])
	}
	if claims["nonce"] != "my-nonce" {
		t.Errorf("nonce = %v, want my-nonce", claims["nonce"])
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

func TestGenerateKeyAttestation_WalletInstanceIDAndAudience(t *testing.T) {
	svc := newTestWalletProviderService(t)

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	ka, err := svc.GenerateKeyAttestation(context.Background(), jwks, "nonce", nil, "wallet-instance-123", "https://issuer.example.com/credential")
	if err != nil {
		t.Fatalf("GenerateKeyAttestation: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, _ := parser.ParseUnverified(ka, jwt.MapClaims{})
	claims := token.Claims.(jwt.MapClaims)

	if claims["sub"] != "wallet-instance-123" {
		t.Errorf("sub = %v, want wallet-instance-123 (binds KA to wallet instance, CS-04 §7.1.3)", claims["sub"])
	}
	if claims["aud"] != "https://issuer.example.com/credential" {
		t.Errorf("aud = %v, want https://issuer.example.com/credential (scopes KA to target issuer)", claims["aud"])
	}
}

func TestGenerateKeyAttestation_NoWalletInstanceIDOrAudience(t *testing.T) {
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

	if _, ok := claims["sub"]; ok {
		t.Error("sub claim should be absent when walletInstanceID is empty")
	}
	if _, ok := claims["aud"]; ok {
		t.Error("aud claim should be absent when audience is empty")
	}
}

func TestGenerateKeyAttestation_DefaultExpiryWhenUnset(t *testing.T) {
	svc := newTestWalletProviderService(t)
	svc.cfg.WalletProvider.Attestation.KAExpirySeconds = 0 // triggers 15s default fallback

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

	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal("iat claim missing or not a number")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("exp claim missing or not a number")
	}
	if got := exp - iat; got != 15 {
		t.Errorf("exp-iat = %v, want 15 (default KA expiry when KAExpirySeconds <= 0)", got)
	}
}

// failingSigner is a crypto.Signer with a valid P-256 public key (so it
// passes NewCryptoSignerES256 construction) but always fails to sign, used
// to exercise GenerateKeyAttestation's signing-error path.
type failingSigner struct {
	pub *ecdsa.PublicKey
}

func (f *failingSigner) Public() crypto.PublicKey { return f.pub }

func (f *failingSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("simulated signing failure")
}

func TestGenerateKeyAttestation_SignError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwtSigner, err := signing.NewCryptoSignerES256(&failingSigner{pub: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Server.BaseURL = "https://wp.example.com"
	cfg.WalletProvider.Attestation = config.AttestationConfig{KAExpirySeconds: 15}
	svc := &WalletProviderService{
		cfg:       cfg,
		logger:    zap.NewNop(),
		jwtSigner: jwtSigner,
		certChain: []string{"deadbeef"},
	}

	jwks := []map[string]interface{}{
		{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	}

	_, err = svc.GenerateKeyAttestation(context.Background(), jwks, "nonce", nil, "", "")
	if err == nil {
		t.Fatal("expected error when the underlying signer fails to sign")
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

func TestGenerateKeyAttestation_KeyStorageStatus(t *testing.T) {
	svc := newTestWalletProviderService(t)
	svc.cfg.WalletProvider.Attestation.StatusListMode = "always"
	svc.cfg.WalletProvider.Attestation.StatusListURL = "https://wp.example.com/ka-statuslists/7"
	svc.cfg.WalletProvider.Attestation.StatusListExpiry = 2678400 // 31 days

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

	ksStatus, ok := claims["key_storage_status"].(map[string]interface{})
	if !ok {
		t.Fatal("key_storage_status claim missing")
	}
	statusObj, ok := ksStatus["status"].(map[string]interface{})
	if !ok {
		t.Fatal("key_storage_status.status missing")
	}
	sl, ok := statusObj["status_list"].(map[string]interface{})
	if !ok {
		t.Fatal("key_storage_status.status.status_list missing")
	}
	if sl["uri"] != "https://wp.example.com/ka-statuslists/7" {
		t.Errorf("uri = %v", sl["uri"])
	}
	if _, ok := ksStatus["exp"]; !ok {
		t.Error("key_storage_status.exp missing when StatusListExpiry > 0")
	}
}

func TestGenerateKeyAttestation_NoKeyStorageStatusWhenNever(t *testing.T) {
	svc := newTestWalletProviderService(t)
	svc.cfg.WalletProvider.Attestation.StatusListMode = "never"

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
		t.Error("key_storage_status should not be present when StatusListMode=never")
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

func TestLoadKeys_UnparsableKey(t *testing.T) {
	// A PEM block with an accepted type but bytes that are valid ASN.1 for
	// neither SEC1 EC nor PKCS8 — both parse attempts fail and the original
	// EC parse error should be returned.
	tmpDir := t.TempDir()
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not valid asn.1 der data at all")})
	kf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	if err := svc.loadKeys(); err == nil {
		t.Fatal("expected error when neither EC nor PKCS8 parsing succeeds")
	}
}

func TestLoadKeys_PKCS8NonECDSAKey(t *testing.T) {
	// A PKCS8-encoded RSA key should fail with "not an ECDSA private key"
	// since the wallet provider only supports ES256.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	err = svc.loadKeys()
	if err == nil {
		t.Fatal("expected error for non-ECDSA PKCS8 key")
	}
	if err.Error() != "not an ECDSA private key" {
		t.Errorf("err = %q, want %q", err.Error(), "not an ECDSA private key")
	}
}

func TestLoadKeys_WrongCurve(t *testing.T) {
	// A valid SEC1 EC key on a non-P256 curve parses fine but must be
	// rejected when building the ES256 JWT signer (wallet provider only
	// supports ES256/P-256).
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	if err := svc.loadKeys(); err == nil {
		t.Fatal("expected error for non-P256 curve key")
	}
}

func TestLoadKeys_MissingCertificateFile(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()

	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPath := tmpDir + "/key.pem"
	kf, _ := os.Create(keyPath)
	_ = pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = "/nonexistent/cert.pem"
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	err := svc.loadKeys()
	if err == nil {
		t.Fatal("expected error for missing certificate file")
	}
	if svc.jwtSigner == nil {
		t.Error("jwtSigner should still be set from the key even though cert loading failed")
	}
}

func TestLoadKeys_InvalidCACert_LogsWarningButSucceeds(t *testing.T) {
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
	cfg.WalletProvider.CACertPath = "/nonexistent/ca.pem"
	svc := &WalletProviderService{cfg: cfg, logger: zap.NewNop()}

	if err := svc.loadKeys(); err != nil {
		t.Fatalf("loadKeys should succeed despite a bad CA cert path: %v", err)
	}
	if len(svc.certChain) != 1 {
		t.Errorf("expected certChain to contain only the primary cert, got %d entries", len(svc.certChain))
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

	svc := NewWalletProviderService(cfg, zap.NewNop())
	if !svc.IsSupported() {
		t.Error("service should be supported with valid keys")
	}
}

func TestNewWalletProviderService_NoKeys(t *testing.T) {
	cfg := &config.Config{}
	svc := NewWalletProviderService(cfg, zap.NewNop())
	if svc.IsSupported() {
		t.Error("service should not be supported without keys")
	}
}

func TestNewWalletProviderService_FileKeys_LoadFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Invalid key content, but paths are set so the file-based branch is taken
	// and loadKeys() is expected to fail (exercises the constructor's warn
	// path instead of loadKeys itself).
	keyPath := tmpDir + "/key.pem"
	if err := os.WriteFile(keyPath, []byte("not a pem file"), 0600); err != nil {
		t.Fatal(err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPath := tmpDir + "/cert.pem"
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.PrivateKeyPath = keyPath
	cfg.WalletProvider.CertificatePath = certPath

	svc := NewWalletProviderService(cfg, zap.NewNop())
	if svc.IsSupported() {
		t.Error("service should not be supported when key loading fails")
	}
}

func TestNewWalletProviderService_PKCS11_LoadFailure(t *testing.T) {
	// PKCS#11 support is only compiled in with the "pkcs11" build tag, so in
	// the default test build LoadKeyMaterial always fails for a PKCS11
	// config. The constructor must log a warning and fall back to an
	// unsupported (no signer) service rather than erroring or panicking.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	tmpDir := t.TempDir()
	certPath := tmpDir + "/cert.pem"
	cf, _ := os.Create(certPath)
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	cfg := &config.Config{}
	cfg.WalletProvider.CertificatePath = certPath
	cfg.WalletProvider.PKCS11 = &config.PKCS11SigningConfig{
		ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
		SlotID:     0,
		PIN:        "1234",
		KeyLabel:   "wallet-provider",
	}

	svc := NewWalletProviderService(cfg, zap.NewNop())
	if svc.IsSupported() {
		t.Error("service should not be supported when PKCS#11 is not compiled in")
	}
	if svc.signer != nil {
		t.Error("signer should remain nil when PKCS#11 load fails")
	}
}
