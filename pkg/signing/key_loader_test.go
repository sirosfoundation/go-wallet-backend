package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestKeyAndCert(t *testing.T, dir string) (keyPath, certPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write key as PEM
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// Write cert as PEM
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	return keyPath, certPath
}

func generateTestPKCS8Key(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key-pkcs8.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath
}

func TestLoadKeyMaterial_FromFile(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := generateTestKeyAndCert(t, dir)

	cfg := &KeyConfig{
		PrivateKeyPath:  keyPath,
		CertificatePath: certPath,
	}

	km, err := LoadKeyMaterial(cfg)
	if err != nil {
		t.Fatalf("LoadKeyMaterial: %v", err)
	}
	if km.Signer == nil {
		t.Error("Signer is nil")
	}
	if len(km.CertChain) == 0 {
		t.Error("CertChain is empty")
	}
}

func TestLoadKeyMaterial_PKCS8Key(t *testing.T) {
	dir := t.TempDir()
	_, certPath := generateTestKeyAndCert(t, dir)
	keyPath := generateTestPKCS8Key(t, dir)

	cfg := &KeyConfig{
		PrivateKeyPath:  keyPath,
		CertificatePath: certPath,
	}

	km, err := LoadKeyMaterial(cfg)
	if err != nil {
		t.Fatalf("LoadKeyMaterial: %v", err)
	}
	if km.Signer == nil {
		t.Error("Signer is nil")
	}
}

func TestLoadKeyMaterial_MissingPaths(t *testing.T) {
	cfg := &KeyConfig{} // No paths set
	_, err := LoadKeyMaterial(cfg)
	if err == nil {
		t.Error("expected error for missing paths")
	}
}

func TestLoadKeyMaterial_BadKeyPath(t *testing.T) {
	dir := t.TempDir()
	_, certPath := generateTestKeyAndCert(t, dir)

	cfg := &KeyConfig{
		PrivateKeyPath:  "/nonexistent/key.pem",
		CertificatePath: certPath,
	}
	_, err := LoadKeyMaterial(cfg)
	if err == nil {
		t.Error("expected error for bad key path")
	}
}

func TestLoadKeyMaterial_BadCertPath(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := generateTestKeyAndCert(t, dir)

	cfg := &KeyConfig{
		PrivateKeyPath:  keyPath,
		CertificatePath: "/nonexistent/cert.pem",
	}
	_, err := LoadKeyMaterial(cfg)
	if err == nil {
		t.Error("expected error for bad cert path")
	}
}

func TestLoadKeyMaterial_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	_, certPath := generateTestKeyAndCert(t, dir)

	keyPath := filepath.Join(dir, "invalid.pem")
	os.WriteFile(keyPath, []byte("not a PEM block"), 0o600)

	cfg := &KeyConfig{
		PrivateKeyPath:  keyPath,
		CertificatePath: certPath,
	}
	_, err := LoadKeyMaterial(cfg)
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestLoadKeyMaterial_WithCACert(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath := generateTestKeyAndCert(t, dir)

	// Write a second cert as "CA"
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ca"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caPath := filepath.Join(dir, "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	os.WriteFile(caPath, caPEM, 0o644)

	cfg := &KeyConfig{
		PrivateKeyPath:  keyPath,
		CertificatePath: certPath,
		CACertPath:      caPath,
	}

	km, err := LoadKeyMaterial(cfg)
	if err != nil {
		t.Fatalf("LoadKeyMaterial with CA: %v", err)
	}
	if len(km.CertChain) != 2 {
		t.Errorf("expected 2 certs in chain, got %d", len(km.CertChain))
	}
}

func TestLoadKeyMaterial_PKCS11NotCompiled(t *testing.T) {
	cfg := &KeyConfig{
		PKCS11: &PKCS11Config{
			ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
			PIN:        "1234",
			KeyLabel:   "test",
		},
		CertificatePath: "/nonexistent",
	}
	_, err := LoadKeyMaterial(cfg)
	if err == nil {
		t.Error("expected error for PKCS11 (stub)")
	}
}

func TestParsePEMCerts_NoCerts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.pem")
	os.WriteFile(p, []byte(""), 0o644)

	certs, err := parsePEMCerts(p)
	if err != nil {
		t.Fatalf("parsePEMCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
}

func TestParsePEMCerts_SkipsNonCertBlocks(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(key)

	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	p := filepath.Join(dir, "mixed.pem")
	os.WriteFile(p, data, 0o644)

	certs, err := parsePEMCerts(p)
	if err != nil {
		t.Fatalf("parsePEMCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs (key block skipped), got %d", len(certs))
	}
}

func TestPKCS11Stub(t *testing.T) {
	// NewPKCS11Signer should return ErrPKCS11NotSupported
	_, err := NewPKCS11Signer(&PKCS11Config{})
	if err != ErrPKCS11NotSupported {
		t.Errorf("NewPKCS11Signer() = %v, want ErrPKCS11NotSupported", err)
	}
}

func TestPKCS11Stub_Methods(t *testing.T) {
	s := &PKCS11Signer{}
	// Sign should return error
	_, err := s.Sign(nil, nil, nil)
	if err != ErrPKCS11NotSupported {
		t.Errorf("Sign() = %v, want ErrPKCS11NotSupported", err)
	}
	// Close should not error
	if err := s.Close(); err != nil {
		t.Errorf("Close() = %v", err)
	}
}

func TestPKCS11Stub_Public_ReturnsNil(t *testing.T) {
	s := &PKCS11Signer{}
	pub := s.Public()
	if pub != nil {
		t.Errorf("Public() should return nil, got %T", pub)
	}
}
