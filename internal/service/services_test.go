package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewServices(t *testing.T) {
	store := memory.NewStore()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
	}
	logger := zap.NewNop()

	services := NewServices(store, cfg, logger)

	if services == nil {
		t.Fatal("expected services to not be nil")
	}

	// Verify all services are initialized
	if services.User == nil {
		t.Error("expected User service to be initialized")
	}
	if services.Tenant == nil {
		t.Error("expected Tenant service to be initialized")
	}
	if services.UserTenant == nil {
		t.Error("expected UserTenant service to be initialized")
	}
	if services.WebAuthn == nil {
		t.Error("expected WebAuthn service to be initialized")
	}
	if services.Credential == nil {
		t.Error("expected Credential service to be initialized")
	}
	if services.Issuer == nil {
		t.Error("expected Issuer service to be initialized")
	}
	if services.Verifier == nil {
		t.Error("expected Verifier service to be initialized")
	}
	if services.Keystore == nil {
		t.Error("expected Keystore service to be initialized")
	}
	if services.Proxy == nil {
		t.Error("expected Proxy service to be initialized")
	}
	if services.Helper == nil {
		t.Error("expected Helper service to be initialized")
	}
	if services.WalletProvider == nil {
		t.Error("expected WalletProvider service to be initialized")
	}
}

func TestNewServices_InvalidWebAuthnConfig(t *testing.T) {
	store := memory.NewStore()
	cfg := &config.Config{
		// Missing WebAuthn config (no RPID, etc.)
		JWT: config.JWTConfig{
			Secret:      "test-secret",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
	}
	logger := zap.NewNop()

	services := NewServices(store, cfg, logger)

	// Services should still be created even if WebAuthn fails
	if services == nil {
		t.Fatal("expected services to not be nil")
	}

	// WebAuthn may be nil if config is invalid
	// This is expected behavior - the service logs a warning and continues

	// Other services should still be available
	if services.User == nil {
		t.Error("expected User service to be initialized")
	}
}

// writeECKeyAndCert generates an EC P-256 key + self-signed cert and writes
// them as PEM files in dir, returning (keyPath, certPath).
func writeECKeyAndCert(t *testing.T, dir, prefix string) (string, string) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, prefix+"-key.pem")
	certPath := filepath.Join(dir, prefix+"-cert.pem")

	if err := writePEMFile(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
		t.Fatal(err)
	}
	if err := writePEMFile(certPath, "CERTIFICATE", certDER); err != nil {
		t.Fatal(err)
	}
	return keyPath, certPath
}

func writePEMFile(path, blockType string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

// TestNewServices_WiresAuditEmitterIntoWIA is a regression test: WIAService
// must receive a real audit emitter whenever cfg.Audit is enabled, so WIA
// issuance/failure SET events actually get emitted (previously NewServices
// hardcoded nil regardless of the Audit config).
func TestNewServices_WiresAuditEmitterIntoWIA(t *testing.T) {
	dir := t.TempDir()
	wpKeyPath, wpCertPath := writeECKeyAndCert(t, dir, "wallet-provider")
	auditKeyPath, _ := writeECKeyAndCert(t, dir, "audit")

	store := memory.NewStore()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret-that-is-at-least-32-bytes-long",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Issuer:  "https://wallet.example.com",
			KeyPath: auditKeyPath,
		},
	}
	cfg.WalletProvider.PrivateKeyPath = wpKeyPath
	cfg.WalletProvider.CertificatePath = wpCertPath
	cfg.WalletProvider.WIA = config.WIAConfig{
		Enabled:             true,
		MaxExpirySeconds:    86400,
		ChallengeTTLSeconds: 300,
	}
	cfg.WalletProvider.Attestation = config.AttestationConfig{
		LifetimeSeconds: 3600,
	}

	logger := zap.NewNop()
	services := NewServices(store, cfg, logger)

	if services.WIA == nil {
		t.Fatal("expected WIA service to be initialized")
	}
	if services.WIA.audit == nil {
		t.Error("expected WIA service to receive a real audit emitter when cfg.Audit.Enabled is true")
	}
}

// TestNewServices_WIANilWhenSigningKeyButNoCertInETSIMode is a regression
// test: a signing key alone is enough to construct WIAService (HasSigningKey
// gates construction, for "ietf" mode's sake), but "etsi" mode (the default)
// additionally requires a certificate chain (WIAService.IsSupported). Without
// this, services.WIA would be non-nil but permanently unsupported, so every
// WIA route would 500 (ErrWIANotSupported falls through to the handlers'
// generic error case) instead of the clean 503 WIA_NOT_SUPPORTED they already
// return when services.WIA == nil.
func TestNewServices_WIANilWhenSigningKeyButNoCertInETSIMode(t *testing.T) {
	dir := t.TempDir()
	wpKeyPath, _ := writeECKeyAndCert(t, dir, "wallet-provider")

	store := memory.NewStore()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret-that-is-at-least-32-bytes-long",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
	}
	cfg.WalletProvider.PrivateKeyPath = wpKeyPath
	// CertificatePath deliberately left unset - etsi mode (the zero-value
	// default) requires it; ietf mode wouldn't.
	cfg.WalletProvider.WIA = config.WIAConfig{
		Enabled:             true,
		MaxExpirySeconds:    86400,
		ChallengeTTLSeconds: 300,
	}
	cfg.WalletProvider.Attestation = config.AttestationConfig{
		LifetimeSeconds: 3600,
	}

	logger := zap.NewNop()
	services := NewServices(store, cfg, logger)

	if services.WIA != nil {
		t.Error("expected WIA service to be nil when unsupported (etsi mode, signing key but no certificate)")
	}
}
