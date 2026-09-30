//go:build pkcs11

package signing

import (
	"crypto"
	"io"
	"time"

	"github.com/sirosfoundation/go-cryptoutil/pkcs11pool"
)

// PKCS11Config holds configuration for a PKCS#11 token.
type PKCS11Config struct {
	ModulePath string `yaml:"module_path" envconfig:"MODULE_PATH"`
	SlotID     uint   `yaml:"slot_id" envconfig:"SLOT_ID"`
	PIN        string `yaml:"pin" envconfig:"PIN"`
	KeyLabel   string `yaml:"key_label" envconfig:"KEY_LABEL"`
	PoolSize   int    `yaml:"pool_size" envconfig:"POOL_SIZE"` // Number of sessions (default 4)
}

// PKCS11Signer implements crypto.Signer backed by a PKCS#11 token.
// It delegates to pkcs11pool for session management and signing.
type PKCS11Signer struct {
	pool   *pkcs11pool.Pool
	signer *pkcs11pool.Signer
}

// NewPKCS11Signer creates a signer backed by a PKCS#11 token.
func NewPKCS11Signer(cfg *PKCS11Config) (*PKCS11Signer, error) {
	pool, err := pkcs11pool.New(pkcs11pool.Config{
		ModulePath: cfg.ModulePath,
		SlotID:     cfg.SlotID,
		PIN:        cfg.PIN,
		PoolSize:   cfg.PoolSize,
	})
	if err != nil {
		return nil, err
	}

	signer, err := pkcs11pool.NewSigner(pool, pkcs11pool.KeyByLabel(cfg.KeyLabel))
	if err != nil {
		pool.Close()
		return nil, err
	}

	return &PKCS11Signer{pool: pool, signer: signer}, nil
}

// Public returns the public key stored on the token.
func (s *PKCS11Signer) Public() crypto.PublicKey {
	return s.signer.Public()
}

// Sign implements crypto.Signer with Prometheus metrics instrumentation.
func (s *PKCS11Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	start := time.Now()

	sig, err := s.signer.Sign(rand, digest, opts)

	pkcs11SignDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		pkcs11SignErrors.Inc()
		return nil, err
	}
	pkcs11SignTotal.Inc()
	return sig, nil
}

// Close releases the PKCS#11 session pool and context.
func (s *PKCS11Signer) Close() error {
	return s.pool.Close()
}
