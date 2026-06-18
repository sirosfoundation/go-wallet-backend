//go:build !pkcs11

package signing

import (
	"crypto"
	"errors"
	"io"
)

// ErrPKCS11NotSupported is returned when the binary is built without pkcs11 tag.
var ErrPKCS11NotSupported = errors.New("PKCS#11 support not compiled in (build with -tags pkcs11)")

// PKCS11Config holds configuration for a PKCS#11 token.
type PKCS11Config struct {
	ModulePath string `yaml:"module_path" envconfig:"MODULE_PATH"`
	SlotID     uint   `yaml:"slot_id" envconfig:"SLOT_ID"`
	PIN        string `yaml:"pin" envconfig:"PIN"`
	KeyLabel   string `yaml:"key_label" envconfig:"KEY_LABEL"`
	PoolSize   int    `yaml:"pool_size" envconfig:"POOL_SIZE"`
}

// NewPKCS11Signer returns an error when pkcs11 is not compiled in.
func NewPKCS11Signer(cfg *PKCS11Config) (*PKCS11Signer, error) {
	return nil, ErrPKCS11NotSupported
}

// PKCS11Signer is a stub when pkcs11 is not compiled in.
// It implements crypto.Signer to satisfy the compiler, but always panics.
type PKCS11Signer struct{}

func (s *PKCS11Signer) Public() crypto.PublicKey { panic("pkcs11 not compiled in") }
func (s *PKCS11Signer) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, ErrPKCS11NotSupported
}
func (s *PKCS11Signer) Close() error { return nil }
