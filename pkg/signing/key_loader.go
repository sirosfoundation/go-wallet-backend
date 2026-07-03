package signing

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// KeyMaterial holds a loaded signing key and its certificate chain.
type KeyMaterial struct {
	// Signer is a crypto.Signer — either a file-based *ecdsa.PrivateKey or
	// a PKCS#11-backed signer.
	Signer crypto.Signer
	// CertChain is the base64-encoded certificate chain for x5c headers.
	CertChain []string
}

// KeyConfig configures how to load signing material.
type KeyConfig struct {
	// File-based key loading
	PrivateKeyPath  string `yaml:"private_key_path" envconfig:"PRIVATE_KEY_PATH"`
	CertificatePath string `yaml:"certificate_path" envconfig:"CERTIFICATE_PATH"`
	CACertPath      string `yaml:"ca_cert_path" envconfig:"CA_CERT_PATH"`
	// PKCS#11-based key loading (takes precedence when configured)
	PKCS11 *PKCS11Config `yaml:"pkcs11,omitempty" envconfig:"PKCS11"`
}

// LoadKeyMaterial loads signing key material from either PKCS#11 or file.
// PKCS#11 takes precedence if configured.
func LoadKeyMaterial(cfg *KeyConfig) (*KeyMaterial, error) {
	if cfg.PKCS11 != nil && cfg.PKCS11.ModulePath != "" {
		return loadFromPKCS11(cfg)
	}
	return loadFromFile(cfg)
}

func loadFromPKCS11(cfg *KeyConfig) (*KeyMaterial, error) {
	if cfg.CertificatePath == "" {
		return nil, errors.New("certificate_path is required for PKCS#11 mode (x5c chain)")
	}

	signer, err := NewPKCS11Signer(cfg.PKCS11)
	if err != nil {
		return nil, fmt.Errorf("pkcs11 signer: %w", err)
	}

	// Certificate chain still comes from file
	chain, err := loadCertChain(cfg.CertificatePath, cfg.CACertPath)
	if err != nil {
		_ = signer.Close()
		return nil, fmt.Errorf("load cert chain: %w", err)
	}

	return &KeyMaterial{Signer: signer, CertChain: chain}, nil
}

func loadFromFile(cfg *KeyConfig) (*KeyMaterial, error) {
	if cfg.PrivateKeyPath == "" || cfg.CertificatePath == "" {
		return nil, errors.New("private_key_path and certificate_path are required")
	}

	keyPEM, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	// Strip \r so CRLF line endings don't break PEM decoding.
	keyPEM = bytes.ReplaceAll(keyPEM, []byte("\r"), nil)

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		var ok bool
		key, ok = pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
	}

	chain, err := loadCertChain(cfg.CertificatePath, cfg.CACertPath)
	if err != nil {
		return nil, err
	}

	return &KeyMaterial{Signer: key, CertChain: chain}, nil
}

func loadCertChain(certPath, caPath string) ([]string, error) {
	chain, err := parsePEMCerts(certPath)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", certPath)
	}

	if caPath != "" {
		caCerts, err := parsePEMCerts(caPath)
		if err == nil && len(caCerts) > 0 {
			chain = append(chain, caCerts...)
		}
	}

	return chain, nil
}

// parsePEMCerts reads a PEM file and returns all CERTIFICATE blocks as
// base64-encoded DER strings (suitable for x5c JWT headers per RFC 7515 §4.1.6).
func parsePEMCerts(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", path, err)
	}

	// Strip \r so CRLF line endings don't break PEM decoding.
	data = bytes.ReplaceAll(data, []byte("\r"), nil)

	var certs []string
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certs = append(certs, base64.StdEncoding.EncodeToString(block.Bytes))
	}
	return certs, nil
}
