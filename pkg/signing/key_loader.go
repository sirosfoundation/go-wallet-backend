package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
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
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}

	certStr := string(certPEM)
	certStr = strings.ReplaceAll(certStr, "-----BEGIN CERTIFICATE-----", "")
	certStr = strings.ReplaceAll(certStr, "-----END CERTIFICATE-----", "")
	certStr = strings.ReplaceAll(certStr, "\r\n", "\n")
	certStr = strings.ReplaceAll(certStr, "\r", "")
	certStr = strings.ReplaceAll(certStr, "\n", "")
	certStr = strings.TrimSpace(certStr)

	chain := []string{certStr}

	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err == nil {
			caStr := string(caPEM)
			caStr = strings.ReplaceAll(caStr, "-----BEGIN CERTIFICATE-----", "")
			caStr = strings.ReplaceAll(caStr, "-----END CERTIFICATE-----", "")
			caStr = strings.ReplaceAll(caStr, "\r\n", "\n")
			caStr = strings.ReplaceAll(caStr, "\r", "")
			caStr = strings.ReplaceAll(caStr, "\n", "")
			caStr = strings.TrimSpace(caStr)
			if caStr != "" {
				chain = append(chain, caStr)
			}
		}
	}

	return chain, nil
}
