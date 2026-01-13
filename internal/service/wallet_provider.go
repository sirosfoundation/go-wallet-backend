package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrKeyAttestationNotSupported = errors.New("key attestation not supported")
)

// WalletProviderService handles wallet provider operations like key attestation
type WalletProviderService struct {
	cfg        *config.Config
	logger     *zap.Logger
	privateKey *ecdsa.PrivateKey
	certChain  []string
}

// NewWalletProviderService creates a new WalletProviderService
func NewWalletProviderService(cfg *config.Config, logger *zap.Logger) *WalletProviderService {
	svc := &WalletProviderService{
		cfg:    cfg,
		logger: logger.Named("wallet-provider-service"),
	}

	// Try to load keys if paths are configured
	if cfg.WalletProvider.PrivateKeyPath != "" && cfg.WalletProvider.CertificatePath != "" {
		if err := svc.loadKeys(); err != nil {
			svc.logger.Warn("Failed to load wallet provider keys", zap.Error(err))
		}
	}

	return svc
}

func (s *WalletProviderService) loadKeys() error {
	// Load private key
	keyPEM, err := os.ReadFile(s.cfg.WalletProvider.PrivateKeyPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return err
		}
		var ok bool
		key, ok = pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("not an ECDSA private key")
		}
	}
	s.privateKey = key

	// Load certificate
	certPEM, err := os.ReadFile(s.cfg.WalletProvider.CertificatePath)
	if err != nil {
		return err
	}

	// Extract the base64 content from the certificate
	certStr := string(certPEM)
	certStr = strings.ReplaceAll(certStr, "-----BEGIN CERTIFICATE-----", "")
	certStr = strings.ReplaceAll(certStr, "-----END CERTIFICATE-----", "")
	certStr = strings.ReplaceAll(certStr, "\n", "")
	certStr = strings.TrimSpace(certStr)

	s.certChain = []string{certStr}

	// Optionally load CA cert for the chain
	if s.cfg.WalletProvider.CACertPath != "" {
		caPEM, err := os.ReadFile(s.cfg.WalletProvider.CACertPath)
		if err == nil {
			caStr := string(caPEM)
			caStr = strings.ReplaceAll(caStr, "-----BEGIN CERTIFICATE-----", "")
			caStr = strings.ReplaceAll(caStr, "-----END CERTIFICATE-----", "")
			caStr = strings.ReplaceAll(caStr, "\n", "")
			caStr = strings.TrimSpace(caStr)
			if caStr != "" {
				s.certChain = append(s.certChain, caStr)
			}
		}
	}

	s.logger.Info("Loaded wallet provider keys")
	return nil
}

// IsSupported returns true if key attestation is supported
func (s *WalletProviderService) IsSupported() bool {
	return s.privateKey != nil && len(s.certChain) > 0
}

// GenerateKeyAttestation generates a key attestation JWT
func (s *WalletProviderService) GenerateKeyAttestation(ctx context.Context, jwks []map[string]interface{}, nonce string) (string, error) {
	if !s.IsSupported() {
		return "", ErrKeyAttestationNotSupported
	}

	// Create the JWT claims
	now := time.Now()
	claims := jwt.MapClaims{
		"attested_keys": jwks,
		"nonce":         nonce,
		"iat":           now.Unix(),
		"exp":           now.Add(15 * time.Second).Unix(),
	}

	// Create the token with ES256 and x5c header
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "keyattestation+jwt"
	token.Header["x5c"] = s.certChain

	// Sign the token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		s.logger.Error("Failed to sign key attestation JWT", zap.Error(err))
		return "", err
	}

	return tokenString, nil
}
