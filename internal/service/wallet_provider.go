package service

import (
	"context"
	"crypto"
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
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

var (
	ErrKeyAttestationNotSupported = errors.New("key attestation not supported")
)

// WalletProviderService handles wallet provider operations like key attestation
type WalletProviderService struct {
	cfg       *config.Config
	logger    *zap.Logger
	signer    crypto.Signer
	jwtSigner *signing.CryptoSignerES256
	certChain []string
}

// NewWalletProviderService creates a new WalletProviderService
func NewWalletProviderService(cfg *config.Config, logger *zap.Logger) *WalletProviderService {
	svc := &WalletProviderService{
		cfg:    cfg,
		logger: logger.Named("wallet-provider-service"),
	}

	// Try PKCS#11 first, then fall back to file-based key loading
	if cfg.WalletProvider.PKCS11 != nil && cfg.WalletProvider.PKCS11.ModulePath != "" {
		keyCfg := &signing.KeyConfig{
			CertificatePath: cfg.WalletProvider.CertificatePath,
			CACertPath:      cfg.WalletProvider.CACertPath,
			PKCS11: &signing.PKCS11Config{
				ModulePath: cfg.WalletProvider.PKCS11.ModulePath,
				SlotID:     cfg.WalletProvider.PKCS11.SlotID,
				PIN:        cfg.WalletProvider.PKCS11.PIN,
				KeyLabel:   cfg.WalletProvider.PKCS11.KeyLabel,
				PoolSize:   cfg.WalletProvider.PKCS11.PoolSize,
			},
		}
		km, err := signing.LoadKeyMaterial(keyCfg)
		if err != nil {
			svc.logger.Warn("Failed to load PKCS#11 key material", zap.Error(err))
		} else {
			svc.signer = km.Signer
			svc.certChain = km.CertChain
			jwtSigner, err := signing.NewCryptoSignerES256(km.Signer)
			if err != nil {
				svc.logger.Warn("Failed to create JWT signer from PKCS#11 key", zap.Error(err))
			} else {
				svc.jwtSigner = jwtSigner
				svc.logger.Info("Loaded wallet provider keys from PKCS#11")
			}
		}
	} else if cfg.WalletProvider.PrivateKeyPath != "" && cfg.WalletProvider.CertificatePath != "" {
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
	s.signer = key

	jwtSigner, err := signing.NewCryptoSignerES256(key)
	if err != nil {
		return err
	}
	s.jwtSigner = jwtSigner

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
	return s.jwtSigner != nil && len(s.certChain) > 0
}

// SecurityProperties carries WSCD-reported security metadata for KA claims.
type SecurityProperties struct {
	KeyStorage         string   `json:"key_storage"`
	UserAuthentication []string `json:"user_authentication"`
	Certification      string   `json:"certification"`
}

// GenerateKeyAttestation generates a key attestation JWT
func (s *WalletProviderService) GenerateKeyAttestation(ctx context.Context, jwks []map[string]interface{}, nonce string, secProps *SecurityProperties) (string, error) {
	if !s.IsSupported() {
		return "", ErrKeyAttestationNotSupported
	}

	// Enrich each key with security properties if provided.
	// Clone each JWK map to avoid mutating the caller's data.
	enriched := make([]map[string]interface{}, len(jwks))
	for i, jwk := range jwks {
		clone := make(map[string]interface{}, len(jwk)+3)
		for k, v := range jwk {
			clone[k] = v
		}
		if secProps != nil {
			if secProps.KeyStorage != "" {
				clone["key_storage"] = secProps.KeyStorage
			}
			if len(secProps.UserAuthentication) > 0 {
				clone["user_authentication"] = secProps.UserAuthentication
			}
			if secProps.Certification != "" {
				clone["certification"] = secProps.Certification
			}
		}
		enriched[i] = clone
	}

	// Create the JWT claims
	now := time.Now()
	kaExpiry := time.Duration(s.cfg.WalletProvider.Attestation.KAExpirySeconds) * time.Second
	if kaExpiry == 0 {
		kaExpiry = 15 * time.Second
	}
	claims := jwt.MapClaims{
		"iss":           s.cfg.Server.BaseURL,
		"attested_keys": enriched,
		"nonce":         nonce,
		"iat":           now.Unix(),
		"exp":           now.Add(kaExpiry).Unix(),
	}

	// Create the token with ES256 and x5c header
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "keyattestation+jwt"
	token.Header["x5c"] = s.certChain

	// Sign the token via crypto.Signer (supports both file and PKCS#11)
	tokenString, err := s.jwtSigner.SignToken(token)
	if err != nil {
		s.logger.Error("Failed to sign key attestation JWT", zap.Error(err))
		kaGenerationErrors.Inc()
		return "", err
	}

	kaGeneratedTotal.Inc()
	return tokenString, nil
}
