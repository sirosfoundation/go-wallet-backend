package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

var (
	ErrKeyAttestationNotSupported = errors.New("key attestation not supported")
)

// statusIndexCounter is a process-scoped monotonic counter for status list indices.
// Each attestation (WIA or KA) gets a unique index. In a multi-instance deployment,
// each instance maintains its own counter range — uniqueness across instances must
// be ensured by configuring non-overlapping StatusListIndexOffset values or by
// using an external allocator behind the StatusListURL endpoint.
var statusIndexCounter atomic.Uint64

// MaxJWKSPerRequest is the hard upper bound on JWKs in a single KA request.
// Prevents DoS via expensive JWT signing with excessively large arrays.
const MaxJWKSPerRequest = 20

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
				// Close the underlying signer to release PKCS#11 session
				if closer, ok := km.Signer.(interface{ Close() error }); ok {
					_ = closer.Close()
				}
				svc.signer = nil
				svc.certChain = nil
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

	// Validate PEM block type before parsing
	switch block.Type {
	case "EC PRIVATE KEY", "PRIVATE KEY":
		// accepted types
	default:
		return fmt.Errorf("unexpected PEM block type %q, expected EC PRIVATE KEY or PRIVATE KEY", block.Type)
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

	// Load certificate chain using proper PEM parsing
	s.certChain, err = parsePEMCertChain(s.cfg.WalletProvider.CertificatePath)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	// Optionally load CA cert for the chain
	if s.cfg.WalletProvider.CACertPath != "" {
		caCerts, err := parsePEMCertChain(s.cfg.WalletProvider.CACertPath)
		if err != nil {
			s.logger.Warn("Failed to load CA certificate", zap.Error(err))
		} else {
			s.certChain = append(s.certChain, caCerts...)
		}
	}

	s.logger.Info("Loaded wallet provider keys")
	return nil
}

// parsePEMCertChain reads a PEM file and returns base64-encoded DER certificates
// suitable for the x5c JWT header. Uses proper PEM parsing instead of string
// manipulation.
func parsePEMCertChain(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var chain []string
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, base64.StdEncoding.EncodeToString(block.Bytes))
		}
		data = rest
	}
	if len(chain) == 0 {
		return nil, errors.New("no CERTIFICATE PEM blocks found")
	}
	return chain, nil
}

// IsSupported returns true if key attestation is supported
func (s *WalletProviderService) IsSupported() bool {
	return s.jwtSigner != nil && len(s.certChain) > 0
}

// SecurityProperties carries WSCD-reported security metadata for KA claims.
// These become top-level KA JWT claims per Annex C §C.3.1.
type SecurityProperties struct {
	// KeyStorage is the key storage security level (e.g., ["iso_18045_high"]).
	KeyStorage []string `json:"key_storage"`
	// UserAuthentication is the user auth mechanism (e.g., ["iso_18045_high"]).
	UserAuthentication []string `json:"user_authentication"`
	// Certification describes the certification status.
	// String "none" for no certification, or an object like
	// {"scheme":"EUCC","assurance_level":"substantial"} for certified devices.
	Certification interface{} `json:"certification"`
}

// GenerateKeyAttestation generates a key attestation JWT.
// The walletInstanceID is the JWK Thumbprint from the WIA (binds KA to wallet instance).
// The audience is the credential endpoint URL of the target issuer.
func (s *WalletProviderService) GenerateKeyAttestation(ctx context.Context, jwks []map[string]interface{}, nonce string, secProps *SecurityProperties, walletInstanceID string, audience string) (string, error) {
	if !s.IsSupported() {
		return "", ErrKeyAttestationNotSupported
	}
	start := time.Now()
	defer func() { kaGenerationDuration.Observe(time.Since(start).Seconds()) }()

	// Clone each JWK map to avoid mutating the caller's data.
	attested := make([]map[string]interface{}, len(jwks))
	for i, jwk := range jwks {
		clone := make(map[string]interface{}, len(jwk))
		for k, v := range jwk {
			clone[k] = v
		}
		attested[i] = clone
	}

	// Create the JWT claims
	now := time.Now()
	kaExpiry := time.Duration(s.cfg.WalletProvider.Attestation.KAExpirySeconds) * time.Second
	if kaExpiry <= 0 {
		kaExpiry = 15 * time.Second
	}
	claims := jwt.MapClaims{
		"iss":           s.cfg.Server.BaseURL,
		"jti":           uuid.New().String(),
		"attested_keys": attested,
		"nonce":         nonce,
		"iat":           now.Unix(),
		"exp":           now.Add(kaExpiry).Unix(),
	}

	// Bind KA to the wallet instance (CS-04 §7.1.3)
	if walletInstanceID != "" {
		claims["sub"] = walletInstanceID
	}

	// Scope KA to the target issuer (prevents cross-issuer replay)
	if audience != "" {
		claims["aud"] = audience
	}

	// Security properties are top-level KA claims (Annex C §C.3.1)
	if secProps != nil {
		if len(secProps.KeyStorage) > 0 {
			claims["key_storage"] = secProps.KeyStorage
		}
		if len(secProps.UserAuthentication) > 0 {
			claims["user_authentication"] = secProps.UserAuthentication
		}
		if secProps.Certification != nil {
			claims["certification"] = secProps.Certification
		}
	}

	// key_storage_status: KA revocation via Token Status List (CS-04 §7.1.3)
	if s.cfg.WalletProvider.Attestation.StatusListMode == "always" && s.cfg.WalletProvider.Attestation.StatusListURL != "" {
		idx := statusIndexCounter.Add(1)
		ksStatus := map[string]interface{}{
			"status": map[string]interface{}{
				"status_list": map[string]interface{}{
					"uri": s.cfg.WalletProvider.Attestation.StatusListURL,
					"idx": idx,
				},
			},
		}
		if s.cfg.WalletProvider.Attestation.StatusListExpiry > 0 {
			ksStatus["exp"] = now.Add(time.Duration(s.cfg.WalletProvider.Attestation.StatusListExpiry) * time.Second).Unix()
		}
		claims["key_storage_status"] = ksStatus
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
