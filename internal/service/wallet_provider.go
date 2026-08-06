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
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

var (
	ErrKeyAttestationNotSupported = errors.New("key attestation not supported")
)

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
	instances storage.WalletInstanceStore
}

// NewWalletProviderService creates a new WalletProviderService.
// instances is used to corroborate a KA request's self-reported security
// properties against a WIA that already proved native platform integrity
// for the same wallet instance (see GenerateKeyAttestation) — may be nil in
// tests that don't exercise that path.
func NewWalletProviderService(cfg *config.Config, logger *zap.Logger, instances storage.WalletInstanceStore) *WalletProviderService {
	svc := &WalletProviderService{
		cfg:       cfg,
		logger:    logger.Named("wallet-provider-service"),
		instances: instances,
	}

	// Try PKCS#11 first, then fall back to file-based key loading if PKCS#11
	// wasn't configured OR failed to load. These are deliberately independent
	// checks (not if/else-if) — an else-if would mean a configured file-key
	// fallback is never even attempted when PKCS#11 is configured but fails
	// at runtime (HSM unreachable, wrong PIN, built without -tags pkcs11),
	// leaving the service with no signing key at all instead of the working
	// fallback the operator configured.
	pkcs11Loaded := false
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
				pkcs11Loaded = true
			}
		}
	}
	if !pkcs11Loaded && cfg.WalletProvider.PrivateKeyPath != "" {
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

	// CertificatePath is optional: a signing key alone is enough for
	// "ietf"-mode WIA issuance (JWKS-based trust, no x5c — see
	// WIAConfig.Mode). Key Attestation (KA) and "etsi"-mode WIA always
	// require x5c, which config.Validate() enforces by requiring a
	// certificate whenever wallet_provider.wia.mode is "etsi"; without one,
	// IsSupported() (KA) correctly reports unsupported and only WIAService's
	// own ietf-mode IsSupported() can be true.
	if s.cfg.WalletProvider.CertificatePath == "" {
		s.logger.Info("Loaded wallet provider signing key (no certificate configured; x5c/KA unavailable)")
		return nil
	}

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

// IsSupported returns true if Key Attestation (KA) generation is supported.
// KA always requires x5c (there is no "ietf mode" for KA — see
// GenerateKeyAttestation), so this deliberately requires a certificate chain,
// unlike HasSigningKey.
func (s *WalletProviderService) IsSupported() bool {
	return s.jwtSigner != nil && len(s.certChain) > 0
}

// HasSigningKey returns true if a signing key (file or PKCS#11) is loaded,
// regardless of whether a certificate/x5c chain is also configured. Used to
// gate WIA-only ("ietf" mode) functionality, which doesn't need x5c — unlike
// IsSupported, which additionally requires a certificate for KA.
func (s *WalletProviderService) HasSigningKey() bool {
	return s.jwtSigner != nil
}

// PublicKey returns the wallet provider's signing public key, or nil if no
// signing key is configured. Used to serve the wallet provider's own JWKS
// (see RegisterWalletProviderJWKSRoute) for relying parties resolving trust
// via an iss-based (WIA.Mode == config.WIAModeIETF) attestation instead of
// its x5c chain.
func (s *WalletProviderService) PublicKey() crypto.PublicKey {
	if s.signer == nil {
		return nil
	}
	return s.signer.Public()
}

// Issuer returns the value used as the WIA's iss claim (see WIAService's
// GenerateWIA), so relying parties' RFC 8414 metadata discovery
// (RegisterWalletProviderJWKSRoute) advertises the exact issuer the WIA
// itself claims. No WalletProviderURI fallback: config.Validate() requires
// WIA.Issuer to be explicitly set whenever Mode is "ietf" (the only mode
// that calls this), so falling back here would only mask a config that
// bypassed Validate() (e.g. constructed directly in tests) - and
// WalletProviderURI is a different identifier for a different purpose (the
// WIA-PoP's expected aud, not this wallet provider's own issuer identity;
// see docs/wallet-instance-attestation.md).
func (s *WalletProviderService) Issuer() string {
	return s.cfg.WalletProvider.WIA.Issuer
}

// Close releases resources held by the service.
// For PKCS#11 signers, this closes the token session pool.
func (s *WalletProviderService) Close() {
	if closer, ok := s.signer.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
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
		// No `iss`: EC TS03 v1.5.2 removed `iss` from the KA (as it did for
		// the WIA) — Wallet Provider identity is inferred solely from the
		// x5c signing certificate below.
		"jti":           uuid.New().String(),
		"attested_keys": attested,
		// c_nonce (not `nonce`): TS03 §2.3.2 requires a KA sent via the
		// `attestation` proof type to carry `c_nonce`. When a KA is instead
		// wrapped in the `jwt` proof type, the nonce belongs in the outer
		// proof JWT's body (built client-side), not here — this claim is
		// then unused by conformant verifiers but harmless to include.
		"c_nonce": nonce,
		"iat":     now.Unix(),
		"exp":     now.Add(kaExpiry).Unix(),
	}

	// Bind KA to the wallet instance (CS-04 §7.1.3)
	if walletInstanceID != "" {
		claims["sub"] = walletInstanceID
	}

	// Scope KA to the target issuer (prevents cross-issuer replay)
	if audience != "" {
		claims["aud"] = audience
	}

	// Security properties are top-level KA claims (Annex C §C.3.1). These are
	// self-reported by the client — trust them only when the same wallet
	// instance already has a WIA proving native platform integrity
	// (Tier 1: ios_app_attest / android_play_integrity). Otherwise clamp to
	// the software/K3 floor: a client can always claim more than it can
	// back up, and nothing here independently verifies a hardware or
	// remote-HSM claim. See internal/service/wallet_provider_test.go for
	// the regression tests this guards.
	if secProps != nil {
		trusted := s.instanceHasNativeAttestation(ctx, walletInstanceID)
		normalized := normalizeSecurityProperties(secProps, trusted)
		if len(normalized.KeyStorage) > 0 {
			claims["key_storage"] = normalized.KeyStorage
		}
		if len(normalized.UserAuthentication) > 0 {
			claims["user_authentication"] = normalized.UserAuthentication
		}
		if normalized.Certification != nil {
			claims["certification"] = normalized.Certification
		}
	}

	// No `key_storage_status`: this wallet provider does not implement
	// KA/WIA revocation-chaining. See AttestationConfig's type-level comment
	// for the design rationale (short KA/WIA lifetime instead).

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

// nativeAttestationSources are the WalletInstance.AttestationSource values
// that indicate the wallet's Tier 1 WIA was backed by verified platform
// attestation (iOS App Attest or Android Play Integrity) — i.e. an
// independent signal that the instance's runtime integrity was checked,
// which corroborates (though doesn't cryptographically prove) an elevated
// key_storage/certification claim for that same instance.
var nativeAttestationSources = map[string]bool{
	"ios_app_attest":         true,
	"android_play_integrity": true,
}

// instanceHasNativeAttestation reports whether walletInstanceID resolves to
// a WalletInstance whose WIA was backed by verified native platform
// attestation. Returns false on a missing ID, an unknown instance, a
// lookup error, or a nil instance store (e.g. in tests that construct
// WalletProviderService directly) — all of which mean there's no evidence
// to corroborate an elevated claim, not that one should be granted.
func (s *WalletProviderService) instanceHasNativeAttestation(ctx context.Context, walletInstanceID string) bool {
	if s.instances == nil || walletInstanceID == "" {
		return false
	}
	instance, err := s.instances.GetByID(ctx, walletInstanceID)
	if err != nil {
		if !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("failed to look up wallet instance for KA trust check", zap.Error(err))
		}
		return false
	}
	return nativeAttestationSources[instance.AttestationSource]
}

// isoAttackPotential maps SIROS's internal WSCD key-storage/user-auth
// vocabulary onto the OID4VCI Key Attestation JWT's registered
// `iso_18045_*` attack-potential-resistance values. Mirrors the mapping
// already used client-side in the Kotlin/Swift SDKs' self-signed fallback
// path (WscdKeystoreAdapter.toIso18045AttackPotential) — kept in sync so
// the same raw value maps the same way regardless of which side does it.
// Mappings are necessarily approximate; conservative/lower tiers are
// preferred over overclaiming resistance that hasn't been verified.
func isoAttackPotential(raw string, omitIfNone bool) (string, bool) {
	if strings.HasPrefix(raw, "iso_18045_") {
		return raw, true // already spec-compliant, pass through
	}
	switch strings.ToLower(raw) {
	case "none":
		if omitIfNone {
			return "", false
		}
		return "iso_18045_basic", true
	case "software":
		return "iso_18045_basic", true
	case "hardware":
		return "iso_18045_moderate", true
	case "trusted_execution":
		return "iso_18045_enhanced-basic", true
	case "remote_hsm":
		return "iso_18045_high", true
	default:
		return "iso_18045_basic", true
	}
}

// normalizeSecurityProperties maps secProps onto the registered
// `iso_18045_*` vocabulary and, when trusted is false, clamps every claim
// down to the software/K3 floor regardless of what the client asserted.
func normalizeSecurityProperties(secProps *SecurityProperties, trusted bool) *SecurityProperties {
	if !trusted {
		return &SecurityProperties{
			KeyStorage:    []string{"iso_18045_basic"},
			Certification: "none",
		}
	}

	out := &SecurityProperties{Certification: secProps.Certification}
	out.KeyStorage = mapDistinct(secProps.KeyStorage, false)
	if len(out.KeyStorage) == 0 {
		out.KeyStorage = []string{"iso_18045_basic"}
	}
	out.UserAuthentication = mapDistinct(secProps.UserAuthentication, true)
	return out
}

// mapDistinct applies isoAttackPotential to each value, dropping omitted
// entries and de-duplicating (matching the Kotlin/Swift SDKs' .distinct()).
func mapDistinct(raw []string, omitIfNone bool) []string {
	seen := make(map[string]bool, len(raw))
	var out []string
	for _, v := range raw {
		mapped, ok := isoAttackPotential(v, omitIfNone)
		if !ok || seen[mapped] {
			continue
		}
		seen[mapped] = true
		out = append(out, mapped)
	}
	return out
}
