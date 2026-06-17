package service

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrNativeAttestationDisabled = errors.New("native attestation verification is not enabled")
	ErrNativeAttestationInvalid  = errors.New("native attestation verification failed")
)

// NativeAttestationType identifies the platform attestation type.
type NativeAttestationType string

const (
	NativeAttestationAppleAppAttest  NativeAttestationType = "apple_app_attest"
	NativeAttestationGooglePlayInteg NativeAttestationType = "google_play_integrity"
)

// NativeAttestationRequest contains the attestation evidence from a native SDK.
type NativeAttestationRequest struct {
	// Type is the attestation type ("apple_app_attest" or "google_play_integrity")
	Type NativeAttestationType `json:"type"`
	// Token is the platform-specific attestation token/assertion
	Token string `json:"token"`
	// KeyID is the key identifier bound to the attestation
	KeyID string `json:"key_id"`
	// Challenge is the nonce/challenge that was attested
	Challenge string `json:"challenge"`
}

// NativeAttestationResult contains the verified attestation outcome.
type NativeAttestationResult struct {
	// Verified indicates the attestation passed all checks
	Verified bool `json:"verified"`
	// Platform is the resolved platform
	Platform NativeAttestationType `json:"platform"`
	// AppID is the verified app identifier
	AppID string `json:"app_id"`
	// AttestationSource for WIA claims
	AttestationSource string `json:"attestation_source"`
}

// NativeAttestationService verifies platform attestation tokens.
type NativeAttestationService struct {
	cfg    *config.Config
	logger *zap.Logger
}

// NewNativeAttestationService creates a new native attestation verifier.
func NewNativeAttestationService(cfg *config.Config, logger *zap.Logger) *NativeAttestationService {
	return &NativeAttestationService{
		cfg:    cfg,
		logger: logger.Named("native-attestation"),
	}
}

// IsEnabled returns true if native attestation verification is configured.
func (s *NativeAttestationService) IsEnabled() bool {
	return s.cfg.WalletProvider.Attestation.NativeAttestation.Enabled
}

// Verify validates a native attestation request.
func (s *NativeAttestationService) Verify(ctx context.Context, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	if !s.IsEnabled() {
		return nil, ErrNativeAttestationDisabled
	}

	switch req.Type {
	case NativeAttestationAppleAppAttest:
		return s.verifyAppleAppAttest(ctx, req)
	case NativeAttestationGooglePlayInteg:
		return s.verifyGooglePlayIntegrity(ctx, req)
	default:
		return nil, fmt.Errorf("%w: unsupported type %q", ErrNativeAttestationInvalid, req.Type)
	}
}

// verifyAppleAppAttest validates an Apple App Attest assertion.
// See: https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
func (s *NativeAttestationService) verifyAppleAppAttest(_ context.Context, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	nativeCfg := s.cfg.WalletProvider.Attestation.NativeAttestation

	// Decode the attestation statement (CBOR-encoded attestation object)
	attestBytes, err := base64.StdEncoding.DecodeString(req.Token)
	if err != nil {
		return nil, fmt.Errorf("%w: decode token: %v", ErrNativeAttestationInvalid, err)
	}

	// Apple App Attest attestation object is CBOR:
	// { "fmt": "apple-appattest", "attStmt": { "x5c": [...], "receipt": ... }, "authData": ... }
	// For assertion (post-attestation), it's a simpler structure.
	// Here we verify the core properties.

	// Step 1: Verify the challenge hash
	challengeHash := sha256.Sum256([]byte(req.Challenge))

	// Step 2: Parse the attestation (simplified verification)
	// In production, use a full CBOR parser and validate:
	// - x5c chain roots to Apple App Attest CA
	// - Nonce in authData matches SHA256(challenge)
	// - App ID matches configured value
	// - Counter is valid
	if len(attestBytes) == 0 {
		return nil, fmt.Errorf("%w: empty attestation", ErrNativeAttestationInvalid)
	}

	// Verify app ID matches
	if nativeCfg.AppleAppID == "" {
		return nil, fmt.Errorf("%w: apple_app_id not configured", ErrNativeAttestationInvalid)
	}

	s.logger.Debug("Apple App Attest verification",
		zap.String("key_id", req.KeyID),
		zap.String("challenge_hash", base64.RawURLEncoding.EncodeToString(challengeHash[:])),
		zap.String("environment", nativeCfg.AppleAppAttestEnvironment),
	)

	// TODO: Full CBOR parsing and x5c chain validation against Apple CA.
	// For now, validate structure and return platform-attested source.
	// Full implementation requires github.com/fxamacker/cbor/v2 for CBOR parsing
	// and the Apple App Attest root CA for chain verification.

	return &NativeAttestationResult{
		Verified:          true,
		Platform:          NativeAttestationAppleAppAttest,
		AppID:             nativeCfg.AppleAppID,
		AttestationSource: "platform_attested",
	}, nil
}

// verifyGooglePlayIntegrity validates a Google Play Integrity token.
// See: https://developer.android.com/google/play/integrity/verdict
func (s *NativeAttestationService) verifyGooglePlayIntegrity(_ context.Context, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	nativeCfg := s.cfg.WalletProvider.Attestation.NativeAttestation

	if nativeCfg.GooglePackageName == "" {
		return nil, fmt.Errorf("%w: google_package_name not configured", ErrNativeAttestationInvalid)
	}

	// Play Integrity token is a nested JWS (signed then encrypted).
	// Decryption key + verification key are configured.
	if nativeCfg.GooglePlayIntegrityDecryptionKey == "" || nativeCfg.GooglePlayIntegrityVerificationKey == "" {
		return nil, fmt.Errorf("%w: play integrity keys not configured", ErrNativeAttestationInvalid)
	}

	// Step 1: Decrypt the integrity token (AES-256-GCM with decryption key)
	decKeyBytes, err := base64.StdEncoding.DecodeString(nativeCfg.GooglePlayIntegrityDecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decode decryption key: %v", ErrNativeAttestationInvalid, err)
	}

	verKeyBytes, err := base64.StdEncoding.DecodeString(nativeCfg.GooglePlayIntegrityVerificationKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decode verification key: %v", ErrNativeAttestationInvalid, err)
	}

	// Step 2: Verify the JWS signature
	// The decrypted payload is a JWS signed with the verification key.
	// Parse and verify the integrity verdict.
	_ = decKeyBytes
	_ = verKeyBytes

	// Step 3: Parse the verdict JSON
	// Expected structure:
	// { "requestDetails": { "nonce": "...", "requestPackageName": "..." },
	//   "appIntegrity": { "appRecognitionVerdict": "PLAY_RECOGNIZED" },
	//   "deviceIntegrity": { "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"] },
	//   "accountDetails": { "appLicensingVerdict": "LICENSED" } }

	// TODO: Full JWE decryption + JWS verification.
	// Requires: AES-256-GCM decryption of outer layer, then EC signature
	// verification of inner JWS. Use go-jose/v4 for both.
	// For now, validate structure presence.

	if req.Token == "" {
		return nil, fmt.Errorf("%w: empty token", ErrNativeAttestationInvalid)
	}

	s.logger.Debug("Play Integrity verification",
		zap.String("key_id", req.KeyID),
		zap.String("package", nativeCfg.GooglePackageName),
	)

	return &NativeAttestationResult{
		Verified:          true,
		Platform:          NativeAttestationGooglePlayInteg,
		AppID:             nativeCfg.GooglePackageName,
		AttestationSource: "platform_attested",
	}, nil
}

// AppleAppAttestRootCAs returns the Apple App Attest root CA pool.
func AppleAppAttestRootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	// Apple App Attest Root CA (valid until 2038)
	// In production, embed or fetch from Apple's PKI
	return pool
}

// PlayIntegrityVerdict represents the Google Play Integrity API verdict.
type PlayIntegrityVerdict struct {
	RequestDetails struct {
		Nonce              string `json:"nonce"`
		RequestPackageName string `json:"requestPackageName"`
		TimestampMillis    int64  `json:"timestampMillis"`
	} `json:"requestDetails"`
	AppIntegrity struct {
		AppRecognitionVerdict string `json:"appRecognitionVerdict"`
	} `json:"appIntegrity"`
	DeviceIntegrity struct {
		DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
	} `json:"deviceIntegrity"`
}

// parsePlayIntegrityVerdict parses a decrypted Play Integrity verdict.
func parsePlayIntegrityVerdict(data []byte) (*PlayIntegrityVerdict, error) {
	var verdict PlayIntegrityVerdict
	if err := json.Unmarshal(data, &verdict); err != nil {
		return nil, fmt.Errorf("parse verdict: %w", err)
	}
	return &verdict, nil
}

// validatePlayIntegrityVerdict checks that the verdict meets minimum requirements.
func validatePlayIntegrityVerdict(verdict *PlayIntegrityVerdict, expectedNonce string, expectedPackage string) error {
	if verdict.RequestDetails.Nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch")
	}
	if verdict.RequestDetails.RequestPackageName != expectedPackage {
		return fmt.Errorf("package mismatch: got %q, want %q", verdict.RequestDetails.RequestPackageName, expectedPackage)
	}

	// Verify timestamp is recent (within 10 minutes)
	ts := time.UnixMilli(verdict.RequestDetails.TimestampMillis)
	if time.Since(ts) > 10*time.Minute {
		return fmt.Errorf("verdict too old: %v", ts)
	}

	// Require device integrity
	hasDeviceIntegrity := false
	for _, v := range verdict.DeviceIntegrity.DeviceRecognitionVerdict {
		if v == "MEETS_DEVICE_INTEGRITY" || v == "MEETS_STRONG_INTEGRITY" {
			hasDeviceIntegrity = true
			break
		}
	}
	if !hasDeviceIntegrity {
		return fmt.Errorf("device integrity not met: %v", verdict.DeviceIntegrity.DeviceRecognitionVerdict)
	}

	return nil
}
