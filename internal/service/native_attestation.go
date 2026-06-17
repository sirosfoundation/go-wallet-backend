package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-jose/go-jose/v4"
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

// appleAppAttestAttestation represents the CBOR attestation object from App Attest.
type appleAppAttestAttestation struct {
	Fmt      string                        `cbor:"fmt"`
	AttStmt  appleAppAttestAttestStatement `cbor:"attStmt"`
	AuthData []byte                        `cbor:"authData"`
}

// appleAppAttestAttestStatement is the attestation statement within the CBOR object.
type appleAppAttestAttestStatement struct {
	X5C     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

// verifyAppleAppAttest validates an Apple App Attest attestation object.
// See: https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
func (s *NativeAttestationService) verifyAppleAppAttest(_ context.Context, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	nativeCfg := s.cfg.WalletProvider.Attestation.NativeAttestation

	if nativeCfg.AppleAppID == "" {
		return nil, fmt.Errorf("%w: apple_app_id not configured", ErrNativeAttestationInvalid)
	}

	// Decode the attestation object
	attestBytes, err := base64.StdEncoding.DecodeString(req.Token)
	if err != nil {
		return nil, fmt.Errorf("%w: decode token: %v", ErrNativeAttestationInvalid, err)
	}
	if len(attestBytes) == 0 {
		return nil, fmt.Errorf("%w: empty attestation", ErrNativeAttestationInvalid)
	}

	// Step 1: CBOR-decode the attestation object
	var attestObj appleAppAttestAttestation
	if err := cbor.Unmarshal(attestBytes, &attestObj); err != nil {
		return nil, fmt.Errorf("%w: cbor decode: %v", ErrNativeAttestationInvalid, err)
	}

	// Step 2: Verify format
	if attestObj.Fmt != "apple-appattest" {
		return nil, fmt.Errorf("%w: unexpected fmt %q", ErrNativeAttestationInvalid, attestObj.Fmt)
	}

	// Step 3: Verify x5c chain
	if len(attestObj.AttStmt.X5C) < 2 {
		return nil, fmt.Errorf("%w: x5c chain too short (%d certs)", ErrNativeAttestationInvalid, len(attestObj.AttStmt.X5C))
	}

	// Parse the leaf certificate
	leafCert, err := x509.ParseCertificate(attestObj.AttStmt.X5C[0])
	if err != nil {
		return nil, fmt.Errorf("%w: parse leaf cert: %v", ErrNativeAttestationInvalid, err)
	}

	// Build intermediates pool
	intermediates := x509.NewCertPool()
	for _, certDER := range attestObj.AttStmt.X5C[1:] {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("%w: parse intermediate: %v", ErrNativeAttestationInvalid, err)
		}
		intermediates.AddCert(cert)
	}

	// Verify chain against Apple App Attest root CA
	roots := AppleAppAttestRootCAs()
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		// In development environment, log warning but continue
		if nativeCfg.AppleAppAttestEnvironment == "development" {
			s.logger.Warn("App Attest x5c chain verification failed (development mode)", zap.Error(err))
		} else {
			return nil, fmt.Errorf("%w: x5c chain verification: %v", ErrNativeAttestationInvalid, err)
		}
	}

	// Step 4: Verify the nonce in authData
	// authData structure: rpIdHash (32) || flags (1) || signCount (4) || attestedCredData (...)
	// The nonce is SHA256(authData || SHA256(clientDataJSON))
	// For App Attest, clientDataHash = SHA256(challenge)
	if len(attestObj.AuthData) < 37 {
		return nil, fmt.Errorf("%w: authData too short", ErrNativeAttestationInvalid)
	}

	clientDataHash := sha256.Sum256([]byte(req.Challenge))
	composite := append(attestObj.AuthData, clientDataHash[:]...)
	nonce := sha256.Sum256(composite)

	// The nonce should be embedded in the leaf certificate's extension (OID 1.2.840.113635.100.8.2)
	// The extension value is ASN.1: SEQUENCE { SET { SEQUENCE { [0] EXPLICIT OCTET STRING { nonce } } } }
	expectedNonceFound := false
	for _, ext := range leafCert.Extensions {
		if ext.Id.String() == "1.2.840.113635.100.8.2" {
			extractedNonce, err := extractAppAttestNonce(ext.Value)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to parse nonce extension: %v", ErrNativeAttestationInvalid, err)
			}
			if subtle.ConstantTimeCompare(extractedNonce, nonce[:]) == 1 {
				expectedNonceFound = true
			}
			break
		}
	}
	if !expectedNonceFound {
		// In development mode, log and continue
		if nativeCfg.AppleAppAttestEnvironment == "development" {
			s.logger.Warn("App Attest nonce mismatch (development mode)")
		} else {
			return nil, fmt.Errorf("%w: nonce mismatch in leaf certificate", ErrNativeAttestationInvalid)
		}
	}

	// Step 5: Verify rpIdHash matches configured App ID
	// rpIdHash is the first 32 bytes of authData = SHA256(appID)
	expectedRpIdHash := sha256.Sum256([]byte(nativeCfg.AppleAppID))
	rpIdHash := attestObj.AuthData[:32]
	if subtle.ConstantTimeCompare(rpIdHash, expectedRpIdHash[:]) != 1 {
		return nil, fmt.Errorf("%w: rpIdHash mismatch (wrong app ID)", ErrNativeAttestationInvalid)
	}

	// Step 6: Extract the public key from authData attested credential data
	// Flags byte (index 32) bit 6 indicates attested credential data is present
	flags := attestObj.AuthData[32]
	if flags&0x40 == 0 {
		return nil, fmt.Errorf("%w: no attested credential data in authData", ErrNativeAttestationInvalid)
	}

	s.logger.Info("Apple App Attest verification successful",
		zap.String("key_id", req.KeyID),
		zap.String("app_id", nativeCfg.AppleAppID),
	)

	return &NativeAttestationResult{
		Verified:          true,
		Platform:          NativeAttestationAppleAppAttest,
		AppID:             nativeCfg.AppleAppID,
		AttestationSource: "platform_attested",
	}, nil
}

// verifyGooglePlayIntegrity validates a Google Play Integrity token.
// The token is a nested JWE (encrypted, then signed): decrypt with AES key, verify JWS with EC key.
// See: https://developer.android.com/google/play/integrity/verdict
func (s *NativeAttestationService) verifyGooglePlayIntegrity(_ context.Context, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	nativeCfg := s.cfg.WalletProvider.Attestation.NativeAttestation

	if nativeCfg.GooglePackageName == "" {
		return nil, fmt.Errorf("%w: google_package_name not configured", ErrNativeAttestationInvalid)
	}
	if nativeCfg.GooglePlayIntegrityDecryptionKey == "" || nativeCfg.GooglePlayIntegrityVerificationKey == "" {
		return nil, fmt.Errorf("%w: play integrity keys not configured", ErrNativeAttestationInvalid)
	}
	if req.Token == "" {
		return nil, fmt.Errorf("%w: empty token", ErrNativeAttestationInvalid)
	}

	// Step 1: Decode the decryption key (AES-256)
	decKeyBytes, err := base64.StdEncoding.DecodeString(nativeCfg.GooglePlayIntegrityDecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decode decryption key: %v", ErrNativeAttestationInvalid, err)
	}

	// Step 2: Decrypt the JWE token
	jwe, err := jose.ParseEncrypted(req.Token, []jose.KeyAlgorithm{jose.A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("%w: parse JWE: %v", ErrNativeAttestationInvalid, err)
	}

	decrypted, err := jwe.Decrypt(decKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt JWE: %v", ErrNativeAttestationInvalid, err)
	}

	// Step 3: Verify the JWS signature
	verKeyBytes, err := base64.StdEncoding.DecodeString(nativeCfg.GooglePlayIntegrityVerificationKey)
	if err != nil {
		return nil, fmt.Errorf("%w: decode verification key: %v", ErrNativeAttestationInvalid, err)
	}

	// The verification key is a DER-encoded EC public key
	verPubKey, err := x509.ParsePKIXPublicKey(verKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse verification key: %v", ErrNativeAttestationInvalid, err)
	}
	ecPubKey, ok := verPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: verification key is not EC", ErrNativeAttestationInvalid)
	}

	jws, err := jose.ParseSigned(string(decrypted), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("%w: parse JWS: %v", ErrNativeAttestationInvalid, err)
	}

	payload, err := jws.Verify(ecPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: verify JWS: %v", ErrNativeAttestationInvalid, err)
	}

	// Step 4: Parse and validate the verdict
	verdict, err := parsePlayIntegrityVerdict(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNativeAttestationInvalid, err)
	}

	// The nonce sent to Play Integrity is base64url(SHA256(challenge))
	challengeHash := sha256.Sum256([]byte(req.Challenge))
	expectedNonce := base64.URLEncoding.EncodeToString(challengeHash[:])

	if err := validatePlayIntegrityVerdict(verdict, expectedNonce, nativeCfg.GooglePackageName); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNativeAttestationInvalid, err)
	}

	s.logger.Info("Play Integrity verification successful",
		zap.String("key_id", req.KeyID),
		zap.String("package", nativeCfg.GooglePackageName),
		zap.String("app_verdict", verdict.AppIntegrity.AppRecognitionVerdict),
		zap.Strings("device_verdict", verdict.DeviceIntegrity.DeviceRecognitionVerdict),
	)

	return &NativeAttestationResult{
		Verified:          true,
		Platform:          NativeAttestationGooglePlayInteg,
		AppID:             nativeCfg.GooglePackageName,
		AttestationSource: "platform_attested",
	}, nil
}

// AppleAppAttestRootCAs returns the Apple App Attest root CA pool.
// This is the Apple App Attestation Root CA, valid until 2038-02-01.
func AppleAppAttestRootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	// Apple App Attestation Root CA
	// Subject: CN=Apple App Attestation Root CA, O=Apple Inc., ST=California, C=US
	// Validity: 2020-03-18 to 2045-03-15
	const appleAppAttestRootPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMQsw
CQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEuMCwGA1UEAxMlQXBwbGUg
QXBwIEF0dGVzdGF0aW9uIFJvb3QgQ0EgLSBHMzAeFw0yMDAzMTgxODMyNTNaFw00
NTAzMTUwMDAwMDBaMFIxCzAJBgNVBAYTAlVTMRMwEQYDVQQKEwpBcHBsZSBJbmMu
MS4wLAYDVQQDEyVBcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQSAtIEczMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/I
i2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMsI
n4XoWCTkESWNc3eLBSEWUq76L5VHo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
DgQWBBSskVBDFdm8URArZ6DPsDZmDbjhlDAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZI
zj0EAwMDaAAwZQIxAOVpEslu28YxuglB4Zf4+/2a4n0Sye18ZNPLBSWLVtmg515d
TguDnFt2KaAJJiFqYgIwcdK1j1zqO+F4CYWodZI7yFz9SO8NdCKoCOJuxUnOxwy8
p2Fp8fc74SrL+SvzZpA3
-----END CERTIFICATE-----`
	pool.AppendCertsFromPEM([]byte(appleAppAttestRootPEM))
	return pool
}

// extractAppAttestNonce parses the Apple App Attest nonce from the
// credCert extension OID 1.2.840.113635.100.8.2.
// The ASN.1 structure is: SEQUENCE { SEQUENCE { [0] EXPLICIT OCTET STRING } }
func extractAppAttestNonce(extValue []byte) ([]byte, error) {
	// Outer SEQUENCE
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(extValue, &outer)
	if err != nil {
		return nil, fmt.Errorf("unmarshal outer: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after outer SEQUENCE")
	}
	if outer.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("expected SEQUENCE, got tag %d", outer.Tag)
	}

	// Inner SEQUENCE
	var inner asn1.RawValue
	rest, err = asn1.Unmarshal(outer.Bytes, &inner)
	if err != nil {
		return nil, fmt.Errorf("unmarshal inner: %w", err)
	}
	_ = rest // may have additional elements

	// Context-specific [0] EXPLICIT wrapping the OCTET STRING
	var tagged asn1.RawValue
	if inner.Tag == asn1.TagSequence {
		// Nested: SEQUENCE { [0] OCTET STRING }
		_, err = asn1.Unmarshal(inner.Bytes, &tagged)
	} else {
		tagged = inner
	}
	if err != nil {
		return nil, fmt.Errorf("unmarshal tagged: %w", err)
	}

	// Extract the OCTET STRING nonce
	if tagged.Class == asn1.ClassContextSpecific && tagged.Tag == 0 {
		// Explicit tagging: the content is the OCTET STRING
		var octetStr []byte
		_, err = asn1.Unmarshal(tagged.Bytes, &octetStr)
		if err != nil {
			return nil, fmt.Errorf("unmarshal octet string: %w", err)
		}
		return octetStr, nil
	}

	// Fallback: try treating as raw OCTET STRING
	if tagged.Tag == asn1.TagOctetString {
		return tagged.Bytes, nil
	}

	return nil, fmt.Errorf("unexpected ASN.1 structure: class=%d tag=%d", tagged.Class, tagged.Tag)
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
	if subtle.ConstantTimeCompare([]byte(verdict.RequestDetails.Nonce), []byte(expectedNonce)) != 1 {
		return fmt.Errorf("nonce mismatch")
	}
	if verdict.RequestDetails.RequestPackageName != expectedPackage {
		return fmt.Errorf("package mismatch: got %q, want %q", verdict.RequestDetails.RequestPackageName, expectedPackage)
	}

	// Verify timestamp is recent (within 10 minutes) and not in the future (+ 1 min tolerance)
	ts := time.UnixMilli(verdict.RequestDetails.TimestampMillis)
	if time.Since(ts) > 10*time.Minute {
		return fmt.Errorf("verdict too old: %v", ts)
	}
	if ts.After(time.Now().Add(1 * time.Minute)) {
		return fmt.Errorf("verdict timestamp in the future: %v", ts)
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
