package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrNativeAttestationDisabled = errors.New("native attestation verification is not enabled")
	ErrNativeAttestationInvalid  = errors.New("native attestation verification failed")
	// ErrNativeAttestationUnavailable means a valid-looking attestation could
	// not be judged or recorded because storage failed. It is not a client
	// error: the request is refused and may be retried.
	ErrNativeAttestationUnavailable = errors.New("native attestation cannot be verified right now")
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
	// KeyID is the key identifier. For App Attest it is required and is
	// validated against the attested public key (it must be the base64 of
	// SHA-256 over the credCert public key); for Play Integrity it is only
	// logged, never used as an identity.
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

	// appAttestKeys durably stores verified App Attest keys; nil disables
	// storing (attestations are still verified in full).
	appAttestKeys storage.AppAttestKeyStore
	// appRoots is the trust root pool for the attestation chain; nil means
	// the pinned Apple App Attestation Root CA. Tests inject a test CA.
	appRoots *x509.CertPool
}

// NewNativeAttestationService creates a new native attestation verifier.
func NewNativeAttestationService(cfg *config.Config, logger *zap.Logger) *NativeAttestationService {
	return &NativeAttestationService{
		cfg:    cfg,
		logger: logger.Named("native-attestation"),
	}
}

// SetAppAttestKeys installs the store verified App Attest keys are kept in.
func (s *NativeAttestationService) SetAppAttestKeys(k storage.AppAttestKeyStore) { s.appAttestKeys = k }

// IsEnabled returns true if native attestation verification is configured.
func (s *NativeAttestationService) IsEnabled() bool {
	return s.cfg.WalletProvider.Attestation.NativeAttestation.Enabled
}

// Verify validates a native attestation request.
//
// It verifies only: an App Attest key is not stored, because there is no
// caller context to bind it to. The WIA path uses VerifyBound.
func (s *NativeAttestationService) Verify(ctx context.Context, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	return s.verify(ctx, nil, req)
}

// VerifyBound validates a native attestation request on behalf of an
// authenticated caller. A verified App Attest key is stored bound to that
// caller (tenant, user, wallet instance), so later requests can use assertions.
func (s *NativeAttestationService) VerifyBound(ctx context.Context, bind NativeAttestationBinding, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	return s.verify(ctx, &bind, req)
}

func (s *NativeAttestationService) verify(ctx context.Context, bind *NativeAttestationBinding, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	if !s.IsEnabled() {
		return nil, ErrNativeAttestationDisabled
	}

	switch req.Type {
	case NativeAttestationAppleAppAttest:
		return s.verifyAppleAppAttest(ctx, bind, req)
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

// App Attest authenticator data layout (attestation object):
//
//	rpIdHash (32) || flags (1) || signCount (4) ||
//	aaguid (16) || credentialIdLength (2, big endian) || credentialId || credentialPublicKey (COSE)
const (
	appAttestAuthDataHeaderLen  = 37
	appAttestAttestedDataOffset = appAttestAuthDataHeaderLen + 16 + 2 // 55
	appAttestKeyIDLen           = sha256.Size
	// maxAppAttestObjectLen bounds the attestation object accepted. Real
	// objects are a few KiB; the cap keeps a hostile client from making the
	// server decode megabytes of CBOR.
	maxAppAttestObjectLen = 64 * 1024
)

// AAGUIDs Apple puts in attestation objects: the environment is part of the
// signed authenticator data, not something the client reports.
var (
	appAttestAAGUIDProduction  = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't'}
	appAttestAAGUIDDevelopment = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 'd', 'e', 'v', 'e', 'l', 'o', 'p'}
)

// appAttestEnvironment resolves the configured environment. Empty means
// production (the historical default); anything unrecognised is refused
// rather than guessed.
func appAttestEnvironment(configured string) (domain.AppAttestEnvironment, [16]byte, error) {
	switch configured {
	case "", "production":
		return domain.AppAttestProduction, appAttestAAGUIDProduction, nil
	case "development":
		return domain.AppAttestDevelopment, appAttestAAGUIDDevelopment, nil
	}
	return "", [16]byte{}, fmt.Errorf("unsupported apple_app_attest_environment %q", configured)
}

// decodeAppAttestKeyID decodes the key identifier a client sends. Apple's
// keyId is the base64 of 32 bytes; standard and URL alphabets, padded or not,
// are accepted. Anything that does not decode to exactly 32 bytes is refused.
func decodeAppAttestKeyID(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != appAttestKeyIDLen {
				return nil, fmt.Errorf("key_id is %d bytes, want %d", len(b), appAttestKeyIDLen)
			}
			return b, nil
		}
	}
	return nil, errors.New("key_id is not base64")
}

// canonicalAppAttestKeyID is the stored form of a key id.
func canonicalAppAttestKeyID(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// NativeAttestationBinding is the context an App Attest key is attested in:
// the authenticated caller of the WIA request. The attested key is stored
// bound to it.
type NativeAttestationBinding struct {
	TenantID         domain.TenantID
	UserID           *domain.UserID
	WalletInstanceID string
}

// verifyAppleAppAttest validates an Apple App Attest attestation object.
// See: https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server
//
// It performs the checks Apple specifies, in order: certificate chain to the
// pinned App Attest root, nonce, keyId against the credCert public key, rpIdHash, counter
// zero, AAGUID for the configured environment and credentialId against keyId.
// The public key is then stored (when a store is configured and the caller is
// bound) so later requests prove key possession with assertions instead of
// attesting again.
func (s *NativeAttestationService) verifyAppleAppAttest(ctx context.Context, bind *NativeAttestationBinding, req *NativeAttestationRequest) (*NativeAttestationResult, error) {
	nativeCfg := s.cfg.WalletProvider.Attestation.NativeAttestation

	if nativeCfg.AppleAppID == "" {
		return nil, fmt.Errorf("%w: apple_app_id not configured", ErrNativeAttestationInvalid)
	}
	env, wantAAGUID, err := appAttestEnvironment(nativeCfg.AppleAppAttestEnvironment)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNativeAttestationInvalid, err)
	}

	// The key id is required and validated below against the attested key;
	// it is never trusted as sent.
	wantKeyID, err := decodeAppAttestKeyID(req.KeyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNativeAttestationInvalid, err)
	}

	// Decode the attestation object
	if base64.StdEncoding.DecodedLen(len(req.Token)) > maxAppAttestObjectLen {
		return nil, fmt.Errorf("%w: attestation too large", ErrNativeAttestationInvalid)
	}
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
	roots := s.appRoots
	if roots == nil {
		roots = AppleAppAttestRootCAs()
	}
	chainVerified := true
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	if err != nil {
		if env == domain.AppAttestDevelopment {
			// Development-only bypass for test harnesses without a genuine Apple
			// attestation chain. Logged at Error (not Warn) and counted in a
			// dedicated metric so an accidental "development" setting in a
			// production deployment is loud, not silent. The nonce check below
			// is NOT bypassed even in development — see that check for why.
			// A key accepted this way is stored as chain-unverified and never
			// yields a verified key home.
			chainVerified = false
			nativeAttestationDevChainBypass.Inc()
			s.logger.Error("App Attest x5c chain verification failed — proceeding because apple_app_attest_environment=development; this must never be set in production", zap.Error(err))
		} else {
			return nil, fmt.Errorf("%w: x5c chain verification: %v", ErrNativeAttestationInvalid, err)
		}
	}

	// Step 4: Verify the nonce in authData
	// authData structure: rpIdHash (32) || flags (1) || signCount (4) || attestedCredData (...)
	// The nonce is SHA256(authData || SHA256(clientDataJSON))
	// For App Attest, clientDataHash = SHA256(challenge)
	if len(attestObj.AuthData) < appAttestAttestedDataOffset {
		return nil, fmt.Errorf("%w: authData too short", ErrNativeAttestationInvalid)
	}

	clientDataHash := sha256.Sum256([]byte(req.Challenge))
	composite := append(append([]byte{}, attestObj.AuthData...), clientDataHash[:]...)
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
		// Always enforced, including in development: the nonce is what binds this
		// attestation to the specific single-use WIA challenge. Unlike the x5c
		// chain (which legitimately can't be produced without real Apple hardware
		// in dev/test), a dev/test harness can always compute this correctly, so
		// there's no legitimate reason to skip it — doing so would let a forged
		// attestation with an arbitrary nonce through.
		return nil, fmt.Errorf("%w: nonce mismatch in leaf certificate", ErrNativeAttestationInvalid)
	}

	// Step 5: keyId. SHA-256 of the credCert public key (X9.62 uncompressed
	// point) must equal the key id the client sent: this is what ties the
	// client-supplied identifier to the key that was actually attested.
	certPub, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || certPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: credCert public key is not P-256", ErrNativeAttestationInvalid)
	}
	ecdhPub, err := certPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("%w: credCert public key: %v", ErrNativeAttestationInvalid, err)
	}
	pubPoint := ecdhPub.Bytes() // X9.62 uncompressed
	derivedKeyID := sha256.Sum256(pubPoint)
	if subtle.ConstantTimeCompare(derivedKeyID[:], wantKeyID) != 1 {
		return nil, fmt.Errorf("%w: key_id does not match the attested public key", ErrNativeAttestationInvalid)
	}

	// Step 6: rpIdHash matches configured App ID
	// rpIdHash is the first 32 bytes of authData = SHA256(appID)
	expectedRpIdHash := sha256.Sum256([]byte(nativeCfg.AppleAppID))
	if subtle.ConstantTimeCompare(attestObj.AuthData[:32], expectedRpIdHash[:]) != 1 {
		return nil, fmt.Errorf("%w: rpIdHash mismatch (wrong app ID)", ErrNativeAttestationInvalid)
	}

	// Step 7: attested credential data flag (flags byte, bit 6) must be set,
	// and the counter in a fresh attestation is exactly zero.
	if attestObj.AuthData[32]&0x40 == 0 {
		return nil, fmt.Errorf("%w: no attested credential data in authData", ErrNativeAttestationInvalid)
	}
	if counter := binary.BigEndian.Uint32(attestObj.AuthData[33:37]); counter != 0 {
		return nil, fmt.Errorf("%w: attestation counter is %d, want 0", ErrNativeAttestationInvalid, counter)
	}

	// Step 8: AAGUID names the environment; it must be the configured one
	// (a development attestation is never accepted by a production backend).
	if subtle.ConstantTimeCompare(attestObj.AuthData[37:53], wantAAGUID[:]) != 1 {
		return nil, fmt.Errorf("%w: AAGUID does not match environment %q", ErrNativeAttestationInvalid, env)
	}

	// Step 9: credentialId equals the key id.
	credIDLen := int(binary.BigEndian.Uint16(attestObj.AuthData[53:55]))
	if credIDLen != appAttestKeyIDLen || len(attestObj.AuthData) < appAttestAttestedDataOffset+credIDLen {
		return nil, fmt.Errorf("%w: credentialId has unexpected length", ErrNativeAttestationInvalid)
	}
	credID := attestObj.AuthData[appAttestAttestedDataOffset : appAttestAttestedDataOffset+credIDLen]
	if subtle.ConstantTimeCompare(credID, wantKeyID) != 1 {
		return nil, fmt.Errorf("%w: credentialId does not match key_id", ErrNativeAttestationInvalid)
	}

	keyID := canonicalAppAttestKeyID(wantKeyID)
	if bind != nil {
		if err := s.persistAppAttestKey(ctx, bind, &domain.AppAttestKeyRecord{
			KeyID:         keyID,
			PublicKey:     pubPoint,
			Environment:   env,
			AppID:         nativeCfg.AppleAppID,
			ChainVerified: chainVerified,
			TenantID:      bind.TenantID,
			UserID:        bind.UserID,
			Status:        domain.AppAttestKeyActive,

			WalletInstanceID: bind.WalletInstanceID,
		}); err != nil {
			return nil, err
		}
	}

	s.logger.Info("Apple App Attest verification successful",
		zap.String("key_id", keyID),
		zap.String("app_id", nativeCfg.AppleAppID),
		zap.String("environment", string(env)),
		zap.Bool("chain_verified", chainVerified),
	)

	attSource := "platform_attested"
	appID := nativeCfg.AppleAppID
	if env == domain.AppAttestDevelopment {
		attSource = "development_attested"
		// Development mode accepts a self-signed chain, so nothing
		// authenticated the application: never report an app id as verified.
		appID = ""
	}

	return &NativeAttestationResult{
		Verified:          true,
		Platform:          NativeAttestationAppleAppAttest,
		AppID:             appID,
		AttestationSource: attSource,
	}, nil
}

// persistAppAttestKey stores a freshly verified attested key. A key that is
// already stored is left exactly as it is (its counter is never reset, which
// would reopen assertion replay); it is accepted only when it is the same key
// in the same tenant/user context and still active.
func (s *NativeAttestationService) persistAppAttestKey(ctx context.Context, bind *NativeAttestationBinding, rec *domain.AppAttestKeyRecord) error {
	if s.appAttestKeys == nil {
		return nil
	}
	if bind.TenantID == "" {
		return fmt.Errorf("%w: tenant required to store an attested key", ErrNativeAttestationInvalid)
	}
	err := s.appAttestKeys.Create(ctx, rec)
	if err == nil {
		return nil
	}
	if !errors.Is(err, storage.ErrAlreadyExists) {
		return fmt.Errorf("%w: store attested key: %v", ErrNativeAttestationUnavailable, err)
	}
	existing, err := s.appAttestKeys.Get(ctx, rec.KeyID)
	if err != nil {
		return fmt.Errorf("%w: load attested key: %v", ErrNativeAttestationUnavailable, err)
	}
	switch {
	case !existing.IsActive():
		return fmt.Errorf("%w: attested key is not active", ErrNativeAttestationInvalid)
	case !existing.BelongsTo(bind.TenantID, bind.UserID):
		return fmt.Errorf("%w: attested key belongs to another context", ErrNativeAttestationInvalid)
	case !bytes.Equal(existing.PublicKey, rec.PublicKey), existing.Environment != rec.Environment:
		return fmt.Errorf("%w: stored attested key differs from the attestation", ErrNativeAttestationInvalid)
	}
	return nil
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
	if len(decKeyBytes) != 32 {
		return nil, fmt.Errorf("%w: decryption key must be 32 bytes (AES-256), got %d", ErrNativeAttestationInvalid, len(decKeyBytes))
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

	// The nonce sent to Play Integrity is base64url-no-pad(SHA256(challenge))
	challengeHash := sha256.Sum256([]byte(req.Challenge))
	expectedNonce := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	if err := validatePlayIntegrityVerdict(verdict, expectedNonce, nativeCfg.GooglePackageName); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNativeAttestationInvalid, err)
	}

	s.logger.Info("Play Integrity verification successful",
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
// This is the Apple App Attestation Root CA, valid until 2045-03-15.
func AppleAppAttestRootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	// Apple App Attestation Root CA
	// Subject: CN=Apple App Attestation Root CA, O=Apple Inc., ST=California
	// Validity: 2020-03-18 to 2045-03-15
	// Source: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
	const appleAppAttestRootPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`
	if !pool.AppendCertsFromPEM([]byte(appleAppAttestRootPEM)) {
		panic("failed to parse embedded Apple App Attestation Root CA PEM")
	}
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

	// Require app recognition — reject sideloaded/tampered apps
	if verdict.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		return fmt.Errorf("app not recognized by Play Store: %q", verdict.AppIntegrity.AppRecognitionVerdict)
	}

	return nil
}
