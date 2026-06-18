package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func testNativeAttestationConfig(enabled bool) *config.Config {
	return &config.Config{
		WalletProvider: config.WalletProviderConfig{
			Attestation: config.AttestationConfig{
				NativeAttestation: config.NativeAttestationConfig{
					Enabled:                   enabled,
					AppleAppID:                "com.example.test",
					AppleAppAttestEnvironment: "development",
					GooglePackageName:         "com.example.test",
				},
			},
		},
	}
}

func TestNativeAttestationService_Disabled(t *testing.T) {
	cfg := testNativeAttestationConfig(false)
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationAppleAppAttest,
		Token:     "dGVzdA==",
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err != ErrNativeAttestationDisabled {
		t.Fatalf("expected ErrNativeAttestationDisabled, got %v", err)
	}
}

func TestNativeAttestationService_UnsupportedType(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      "unknown_platform",
		Token:     "dGVzdA==",
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestNativeAttestationService_AppAttest_EmptyToken(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationAppleAppAttest,
		Token:     base64.StdEncoding.EncodeToString([]byte{}),
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for empty attestation")
	}
}

func TestNativeAttestationService_AppAttest_InvalidCBOR(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationAppleAppAttest,
		Token:     base64.StdEncoding.EncodeToString([]byte("not-cbor")),
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for invalid CBOR")
	}
}

func TestNativeAttestationService_AppAttest_WrongFmt(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	obj := appleAppAttestAttestation{
		Fmt:      "wrong-format",
		AuthData: make([]byte, 37),
	}
	cborBytes, _ := cbor.Marshal(obj)

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationAppleAppAttest,
		Token:     base64.StdEncoding.EncodeToString(cborBytes),
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for wrong fmt")
	}
}

func TestNativeAttestationService_AppAttest_MissingAppID(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	cfg.WalletProvider.Attestation.NativeAttestation.AppleAppID = ""
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationAppleAppAttest,
		Token:     "dGVzdA==",
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for missing app ID")
	}
}

func TestNativeAttestationService_PlayIntegrity_EmptyToken(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	cfg.WalletProvider.Attestation.NativeAttestation.GooglePlayIntegrityDecryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg.WalletProvider.Attestation.NativeAttestation.GooglePlayIntegrityVerificationKey = "test"
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationGooglePlayInteg,
		Token:     "",
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestNativeAttestationService_PlayIntegrity_MissingKeys(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationGooglePlayInteg,
		Token:     "test-token",
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for missing keys")
	}
}

func TestNativeAttestationService_PlayIntegrity_MissingPackageName(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	cfg.WalletProvider.Attestation.NativeAttestation.GooglePackageName = ""
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationGooglePlayInteg,
		Token:     "test-token",
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for missing package name")
	}
}

func TestNativeAttestationService_PlayIntegrity_InvalidJWE(t *testing.T) {
	cfg := testNativeAttestationConfig(true)
	cfg.WalletProvider.Attestation.NativeAttestation.GooglePlayIntegrityDecryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	cfg.WalletProvider.Attestation.NativeAttestation.GooglePlayIntegrityVerificationKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	_, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationGooglePlayInteg,
		Token:     "not-a-valid-jwe",
		KeyID:     "test-key",
		Challenge: "test-challenge",
	})
	if err == nil {
		t.Fatal("expected error for invalid JWE")
	}
}

func TestNativeAttestationService_PlayIntegrity_FullFlow(t *testing.T) {
	// Generate an AES-256 decryption key
	decKey := make([]byte, 32)
	if _, err := rand.Read(decKey); err != nil {
		t.Fatal(err)
	}

	// Generate an EC P-256 signing key
	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	challenge := "test-challenge-12345"
	challengeHash := sha256.Sum256([]byte(challenge))
	expectedNonce := base64.RawURLEncoding.EncodeToString(challengeHash[:])

	// Build a Play Integrity verdict payload
	now := time.Now()
	verdict := map[string]interface{}{
		"requestDetails": map[string]interface{}{
			"nonce":              expectedNonce,
			"requestPackageName": "com.example.test",
			"timestampMillis":    now.UnixMilli(),
		},
		"appIntegrity": map[string]interface{}{
			"appRecognitionVerdict": "PLAY_RECOGNIZED",
			"packageName":           "com.example.test",
		},
		"deviceIntegrity": map[string]interface{}{
			"deviceRecognitionVerdict": []string{"MEETS_DEVICE_INTEGRITY"},
		},
		"accountDetails": map[string]interface{}{
			"appLicensingVerdict": "LICENSED",
		},
	}
	verdictJSON, _ := json.Marshal(verdict)

	// Sign with JWS (ES256)
	joseSignKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       sigKey,
	}
	jwsSigner, err := jose.NewSigner(joseSignKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	jwsObject, err := jwsSigner.Sign(verdictJSON)
	if err != nil {
		t.Fatal(err)
	}
	jwsSerialized, err := jwsObject.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with JWE (A256KW / A256GCM)
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256KW, Key: decKey},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	jweObject, err := enc.Encrypt([]byte(jwsSerialized))
	if err != nil {
		t.Fatal(err)
	}
	jweSerialized, err := jweObject.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	// Encode the EC public key as DER for verification key config
	verKeyDER, err := x509.MarshalPKIXPublicKey(&sigKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	cfg := testNativeAttestationConfig(true)
	cfg.WalletProvider.Attestation.NativeAttestation.GooglePlayIntegrityDecryptionKey = base64.StdEncoding.EncodeToString(decKey)
	cfg.WalletProvider.Attestation.NativeAttestation.GooglePlayIntegrityVerificationKey = base64.StdEncoding.EncodeToString(verKeyDER)
	svc := NewNativeAttestationService(cfg, zap.NewNop())

	result, err := svc.Verify(context.Background(), &NativeAttestationRequest{
		Type:      NativeAttestationGooglePlayInteg,
		Token:     jweSerialized,
		KeyID:     "test-key",
		Challenge: challenge,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected verified=true")
	}
	if result.Platform != NativeAttestationGooglePlayInteg {
		t.Fatalf("expected platform google_play_integrity, got %s", result.Platform)
	}
	if result.AppID != "com.example.test" {
		t.Fatalf("expected app ID com.example.test, got %s", result.AppID)
	}
}

func TestAppleAppAttestRootCAs_NotEmpty(t *testing.T) {
	pool := AppleAppAttestRootCAs()
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}
	// Verify the pool actually contains certificates by checking Subjects()
	//nolint:staticcheck // Subjects() is deprecated in Go 1.22+ but still works for this test
	subjects := pool.Subjects()
	if len(subjects) == 0 {
		t.Fatal("expected at least one certificate in the Apple App Attest root pool")
	}
}

func TestExtractAppAttestNonce(t *testing.T) {
	// Test with a well-formed ASN.1 extension value
	// SEQUENCE { SEQUENCE { [0] EXPLICIT OCTET STRING { 32 bytes of nonce } } }
	expectedNonce := make([]byte, 32)
	for i := range expectedNonce {
		expectedNonce[i] = byte(i)
	}

	// Build the ASN.1 structure manually
	// Inner: context-specific [0] EXPLICIT wrapping OCTET STRING
	innerOctetStr, _ := asn1.Marshal(expectedNonce)
	tagged := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      innerOctetStr,
	}
	taggedBytes, _ := asn1.Marshal(tagged)

	// Inner SEQUENCE
	innerSeq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      taggedBytes,
	}
	innerSeqBytes, _ := asn1.Marshal(innerSeq)

	// Outer SEQUENCE
	outerSeq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      innerSeqBytes,
	}
	extValue, _ := asn1.Marshal(outerSeq)

	got, err := extractAppAttestNonce(extValue)
	if err != nil {
		t.Fatalf("extractAppAttestNonce() error = %v", err)
	}
	if !bytes.Equal(got, expectedNonce) {
		t.Errorf("extractAppAttestNonce() = %x, want %x", got, expectedNonce)
	}

	// Test with invalid data
	_, err = extractAppAttestNonce([]byte{0x00, 0x01})
	if err == nil {
		t.Error("extractAppAttestNonce(invalid) should have returned error")
	}
}

func TestParsePlayIntegrityVerdict(t *testing.T) {
	validVerdict := `{
		"requestDetails": {"nonce": "test-nonce", "requestPackageName": "com.test", "timestampMillis": 123},
		"appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED"},
		"deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
		"accountDetails": {"appLicensingVerdict": "LICENSED"}
	}`

	verdict, err := parsePlayIntegrityVerdict([]byte(validVerdict))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.RequestDetails.Nonce != "test-nonce" {
		t.Fatalf("expected nonce test-nonce, got %s", verdict.RequestDetails.Nonce)
	}
	if verdict.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		t.Fatalf("expected PLAY_RECOGNIZED, got %s", verdict.AppIntegrity.AppRecognitionVerdict)
	}
}

func TestValidatePlayIntegrityVerdict(t *testing.T) {
	now := time.Now()
	verdict := &PlayIntegrityVerdict{
		RequestDetails: struct {
			Nonce              string `json:"nonce"`
			RequestPackageName string `json:"requestPackageName"`
			TimestampMillis    int64  `json:"timestampMillis"`
		}{
			Nonce:              "test-nonce",
			RequestPackageName: "com.test",
			TimestampMillis:    now.UnixMilli(),
		},
		AppIntegrity: struct {
			AppRecognitionVerdict string `json:"appRecognitionVerdict"`
		}{
			AppRecognitionVerdict: "PLAY_RECOGNIZED",
		},
		DeviceIntegrity: struct {
			DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
		}{
			DeviceRecognitionVerdict: []string{"MEETS_DEVICE_INTEGRITY"},
		},
	}

	// Should pass with correct nonce and package name
	if err := validatePlayIntegrityVerdict(verdict, "test-nonce", "com.test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail with wrong nonce
	if err := validatePlayIntegrityVerdict(verdict, "wrong-nonce", "com.test"); err == nil {
		t.Fatal("expected error for wrong nonce")
	}

	// Should fail with wrong package name
	if err := validatePlayIntegrityVerdict(verdict, "test-nonce", "com.other"); err == nil {
		t.Fatal("expected error for wrong package name")
	}
}
