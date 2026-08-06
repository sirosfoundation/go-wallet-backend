package service

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	ErrFIDO2AttestationDisabled = errors.New("FIDO2 attestation verification is not enabled")
	ErrFIDO2AttestationInvalid  = errors.New("FIDO2 attestation verification failed")
)

// FIDO2AttestationRequest contains the raw evidence captured by the
// WSCD FIDO2 (previewSign) plugin at key-creation time (see
// siros-wscd-manager's AttestationChain: certificates[0] is the raw CTAP2
// makeCredential attestation object, client_data_hash is the value its
// signature was computed over — there is no browser in this flow, so it's
// not a real WebAuthn clientDataJSON, just the raw 32-byte hash CTAP2's
// authenticatorMakeCredential itself takes as an argument).
type FIDO2AttestationRequest struct {
	// WalletInstanceID is the JWK Thumbprint of the instance this key
	// belongs to (see domain.WalletInstance.ID).
	WalletInstanceID string
	// AttestationObject is the raw CBOR attestation object from
	// makeCredential.
	AttestationObject []byte
	// ClientDataHash is the 32-byte hash the attestation signature covers
	// (authData || ClientDataHash).
	ClientDataHash []byte
}

// FIDO2AttestationService verifies FIDO2/CTAP2 hardware-key attestation
// objects (e.g. from a YubiKey's rawSign plugin) and durably records the
// result on the corresponding WalletInstance. Verified once at
// registration time — see domain.WalletInstance.HardwareKeyAttested's doc
// for why this is a separate trust path from NativeAttestationService
// (which re-verifies fresh evidence on every WIA request).
type FIDO2AttestationService struct {
	cfg       *config.Config
	logger    *zap.Logger
	instances storage.WalletInstanceStore
}

// NewFIDO2AttestationService creates a new FIDO2 attestation verifier.
func NewFIDO2AttestationService(cfg *config.Config, instances storage.WalletInstanceStore, logger *zap.Logger) *FIDO2AttestationService {
	return &FIDO2AttestationService{
		cfg:       cfg,
		instances: instances,
		logger:    logger.Named("fido2-attestation"),
	}
}

// IsEnabled returns true if FIDO2 attestation verification is configured.
func (s *FIDO2AttestationService) IsEnabled() bool {
	return s.cfg.WalletProvider.Attestation.FIDO2Attestation.Enabled
}

// Verify validates a FIDO2 attestation object and, on success, durably
// marks the corresponding WalletInstance as hardware-key-attested.
func (s *FIDO2AttestationService) Verify(ctx context.Context, req *FIDO2AttestationRequest) error {
	if !s.IsEnabled() {
		return ErrFIDO2AttestationDisabled
	}
	if req.WalletInstanceID == "" {
		return fmt.Errorf("%w: empty wallet_instance_id", ErrFIDO2AttestationInvalid)
	}
	if len(req.ClientDataHash) != 32 {
		return fmt.Errorf("%w: client_data_hash must be 32 bytes, got %d", ErrFIDO2AttestationInvalid, len(req.ClientDataHash))
	}

	// Step 1: CBOR-decode the attestation object (fmt, authData, attStmt).
	var attObj protocol.AttestationObject
	if err := webauthncbor.Unmarshal(req.AttestationObject, &attObj); err != nil {
		return fmt.Errorf("%w: cbor decode: %v", ErrFIDO2AttestationInvalid, err)
	}
	if err := attObj.AuthData.Unmarshal(attObj.RawAuthData); err != nil {
		return fmt.Errorf("%w: parse authData: %v", ErrFIDO2AttestationInvalid, err)
	}
	if !attObj.AuthData.Flags.HasAttestedCredentialData() {
		return fmt.Errorf("%w: authData missing attested credential data flag", ErrFIDO2AttestationInvalid)
	}

	// Step 2: verify the attestation statement's signature over
	// authData||clientDataHash using go-webauthn's format-specific handler
	// (packed/fido-u2f/etc. - handles COSE algorithm mapping and, notably,
	// BER-signature normalization for YubiKey firmware 5.8's non-minimally-
	// encoded ECDSA signatures). No metadata.Provider (nil) - that only
	// matters for FIDO MDS3-based trust-anchor lookup, which this v1
	// doesn't use; we do the trust-anchor check ourselves next, exactly
	// like NativeAttestationService.verifyAppleAppAttest does for x5c.
	if err := attObj.VerifyAttestation(req.ClientDataHash, nil); err != nil {
		return fmt.Errorf("%w: attestation signature: %v", ErrFIDO2AttestationInvalid, err)
	}

	// Step 3: verify the x5c chain (present for "packed" Basic Attestation,
	// which is what a genuine YubiKey produces) against the pinned Yubico
	// root CAs. go-webauthn's VerifyAttestation above does NOT do this
	// unless a metadata.Provider is supplied - without this step, any
	// self-signed leaf cert with a valid signature would pass.
	x5cRaw, ok := attObj.AttStatement["x5c"].([]any)
	if !ok || len(x5cRaw) == 0 {
		return fmt.Errorf("%w: no x5c attestation certificate chain present (self-attestation is not accepted)", ErrFIDO2AttestationInvalid)
	}

	leafDER, ok := x5cRaw[0].([]byte)
	if !ok {
		return fmt.Errorf("%w: malformed x5c leaf certificate", ErrFIDO2AttestationInvalid)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("%w: parse leaf cert: %v", ErrFIDO2AttestationInvalid, err)
	}

	intermediates := x509.NewCertPool()
	for _, raw := range x5cRaw[1:] {
		certDER, ok := raw.([]byte)
		if !ok {
			return fmt.Errorf("%w: malformed x5c intermediate certificate", ErrFIDO2AttestationInvalid)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return fmt.Errorf("%w: parse intermediate cert: %v", ErrFIDO2AttestationInvalid, err)
		}
		intermediates.AddCert(cert)
	}

	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:         YubiKeyAttestationRootCAs(),
		Intermediates: intermediates,
	}); err != nil {
		return fmt.Errorf("%w: x5c chain verification: %v", ErrFIDO2AttestationInvalid, err)
	}

	// Step 4: durably record the result. Deliberately a dedicated store
	// method, not folded into the WIA-issuance Upsert path - see
	// domain.WalletInstance.HardwareKeyAttested's doc comment.
	verifiedAt := time.Now().UTC()
	if err := s.instances.MarkHardwareKeyAttested(ctx, req.WalletInstanceID, verifiedAt); err != nil {
		return fmt.Errorf("%w: record verification: %v", ErrFIDO2AttestationInvalid, err)
	}

	s.logger.Info("FIDO2 hardware attestation verified",
		zap.String("wallet_instance_id", req.WalletInstanceID),
		zap.String("format", attObj.Format),
	)

	return nil
}

// YubiKeyAttestationRootCAs returns the Yubico FIDO2 attestation root CA
// pool: "Yubico FIDO Root CA Serial 450203556" (issued 2024-05-01) and
// "Yubico Attestation Root 1" (issued 2024-12-01). Both fetched and their
// OpenPGP signature verified against Yubico's own published signing-key
// fingerprint (developers.yubico.com/Software_Projects/Software_Signing.html)
// from https://developers.yubico.com/PKI/yubico-ca-certs.txt on 2026-08-06.
// The older "Yubico U2F Root CA Serial 457200631" (2014) covers U2F/CTAP1-only
// devices and is deliberately not included - out of scope for FIDO2/CTAP2
// rawSign attestation.
func YubiKeyAttestationRootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	const yubicoFIDORootPEM = `-----BEGIN CERTIFICATE-----
MIIDMzCCAhugAwIBAgIUSOEjTf//yqRfPW7Qq8qtIyCrAg8wDQYJKoZIhvcNAQEL
BQAwLzEtMCsGA1UEAwwkWXViaWNvIEZJRE8gUm9vdCBDQSBTZXJpYWwgNDUwMjAz
NTU2MCAXDTI0MDUwMTAwMDAwMFoYDzIwNjAwNDMwMDAwMDAwWjAvMS0wKwYDVQQD
DCRZdWJpY28gRklETyBSb290IENBIFNlcmlhbCA0NTAyMDM1NTYwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdvl27w2gu1fPXeEFbIdqx0BalvVDVWrQP
J7HqviuEtZHlxSLxSFtcXpTolvLvof8f4tMerQTkVGzcmYzm1EBT4IJuMmoEqfkE
EhWpsADMFrjZkqlZY9EqxQzLoVEEonE5oGxSdVCxCcLIackpyR/CCXvj1Bt/hTgE
9hTlF4pRqxMkx3plF7y8dDZlRHWs7vbnhmBCGeI0ZPEQ6nl2mCg2r74adF2u6K9r
rLfhBC3QLE8EPrgqUsI+hkuq2tK4M2SMOp8uUVVkqUeu3h0kr3WVI0W02pkgrOgi
FKLFNkSrbYhdjMBDj5izmqfc9xJRKoDX612qd8ZGVHpT5AYFX+1hAgMBAAGjRTBD
MB0GA1UdDgQWBBTZyU5DiQ/a2UEgE7qBK0zhIsRNRjASBgNVHRMBAf8ECDAGAQH/
AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAXvnB4SLuUJfY
MSVGAhssL/SmWli3FSccgxydvKlACcidIIWKQqa3q/QSUEQzC9DgEfMgr7iC1BkT
ZbILboV6UZ5knNsvjEZWuMeogJ8tgZs1hVvKwZizwJ+mEcmsjhIrBYuoL1T6yrOJ
vKFg1jv+Cy4ZwA9Bpk/V3UOir1VyK8dCtyHu6vfosotAdYx8FAuR243gRTMV6Jx8
Jdig2JDIAQMlzVeDpSUHX/K2HXRHxHwfgjbgUjjBu/72r8OfehyhzHXI3K8CFFdf
lO+8nEOJK3y8F1ivgS5uN/8SmcYw/STQYwhrxPuwz3nP8baMum4BB2nnYmpB60sX
3bl5k8QUSw==
-----END CERTIFICATE-----`
	const yubicoAttestationRoot1PEM = `-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIUXzeiEDJEOTt14F5n0o6Zf/bBwiUwDQYJKoZIhvcNAQEN
BQAwJDEiMCAGA1UEAwwZWXViaWNvIEF0dGVzdGF0aW9uIFJvb3QgMTAgFw0yNDEy
MDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowJDEiMCAGA1UEAwwZWXViaWNvIEF0
dGVzdGF0aW9uIFJvb3QgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMZ6/TxM8rIT+EaoPvG81ontMOo/2mQ2RBwJHS0QZcxVaNXvl12LUhBZ5LmiBScI
Zd1Rnx1od585h+/dhK7hEm7JAALkKKts1fO53KGNLZujz5h3wGncr4hyKF0G74b/
U3K9hE5mGND6zqYchCRAHfrYMYRDF4YL0X4D5nGdxvppAy6nkEmtWmMnwO3i0TAu
csrbE485HvGM4r0VpgVdJpvgQjiTJCTIq+D35hwtT8QDIv+nGvpcyi5wcIfCkzyC
imJukhYy6KoqNMKQEdpNiSOvWyDMTMt1bwCvEzpw91u+msUt4rj0efnO9s0ZOwdw
MRDnH4xgUl5ZLwrrPkfC1/0CAwEAAaNmMGQwHQYDVR0OBBYEFNLu71oijTptXCOX
PfKF1SbxJXuSMB8GA1UdIwQYMBaAFNLu71oijTptXCOXPfKF1SbxJXuSMBIGA1Ud
EwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBDQUAA4IB
AQC3IW/sgB9pZ8apJNjxuGoX+FkILks0wMNrdXL/coUvsrhzsvl6mePMrbGJByJ1
XnquB5sgcRENFxdQFma3mio8Upf1owM1ZreXrJ0mADG2BplqbJnxiyYa+R11reIF
TWeIhMNcZKsDZrFAyPuFjCWSQvJmNWe9mFRYFgNhXJKkXIb5H1XgEDlwiedYRM7V
olBNlld6pRFKlX8ust6OTMOeADl2xNF0m1LThSdeuXvDyC1g9+ILfz3S6OIYgc3i
roRcFD354g7rKfu67qFAw9gC4yi0xBTPrY95rh4/HqaUYCA/L8ldRk6H7Xk35D+W
Vpmq2Sh/xT5HiFuhf4wJb0bK
-----END CERTIFICATE-----`
	if !pool.AppendCertsFromPEM([]byte(yubicoFIDORootPEM)) {
		panic("failed to parse embedded Yubico FIDO Root CA PEM")
	}
	if !pool.AppendCertsFromPEM([]byte(yubicoAttestationRoot1PEM)) {
		panic("failed to parse embedded Yubico Attestation Root 1 PEM")
	}
	return pool
}
