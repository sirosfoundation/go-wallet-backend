package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
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
	trust     *trust.Service
}

// NewFIDO2AttestationService creates a new FIDO2 attestation verifier. trust
// evaluates the attestation's x5c chain against go-trust's fidomds3
// registry (real FIDO Alliance MDS3 data, keyed by AAGUID) - this service
// does not embed any trust-anchor material itself, per ADR-010.
func NewFIDO2AttestationService(cfg *config.Config, instances storage.WalletInstanceStore, trustSvc *trust.Service, logger *zap.Logger) *FIDO2AttestationService {
	return &FIDO2AttestationService{
		cfg:       cfg,
		instances: instances,
		trust:     trustSvc,
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
	// which is what a genuine YubiKey produces) against real FIDO Alliance
	// MDS3 trust data via go-trust's fidomds3 registry. go-webauthn's
	// VerifyAttestation above does NOT do this unless a metadata.Provider is
	// supplied - without this step, any self-signed leaf cert with a valid
	// signature would pass. Per ADR-010, this service performs no local
	// trust-anchor evaluation itself - the AAGUID+chain decision is
	// delegated to the PDP, same as issuer/verifier trust.
	x5cRaw, ok := attObj.AttStatement["x5c"].([]any)
	if !ok || len(x5cRaw) == 0 {
		return fmt.Errorf("%w: no x5c attestation certificate chain present (self-attestation is not accepted)", ErrFIDO2AttestationInvalid)
	}

	x5cChain := make([]string, 0, len(x5cRaw))
	for i, raw := range x5cRaw {
		der, ok := raw.([]byte)
		if !ok {
			return fmt.Errorf("%w: malformed x5c chain element %d", ErrFIDO2AttestationInvalid, i)
		}
		x5cChain = append(x5cChain, base64.StdEncoding.EncodeToString(der))
	}

	aaguid, err := uuid.FromBytes(attObj.AuthData.AttData.AAGUID)
	if err != nil {
		return fmt.Errorf("%w: parse AAGUID: %v", ErrFIDO2AttestationInvalid, err)
	}

	trustInfo, err := s.trust.EvaluateFIDO2Attestation(ctx, aaguid.String(), x5cChain)
	if err != nil {
		return fmt.Errorf("%w: trust evaluation: %v", ErrFIDO2AttestationInvalid, err)
	}
	if !trustInfo.Trusted {
		return fmt.Errorf("%w: not trusted by FIDO MDS3 registry: %s", ErrFIDO2AttestationInvalid, trustInfo.Reason)
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
