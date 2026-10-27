package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
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
// result keyed by the attested credential key's own JWK Thumbprint (see
// domain.KeyAttestationRecord's doc for why this is per-key, not
// per-instance — a wallet instance's identity key and its
// credential-issuance keys are separate keys, not guaranteed to share a
// WSCD plugin).
type FIDO2AttestationService struct {
	cfg             *config.Config
	logger          *zap.Logger
	instances       storage.WalletInstanceStore
	keyAttestations storage.KeyAttestationStore
	trust           *trust.Service
	// users is read for the SID-AUTH-06 cut-off at the write boundary. Nil disables
	// the recheck.
	users tokengate.UserLookup
}

// SetUsers wires the user store Verify rechecks the token cut-off against, before
// and after recording the evidence.
func (s *FIDO2AttestationService) SetUsers(users tokengate.UserLookup) { s.users = users }

// NewFIDO2AttestationService creates a new FIDO2 attestation verifier. trust
// evaluates the attestation's x5c chain against go-trust's fidomds3
// registry (real FIDO Alliance MDS3 data, keyed by AAGUID) - this service
// does not embed any trust-anchor material itself, per ADR-010.
func NewFIDO2AttestationService(cfg *config.Config, instances storage.WalletInstanceStore, keyAttestations storage.KeyAttestationStore, trustSvc *trust.Service, logger *zap.Logger) *FIDO2AttestationService {
	return &FIDO2AttestationService{
		cfg:             cfg,
		instances:       instances,
		keyAttestations: keyAttestations,
		trust:           trustSvc,
		logger:          logger.Named("fido2-attestation"),
	}
}

// IsEnabled returns true if FIDO2 attestation verification is configured.
func (s *FIDO2AttestationService) IsEnabled() bool {
	return s.cfg.WalletProvider.Attestation.FIDO2Attestation.Enabled
}

// Verify validates a FIDO2 attestation object and, on success, durably
// marks the corresponding WalletInstance as hardware-key-attested.
func (s *FIDO2AttestationService) Verify(ctx context.Context, req *FIDO2AttestationRequest) error {
	if req != nil && req.WalletInstanceID == "" && s.IsEnabled() {
		return fmt.Errorf("%w: empty wallet_instance_id", ErrFIDO2AttestationInvalid)
	}
	rec, err := s.VerifyEvidence(ctx, req)
	if err != nil {
		return err
	}
	// The instance must be live and belong to the authenticated tenant and user:
	// keyAttestationTrustsBatch later trusts the evidence, so a token from another
	// device must not attach it to a revoked or foreign instance. Same gate as key
	// attestation generation; an unknown instance is refused too.
	instance, err := refuseWalletInstance(ctx, s.instances, req.WalletInstanceID, true)
	if err != nil {
		return err
	}
	rec.TenantID = instance.TenantID
	// Mutation-boundary gate: a cut-off since admission (the verification is slow)
	// must stop the write.
	if err := tokengate.RefuseNow(ctx, s.users); err != nil {
		return err
	}
	if err := s.keyAttestations.MarkKeyAttested(ctx, rec); err != nil {
		return fmt.Errorf("record key attestation: %w", err)
	}
	// A cut-off or an instance revocation during the write fails the request
	// closed. The erasure cascade does not cover this record, so undo it,
	// conditionally on this write: delete a new record, restore the evidence an
	// overwrite replaced.
	written := *rec
	undo := func(rctx context.Context) error {
		if written.Previous != nil {
			return s.keyAttestations.RestoreIfUnchanged(rctx, &written, written.Previous)
		}
		return s.keyAttestations.DeleteIfUnchanged(rctx, written.KeyThumbprint, written.WriteToken)
	}
	if err := tokengate.ConfirmWrite(ctx, s.users, undo); err != nil {
		return err
	}
	// The instance can be revoked during the write.
	if _, err := refuseWalletInstance(ctx, s.instances, req.WalletInstanceID, true); err != nil {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if rerr := undo(rctx); rerr != nil && !errors.Is(rerr, storage.ErrNotFound) {
			return errors.Join(err, fmt.Errorf("%w: %w", tokengate.ErrWriteNotRolledBack, rerr))
		}
		return err
	}

	s.logger.Info("FIDO2 hardware attestation verified",
		zap.String("wallet_instance_id", req.WalletInstanceID),
		zap.String("key_thumbprint", rec.KeyThumbprint),
		zap.Bool("uv", rec.UV),
	)

	return nil
}

// VerifyEvidence runs every verification step of Verify (CBOR decode,
// attestation signature, x5c chain against the FIDO MDS3 registry, key
// derivation) and returns the record Verify would store, WITHOUT storing
// anything. It is the single verifier: Verify persists its result, the
// assurance preview endpoint only reads it. The request's WalletInstanceID
// is optional here (a preview has no registration to attach it to).
func (s *FIDO2AttestationService) VerifyEvidence(ctx context.Context, req *FIDO2AttestationRequest) (*domain.KeyAttestationRecord, error) {
	if !s.IsEnabled() {
		return nil, ErrFIDO2AttestationDisabled
	}
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", ErrFIDO2AttestationInvalid)
	}
	if len(req.ClientDataHash) != 32 {
		return nil, fmt.Errorf("%w: client_data_hash must be 32 bytes, got %d", ErrFIDO2AttestationInvalid, len(req.ClientDataHash))
	}

	// Step 1: CBOR-decode the attestation object (fmt, authData, attStmt).
	var attObj protocol.AttestationObject
	if err := webauthncbor.Unmarshal(req.AttestationObject, &attObj); err != nil {
		return nil, fmt.Errorf("%w: cbor decode: %v", ErrFIDO2AttestationInvalid, err)
	}
	if err := attObj.AuthData.Unmarshal(attObj.RawAuthData); err != nil {
		return nil, fmt.Errorf("%w: parse authData: %v", ErrFIDO2AttestationInvalid, err)
	}
	if !attObj.AuthData.Flags.HasAttestedCredentialData() {
		return nil, fmt.Errorf("%w: authData missing attested credential data flag", ErrFIDO2AttestationInvalid)
	}

	// Step 2: verify the attestation statement's signature over
	// authData||clientDataHash using go-webauthn's format-specific handler
	// (packed/fido-u2f/etc. - handles COSE algorithm mapping and, notably,
	// BER-signature normalization for YubiKey firmware 5.8's non-minimally-
	// encoded ECDSA signatures). No metadata.Provider (nil) - that only
	// matters for FIDO MDS3-based trust-anchor lookup, which this v1
	// doesn't use; we do the trust-anchor check ourselves next, exactly
	// like NativeAttestationService.verifyAppleAppAttest does for x5c.
	//
	// go-webauthn 0.18 turned the BER tolerance into an explicit Relying Party
	// choice whose default is the conforming DER-only behaviour, so it has to
	// be selected here: taking the zero value would silently drop support for
	// exactly the authenticators the paragraph above says this depends on. The
	// library rightly calls the relaxation insecure - it makes a signature's
	// encoding malleable - and it is chosen deliberately because YubiKey
	// firmware 5.8 is a population we have to accept.
	policy := protocol.AttestationPolicy{}
	signature := protocol.SignaturePolicy{ECDSAEncoding: protocol.ECDSASignatureEncodingBER}
	if err := attObj.VerifyAttestation(req.ClientDataHash, nil, policy, signature); err != nil {
		return nil, fmt.Errorf("%w: attestation signature: %v", ErrFIDO2AttestationInvalid, err)
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
		return nil, fmt.Errorf("%w: no x5c attestation certificate chain present (self-attestation is not accepted)", ErrFIDO2AttestationInvalid)
	}

	x5cChain := make([]string, 0, len(x5cRaw))
	for i, raw := range x5cRaw {
		der, ok := raw.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: malformed x5c chain element %d", ErrFIDO2AttestationInvalid, i)
		}
		x5cChain = append(x5cChain, base64.StdEncoding.EncodeToString(der))
	}

	aaguid, err := uuid.FromBytes(attObj.AuthData.AttData.AAGUID)
	if err != nil {
		return nil, fmt.Errorf("%w: parse AAGUID: %v", ErrFIDO2AttestationInvalid, err)
	}

	trustInfo, err := s.trust.EvaluateFIDO2Attestation(ctx, aaguid.String(), x5cChain)
	if err != nil {
		return nil, fmt.Errorf("%w: trust evaluation: %v", ErrFIDO2AttestationInvalid, err)
	}
	if !trustInfo.Trusted {
		return nil, fmt.Errorf("%w: not trusted by FIDO MDS3 registry: %s", ErrFIDO2AttestationInvalid, trustInfo.Reason)
	}

	// Step 4: derive the attested credential key's own JWK Thumbprint from
	// its COSE public key (embedded in AttData, already decoded above) and
	// durably record the result keyed by that thumbprint - NOT by
	// wallet_instance_id, so a batch of credential-issuance keys generated
	// later via a different WSCD plugin can never inherit this key's
	// evidence (see domain.KeyAttestationRecord's doc comment).
	pubKeyAny, err := webauthncose.ParsePublicKey(attObj.AuthData.AttData.CredentialPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: parse credential public key: %v", ErrFIDO2AttestationInvalid, err)
	}
	ec2Key, ok := pubKeyAny.(webauthncose.EC2PublicKeyData)
	if !ok || ec2Key.Curve != int64(webauthncose.P256) {
		return nil, fmt.Errorf("%w: unsupported credential key type (only EC P-256 supported)", ErrFIDO2AttestationInvalid)
	}
	keyThumbprint, err := jwk.Thumbprint(map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(ec2Key.XCoord),
		"y":   base64.RawURLEncoding.EncodeToString(ec2Key.YCoord),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: compute key thumbprint: %v", ErrFIDO2AttestationInvalid, err)
	}

	// TenantID is for auditing/scoping only - best-effort lookup, not part
	// of the trust decision (which is keyed by thumbprint alone).
	var tenantID domain.TenantID
	if req.WalletInstanceID != "" {
		if instance, err := s.instances.GetByID(ctx, req.WalletInstanceID); err == nil {
			tenantID = instance.TenantID
		}
	}

	return &domain.KeyAttestationRecord{
		KeyThumbprint:    keyThumbprint,
		WalletInstanceID: req.WalletInstanceID,
		TenantID:         tenantID,
		Kind:             domain.KeyEvidenceFIDO2,
		Home:             domain.KeyHomeFIDO2Hardware,
		AAGUID:           aaguid.String(),
		UV:               attObj.AuthData.Flags.UserVerified() && authDataFlagsAreSigned(attObj.Format),
		VerifiedAt:       time.Now().UTC(),
	}, nil
}

// authDataFlagsAreSigned reports whether the attestation signature of a
// format covers the authenticator data flags. UV is only evidence when it
// does: in fido-u2f the signature is over rpIdHash, clientDataHash,
// credentialId and the public key, NOT over the flags (nor the counter), so a
// caller could set UV on an otherwise valid, trusted attestation. packed,
// apple (the certificate nonce, produced by Apple, is a hash over them) cover
// it. android-key and tpm do cover the flags cryptographically, but the
// signer is a key the caller controls the input to: an app can sign
// caller-constructed authData with an android credential key that needs no
// user authentication (the pinned verifier does not enforce the attested
// NoAuthRequired / UserAuthType), and a TPM attestation identity key certifies
// a caller-supplied hash. Their UV flag proves nothing. Anything else is not
// trusted for UV (fail closed).
func authDataFlagsAreSigned(format string) bool {
	switch format {
	case "packed", "apple":
		return true
	}
	return false
}
