package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

// FIDO2 attestation as instance-key evidence.
//
// A wallet whose instance (PoP) key is a FIDO2 credential key sends the CTAP2
// makeCredential attestation object of that key with its WIA request:
//
//	{"type":"fido2","attestation_object":"<base64url>","client_data_hash":"<base64url>"}
//
// both unpadded base64url, as for POST /wallet-provider/fido2-attestation/register.
// It is verified by FIDO2AttestationService.VerifyEvidence, the same verifier
// that route uses. A FIDO2-requiring WIA policy needs it here: the route
// refuses an instance that does not exist, and the first WIA is what creates it.
//
// The instance key is a raw-signing key: the WSCD "fido2" plugin (CTAP2
// previewSign / rawSign) credential signs the PoP JWT's signing input itself.
// A standard WebAuthn passkey signs authenticatorData || clientDataHash instead,
// cannot produce the PoP, and so is not an instance key; there is no
// assertion-based possession path. Its attestation would verify, but the PoP
// key then differs from the attested key and the request is refused below.
//
// The attested credential key MUST be the PoP key (RFC 7638 thumbprints equal).
// The stored FIDO2 record is looked up by the PoP key's thumbprint, so evidence
// about another key would never count; refusing it here also stops a client
// from attaching someone else's genuine attestation object to its own WIA. The
// PoP proves possession of the attested private key. The attestation cannot
// carry the WIA challenge (its client data hash is fixed at makeCredential
// time), so freshness is the PoP and the single-use challenge of the request.

// maxFIDO2AttestationBytes bounds the decoded attestation object, well above
// real sizes (the assurance preview uses the same bound).
const maxFIDO2AttestationBytes = 32 * 1024

// fido2InstanceKeyRequest is the key_attestation object of this type.
type fido2InstanceKeyRequest struct {
	Type              KeyAttestationType `json:"type"`
	AttestationObject string             `json:"attestation_object"`
	ClientDataHash    string             `json:"client_data_hash"`
}

// FIDO2InstanceKeyVerifier verifies fido2 instance-key evidence. Register it
// with WIAService.RegisterInstanceKeyVerifier.
type FIDO2InstanceKeyVerifier struct {
	fido2  *FIDO2AttestationService
	logger *zap.Logger
}

// NewFIDO2InstanceKeyVerifier wraps the FIDO2 attestation verifier.
func NewFIDO2InstanceKeyVerifier(fido2 *FIDO2AttestationService, logger *zap.Logger) (*FIDO2InstanceKeyVerifier, error) {
	if fido2 == nil {
		return nil, errors.New("fido2 instance key verifier needs a FIDO2 attestation service")
	}
	return &FIDO2InstanceKeyVerifier{fido2: fido2, logger: logger.Named("fido2-instance-key")}, nil
}

// Type implements InstanceKeyEvidenceVerifier.
func (v *FIDO2InstanceKeyVerifier) Type() KeyAttestationType { return KeyAttestationFIDO2 }

func fido2InstanceKeyInvalid(format string, a ...any) error {
	return fmt.Errorf("%w: fido2: %s", ErrWIAKeyAttestationInvalid, fmt.Sprintf(format, a...))
}

// Verify implements InstanceKeyEvidenceVerifier. It stores nothing: the caller
// records the result under the PoP key's thumbprint with the request's scope,
// and undoes it if the request is then refused for a lifecycle reason.
func (v *FIDO2InstanceKeyVerifier) Verify(ctx context.Context, in *InstanceKeyEvidenceInput) (*InstanceKeyEvidenceResult, error) {
	var req fido2InstanceKeyRequest
	if err := json.Unmarshal(in.Payload, &req); err != nil {
		return nil, fido2InstanceKeyInvalid("malformed key_attestation")
	}
	obj, err := base64.RawURLEncoding.DecodeString(req.AttestationObject)
	if err != nil || len(obj) == 0 || len(obj) > maxFIDO2AttestationBytes {
		return nil, fido2InstanceKeyInvalid("attestation_object must be base64url (unpadded) and at most 32 KiB")
	}
	hash, err := base64.RawURLEncoding.DecodeString(req.ClientDataHash)
	if err != nil {
		return nil, fido2InstanceKeyInvalid("client_data_hash must be base64url (unpadded)")
	}

	rec, err := v.fido2.VerifyEvidence(ctx, &FIDO2AttestationRequest{
		WalletInstanceID:  in.Thumbprint,
		AttestationObject: obj,
		ClientDataHash:    hash,
	})
	switch {
	case errors.Is(err, ErrFIDO2AttestationDisabled):
		return nil, fmt.Errorf("%w: fido2 attestation is not enabled", ErrWIAKeyAttestationUnavailable)
	case errors.Is(err, ErrFIDO2AttestationUnavailable):
		return nil, fmt.Errorf("%w: fido2: %w", ErrWIAKeyAttestationUnavailable, err)
	case err != nil:
		return nil, fmt.Errorf("%w: fido2: %w", ErrWIAKeyAttestationInvalid, err)
	}
	if rec.KeyThumbprint == "" || rec.KeyThumbprint != in.Thumbprint {
		return nil, fido2InstanceKeyInvalid("the attested key is not the instance key")
	}
	return &InstanceKeyEvidenceResult{Record: rec}, nil
}
