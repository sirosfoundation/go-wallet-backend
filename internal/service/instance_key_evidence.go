package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// This file is the envelope for evidence about the WIA instance key (the PoP
// key): the optional `key_attestation` field of POST
// /wallet-provider/wia/generate. The field is a JSON object whose `type`
// selects a verifier; every other member belongs to that verifier. Verifiers
// register by type (WIAService.RegisterInstanceKeyVerifier), so adding an
// evidence family never touches another family's verifier:
//
//	android_key            {type, x5c:[base64 DER, leaf first]}   (android_key_attestation.go)
//	app_attest_assertion   {type, key_id, assertion}              (registered by its own stage)
//
// Rules of the envelope:
//   - the field absent: no instance-key evidence, the home stays unknown;
//   - `type` not registered: the request is rejected before the single-use
//     challenge is consumed (ErrWIAKeyAttestationTypeUnsupported, HTTP 400);
//   - evidence submitted but INVALID (malformed, bad signature, wrong
//     challenge or key, revoked): the WIA is refused, like a failing native
//     attestation (ErrWIAKeyAttestationInvalid, HTTP 400);
//   - the evidence cannot be judged because a dependency of the check is
//     unavailable (for example a revocation list): the WIA is refused and
//     nothing is recorded (ErrWIAKeyAttestationUnavailable, HTTP 503);
//   - evidence that is well formed but not trustworthy enough to name a home
//     (unknown root, software keystore, ...): the verifier returns no
//     record; the WIA issues with the home unknown.

var (
	// ErrWIAKeyAttestationTypeUnsupported means the key_attestation type has
	// no registered verifier.
	ErrWIAKeyAttestationTypeUnsupported = errors.New("key_attestation type is not supported")
	// ErrWIAKeyAttestationInvalid means submitted key_attestation evidence
	// failed verification. Verifiers wrap it.
	ErrWIAKeyAttestationInvalid = errors.New("key_attestation evidence is invalid")
	// ErrWIAKeyAttestationUnavailable means the evidence could not be judged
	// because a dependency (such as a revocation list) is unavailable. Fail
	// closed: nothing is recorded and the WIA is refused.
	ErrWIAKeyAttestationUnavailable = errors.New("key_attestation cannot be verified right now")
)

// maxKeyAttestationBytes bounds the encoded key_attestation object a verifier
// is handed.
const maxKeyAttestationBytes = 128 * 1024

// instanceKeyChallengeLabel domain-separates the instance-key attestation
// challenge from every other use of the WIA challenge.
const instanceKeyChallengeLabel = "siros-instance-key-v1"

// InstanceKeyAttestationChallenge is the challenge an instance-key evidence
// family that has a challenge slot (Android key attestation) must embed:
//
//	SHA-256( "siros-instance-key-v1" || C )
//
// where C is the WIA challenge string EXACTLY as the challenge endpoint
// returned it, as its ASCII/UTF-8 bytes (it is base64url without padding; it
// is NOT decoded first), appended with no separator. The result is 32 bytes.
// A client computes the same value and passes it to
// KeyGenParameterSpec.Builder.setAttestationChallenge.
func InstanceKeyAttestationChallenge(wiaChallenge string) []byte {
	h := sha256.New()
	h.Write([]byte(instanceKeyChallengeLabel))
	h.Write([]byte(wiaChallenge))
	return h.Sum(nil)
}

// KeyAttestationType names a family of instance-key evidence.
type KeyAttestationType string

const (
	KeyAttestationAndroidKey         KeyAttestationType = "android_key"
	KeyAttestationAppAttestAssertion KeyAttestationType = "app_attest_assertion"
)

// KeyAttestation is the `key_attestation` request object. Only Type is read
// by the envelope; Raw is the whole object for the type's verifier to decode
// (members of other types are ignored by it).
type KeyAttestation struct {
	Type KeyAttestationType
	Raw  json.RawMessage
}

// UnmarshalJSON reads the object and keeps its encoding for the verifier.
func (k *KeyAttestation) UnmarshalJSON(data []byte) error {
	if len(data) > maxKeyAttestationBytes {
		return fmt.Errorf("key_attestation exceeds %d bytes", maxKeyAttestationBytes)
	}
	var head struct {
		Type KeyAttestationType `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return fmt.Errorf("key_attestation: %w", err)
	}
	k.Type = head.Type
	k.Raw = append(k.Raw[:0], data...)
	return nil
}

// MarshalJSON writes the object as it was received.
func (k KeyAttestation) MarshalJSON() ([]byte, error) {
	if len(k.Raw) == 0 {
		return json.Marshal(struct {
			Type KeyAttestationType `json:"type"`
		}{k.Type})
	}
	return k.Raw, nil
}

// InstanceKeyEvidenceInput is what a verifier is given. Everything in it
// except Payload was established by the backend, not claimed by the client.
type InstanceKeyEvidenceInput struct {
	// Payload is the whole key_attestation object.
	Payload json.RawMessage
	// PoPKey is the validated WIA-PoP public key: the key the evidence must
	// be about.
	PoPKey *ecdsa.PublicKey
	// Thumbprint is the RFC 7638 JWK thumbprint of PoPKey (the instance id).
	Thumbprint string
	// TenantID is the authenticated tenant of the request.
	TenantID domain.TenantID
	// UserID is the authenticated user, "" when unknown.
	UserID string
	// WIAChallenge is the consumed WIA challenge C, as issued. Use
	// InstanceKeyAttestationChallenge for a derived challenge.
	WIAChallenge string
	// Now is the verification time (chains are checked at submission time).
	Now time.Time
}

// InstanceKeyEvidenceResult is the outcome of a verification that did not
// fail.
type InstanceKeyEvidenceResult struct {
	// Record is the verified per-key evidence record to store (Kind, Home
	// and the evidence fields set; KeyThumbprint, WalletInstanceID, TenantID
	// and VerifiedAt are completed by the caller if empty). Nil means the
	// evidence names no home: nothing is recorded and the WIA still issues
	// with the home unknown.
	Record *domain.KeyAttestationRecord
	// Reason says why Record is nil, for logs and audit. Never client text.
	Reason string
}

// InstanceKeyEvidenceVerifier verifies one family of instance-key evidence.
// Verify returns an error wrapping ErrWIAKeyAttestationInvalid for evidence
// that is invalid, ErrWIAKeyAttestationUnavailable when it cannot be judged,
// and a result with a nil Record for evidence that is sound but names no
// home. It must never panic on hostile input and must verify nothing it
// takes from the client without a signature.
type InstanceKeyEvidenceVerifier interface {
	Type() KeyAttestationType
	Verify(ctx context.Context, in *InstanceKeyEvidenceInput) (*InstanceKeyEvidenceResult, error)
}

// RegisterInstanceKeyVerifier registers v for its type, replacing an earlier
// registration. Call it while wiring the service, before requests are served.
func (s *WIAService) RegisterInstanceKeyVerifier(v InstanceKeyEvidenceVerifier) {
	if s.keyVerifiers == nil {
		s.keyVerifiers = make(map[KeyAttestationType]InstanceKeyEvidenceVerifier)
	}
	s.keyVerifiers[v.Type()] = v
}

// InstanceKeyVerifierTypes lists the registered types, sorted.
func (s *WIAService) InstanceKeyVerifierTypes() []string {
	out := make([]string, 0, len(s.keyVerifiers))
	for t := range s.keyVerifiers {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}

// keyVerifierFor resolves the verifier for a request, nil when the request
// has no key_attestation.
func (s *WIAService) keyVerifierFor(ka *KeyAttestation) (InstanceKeyEvidenceVerifier, error) {
	if ka == nil {
		return nil, nil
	}
	v, ok := s.keyVerifiers[ka.Type]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrWIAKeyAttestationTypeUnsupported, truncateForError(string(ka.Type)))
	}
	return v, nil
}

func truncateForError(v string) string {
	if len(v) > 40 {
		return v[:40] + "..."
	}
	return v
}

// verifyKeyAttestation runs the verifier for the request's key_attestation and
// stores a resulting record under the instance key's thumbprint (the store
// refuses to replace stronger evidence with weaker). It returns the record the
// submission produced, nil when it named no home.
func (s *WIAService) verifyKeyAttestation(ctx context.Context, v InstanceKeyEvidenceVerifier, ka *KeyAttestation, tenantID domain.TenantID, userID, jkt string, pop *ecdsa.PublicKey, challenge string) (*domain.KeyAttestationRecord, error) {
	now := time.Now().UTC()
	res, err := v.Verify(ctx, &InstanceKeyEvidenceInput{
		Payload:      ka.Raw,
		PoPKey:       pop,
		Thumbprint:   jkt,
		TenantID:     tenantID,
		UserID:       userID,
		WIAChallenge: challenge,
		Now:          now,
	})
	if err != nil {
		if errors.Is(err, ErrWIAKeyAttestationUnavailable) || errors.Is(err, ErrWIAKeyAttestationInvalid) {
			return nil, err
		}
		// An error a verifier did not classify is a failed verification.
		return nil, fmt.Errorf("%w: %v", ErrWIAKeyAttestationInvalid, err)
	}
	if res == nil || res.Record == nil {
		reason := ""
		if res != nil {
			reason = res.Reason
		}
		s.logger.Info("instance key evidence names no home",
			zap.String("type", truncateForError(string(ka.Type))), zap.String("reason", reason))
		return nil, nil
	}
	rec := res.Record.Clone()
	// The key and scope are the backend's, whatever the verifier put there.
	rec.KeyThumbprint = jkt
	rec.WalletInstanceID = jkt
	rec.TenantID = tenantID
	rec.UserID = userID
	if rec.VerifiedAt.IsZero() {
		rec.VerifiedAt = now
	}
	if s.keyAttestations != nil {
		if err := s.keyAttestations.MarkKeyAttested(ctx, rec); err != nil {
			return nil, fmt.Errorf("%w: store instance key evidence: %v", ErrWIAKeyAttestationUnavailable, err)
		}
	}
	return rec, nil
}

// instanceEvidenceInScope reports whether a stored instance-key record may be
// used for a request of (tenantID, userID). Evidence of a kind other than FIDO2
// is bound to the tenant and, when it was verified for a user, to that user;
// a request without the user it was verified for cannot reuse it. FIDO2
// records predate the scope fields and are keyed by the key alone.
func instanceEvidenceInScope(rec *domain.KeyAttestationRecord, tenantID domain.TenantID, userID string) bool {
	n := *rec
	n.Normalize()
	if n.Kind == domain.KeyEvidenceFIDO2 && n.UserID == "" {
		return true
	}
	if n.TenantID != tenantID {
		return false
	}
	return n.UserID == "" || n.UserID == userID
}
