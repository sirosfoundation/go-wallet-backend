package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// App Attest assertions as instance-key evidence.
//
// An App Attest key is assertion-only: it cannot sign a JWS, so it cannot be
// the WIA PoP key. What it can do is sign a statement. The wallet generates the
// instance (PoP) key, then asks its attested App Attest key for an assertion
// over
//
//	clientDataHash = SHA-256( "siros-instance-key-v1" || C || jkt )
//
// where C is the WIA challenge string exactly as issued (its ASCII bytes, as
// InstanceKeyAttestationChallenge defines) and jkt is the RFC 7638 thumbprint
// of the PoP key in its base64url no-padding string form (its ASCII bytes),
// appended with no separator. This verifier checks the assertion against the
// public key stored when that App Attest key was attested (ECDSA-SHA256 over
// the nonce SHA-256(authenticatorData || clientDataHash), so a double hash; see
// NativeAttestationService), and records:
//
//	kind app_attest_assertion, home secure_enclave_asserted, binding assertion
//
// WHAT THIS PROVES, AND WHAT IT DOES NOT. It proves that an attested app
// instance, holding a key Apple attested for this app, endorsed this PoP key at
// this challenge. It does NOT prove the PoP key lives in the Secure Enclave:
// the server never sees an attestation of the PoP key itself, and App Attest
// does not offer one for an arbitrary key. The home is therefore "asserted",
// ranks below tee, is rendered with binding assertion (never attested), and is
// never usable as a K (key storage) high by any shipped rule.
//
// Wire form: {"type":"app_attest_assertion","key_id":"<base64>","assertion":"<base64 CBOR>"}
// with the assertion CBOR {signature, authenticatorData} exactly as
// DCAppAttestService.generateAssertion returns it.

// Bounds on the submitted object, well above real sizes.
const (
	maxAppAttestAssertionBytes = 4 * 1024
	appAttestAssertionAuthLen  = 37 // rpIdHash (32) || flags (1) || counter (4)
)

// appAttestAssertionRequest is the key_attestation object of this type.
type appAttestAssertionRequest struct {
	Type      KeyAttestationType `json:"type"`
	KeyID     string             `json:"key_id"`
	Assertion string             `json:"assertion"`
}

// appAttestAssertionObject is the CBOR App Attest returns from generateAssertion.
type appAttestAssertionObject struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

// AppAttestClientDataHash is the client data hash the wallet must pass to
// generateAssertion for the instance key with RFC 7638 thumbprint jkt and WIA
// challenge wiaChallenge. See the file comment for the encoding.
func AppAttestClientDataHash(wiaChallenge, jkt string) []byte {
	h := sha256.New()
	h.Write([]byte(instanceKeyChallengeLabel))
	h.Write([]byte(wiaChallenge))
	h.Write([]byte(jkt))
	return h.Sum(nil)
}

// AppAttestAssertionVerifier verifies app_attest_assertion instance-key
// evidence. Register it with WIAService.RegisterInstanceKeyVerifier.
type AppAttestAssertionVerifier struct {
	keys storage.AppAttestKeyStore
	// appID is the App ID (TeamID.BundleID) the assertion's rpIdHash must match.
	appID string
	// env is the App Attest environment this backend is configured for; a key
	// attested in another environment is refused.
	env    domain.AppAttestEnvironment
	logger *zap.Logger
}

// NewAppAttestAssertionVerifier builds the verifier from the stored App Attest
// keys and the configured App ID and environment (as for native attestation).
func NewAppAttestAssertionVerifier(keys storage.AppAttestKeyStore, appID, environment string, logger *zap.Logger) (*AppAttestAssertionVerifier, error) {
	if keys == nil {
		return nil, errors.New("app attest assertion verifier needs a key store")
	}
	if appID == "" {
		return nil, errors.New("app attest assertion verifier needs apple_app_id")
	}
	env, _, err := appAttestEnvironment(environment)
	if err != nil {
		return nil, err
	}
	return &AppAttestAssertionVerifier{keys: keys, appID: appID, env: env, logger: logger.Named("app-attest-assertion")}, nil
}

// Type implements InstanceKeyEvidenceVerifier.
func (v *AppAttestAssertionVerifier) Type() KeyAttestationType {
	return KeyAttestationAppAttestAssertion
}

func assertionInvalid(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrWIAKeyAttestationInvalid}, a...)...)
}

// Verify implements InstanceKeyEvidenceVerifier. Order matters: everything
// that needs no state is checked first, the signature is verified BEFORE the
// counter is advanced (an unauthenticated request must not be able to burn a
// key's counter), and the counter advance is one atomic compare-and-set.
func (v *AppAttestAssertionVerifier) Verify(ctx context.Context, in *InstanceKeyEvidenceInput) (*InstanceKeyEvidenceResult, error) {
	if len(in.Payload) > maxAppAttestAssertionBytes*2 {
		return nil, assertionInvalid("key_attestation too large")
	}
	var req appAttestAssertionRequest
	if err := json.Unmarshal(in.Payload, &req); err != nil {
		return nil, assertionInvalid("malformed key_attestation")
	}
	rawKeyID, err := decodeAppAttestKeyID(req.KeyID)
	if err != nil {
		return nil, assertionInvalid("%v", err)
	}
	keyID := canonicalAppAttestKeyID(rawKeyID)

	assertionBytes, err := base64.StdEncoding.DecodeString(req.Assertion)
	if err != nil || len(assertionBytes) == 0 || len(assertionBytes) > maxAppAttestAssertionBytes {
		return nil, assertionInvalid("assertion is not base64 or has an unreasonable size")
	}
	var obj appAttestAssertionObject
	if err := cbor.Unmarshal(assertionBytes, &obj); err != nil {
		return nil, assertionInvalid("assertion is not valid CBOR")
	}
	if len(obj.AuthenticatorData) < appAttestAssertionAuthLen || len(obj.Signature) == 0 {
		return nil, assertionInvalid("assertion is incomplete")
	}

	// The stored key: the only source of the public key. A key the backend
	// never attested, or attested for someone else, or revoked, is no evidence.
	rec, err := v.keys.Get(ctx, keyID)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return nil, assertionInvalid("unknown App Attest key")
	case err != nil:
		return nil, fmt.Errorf("%w: load App Attest key: %v", ErrWIAKeyAttestationUnavailable, err)
	}
	if !rec.IsActive() {
		return nil, assertionInvalid("App Attest key is not active")
	}
	var user *domain.UserID
	if in.UserID != "" {
		u := domain.UserIDFromString(in.UserID)
		user = &u
	}
	if !rec.BelongsTo(in.TenantID, user) {
		return nil, assertionInvalid("App Attest key belongs to another context")
	}
	if rec.Environment != v.env {
		return nil, assertionInvalid("App Attest key was attested in another environment")
	}
	pub, err := appAttestPublicKey(rec.PublicKey)
	if err != nil {
		return nil, assertionInvalid("stored key is unusable")
	}

	// rpIdHash = SHA-256(App ID).
	rp := sha256.Sum256([]byte(v.appID))
	if subtle.ConstantTimeCompare(obj.AuthenticatorData[:32], rp[:]) != 1 {
		return nil, assertionInvalid("rpIdHash does not match the App ID")
	}

	// Signature: Apple defines nonce = SHA-256(authenticatorData ||
	// clientDataHash) and the signature is ECDSA-with-SHA-256 over that nonce,
	// i.e. over a second hash of it: the digest handed to ECDSA verification is
	// SHA-256(nonce). clientDataHash binds this WIA challenge and this PoP key.
	cdh := AppAttestClientDataHash(in.WIAChallenge, in.Thumbprint)
	nonce := sha256.Sum256(append(append([]byte{}, obj.AuthenticatorData...), cdh...))
	digest := sha256.Sum256(nonce[:])
	if !ecdsa.VerifyASN1(pub, digest[:], obj.Signature) {
		return nil, assertionInvalid("assertion signature does not verify")
	}

	// Counter: strictly greater than the stored one, advanced atomically. The
	// store's conditional update is the replay protection; the comparison here
	// only gives a precise error before touching it.
	counter := binary.BigEndian.Uint32(obj.AuthenticatorData[33:37])
	if counter <= rec.Counter {
		return nil, assertionInvalid("assertion counter %d is not above %d (replay)", counter, rec.Counter)
	}
	if err := v.keys.AdvanceCounter(ctx, keyID, counter); err != nil {
		switch {
		case errors.Is(err, storage.ErrCounterNotAdvanced), errors.Is(err, storage.ErrNotFound):
			return nil, assertionInvalid("assertion counter was already used")
		default:
			return nil, fmt.Errorf("%w: advance App Attest counter: %v", ErrWIAKeyAttestationUnavailable, err)
		}
	}

	// A development key, or one whose chain could not be verified, proved
	// nothing about the device: the assertion is sound but names no home.
	if !rec.VerifiedHomeEligible() {
		v.logger.Info("assertion accepted but names no home",
			zap.String("environment", string(rec.Environment)), zap.Bool("chain_verified", rec.ChainVerified))
		return &InstanceKeyEvidenceResult{Reason: "app attest key is not a verified production key"}, nil
	}
	return &InstanceKeyEvidenceResult{Record: &domain.KeyAttestationRecord{
		Kind: domain.KeyEvidenceAppAttestAssertion,
		// Asserted, not attested: an attested app instance endorsed the key.
		Home:       domain.KeyHomeSecureEnclaveAsserted,
		VerifiedAt: in.Now,
	}}, nil
}

// appAttestPublicKey rebuilds an ECDSA P-256 key from a stored X9.62
// uncompressed point; a point that is not on the curve is refused.
func appAttestPublicKey(point []byte) (*ecdsa.PublicKey, error) {
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

// appAttestAssertionBuilder renders a stored app_attest_assertion record as the
// instance_key evidence slot. The binding is ALWAYS assertion and the home is
// only ever the asserted one: a record that says anything stronger is not
// rendered at all, so this evidence family can never read as attested. No
// level or boot state is rendered; an assertion reports neither.
type appAttestAssertionBuilder struct{}

func (appAttestAssertionBuilder) Kind() domain.KeyEvidenceKind {
	return domain.KeyEvidenceAppAttestAssertion
}

func (appAttestAssertionBuilder) Build(rec *domain.KeyAttestationRecord) *assurance.InstanceKeyVerified {
	if rec.Home != domain.KeyHomeSecureEnclaveAsserted {
		return nil
	}
	return &assurance.InstanceKeyVerified{
		Kind:    string(domain.KeyEvidenceAppAttestAssertion),
		Home:    string(domain.KeyHomeSecureEnclaveAsserted),
		Binding: assurance.BindingAssertion,
	}
}
