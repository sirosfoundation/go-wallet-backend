package service

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/jwk"
)

// ErrAssuranceUnavailable is returned when the assurance policy is enabled
// but no usable policy is loaded. Key Attestation then fails closed instead
// of silently falling back to a different decision procedure.
var ErrAssuranceUnavailable = errors.New("assurance policy enabled but not loaded")

// KeyAttestationCaller identifies the authenticated caller of a KA request.
type KeyAttestationCaller struct {
	TenantID domain.TenantID
	// UserID is the authenticated user, empty when unknown.
	UserID string
}

type callerCtxKey struct{}

// WithKeyAttestationCaller records the authenticated caller in ctx so that
// GenerateKeyAttestation only accepts evidence from wallet instances that
// caller owns. Without it (internal callers, tests) no ownership check is
// made; the HTTP handler always sets it.
func WithKeyAttestationCaller(ctx context.Context, c KeyAttestationCaller) context.Context {
	return context.WithValue(ctx, callerCtxKey{}, c)
}

// lookupOwnedInstance loads an active wallet instance and, when the caller is
// known, requires it to belong to that caller: the same tenant, and the same user
// when the instance records one. A foreign instance is reported as not found,
// so another wallet's platform attestation can never raise this caller's KA.
func (s *WalletProviderService) lookupOwnedInstance(ctx context.Context, walletInstanceID string) (*domain.WalletInstance, error) {
	instance, err := s.instances.GetByID(ctx, walletInstanceID)
	if err != nil {
		return nil, err
	}
	// A suspended or revoked instance keeps its AttestationSource, but must
	// not keep lending platform evidence. An unset status (records that
	// predate the field) is not treated as deactivated.
	if instance.Status != "" && instance.Status != domain.InstanceStatusActive {
		s.logger.Warn("wallet instance is not active; ignoring its evidence",
			zap.String("wallet_instance_id", walletInstanceID), zap.String("status", string(instance.Status)))
		return nil, storage.ErrNotFound
	}
	// Platform integrity is re-derived on every WIA request, so it is only
	// as fresh as the last one. Evidence older than the WIA lifetime (the
	// same short window that bounds a WIA's exposure) is not used; an
	// instance that never recorded an attestation time has none.
	if age := time.Since(instance.LastAttestedAt); instance.LastAttestedAt.IsZero() || age > s.platformEvidenceMaxAge() {
		s.logger.Warn("wallet instance attestation is stale; ignoring its evidence",
			zap.String("wallet_instance_id", walletInstanceID), zap.Time("last_attested_at", instance.LastAttestedAt))
		return nil, storage.ErrNotFound
	}
	if caller, ok := ctx.Value(callerCtxKey{}).(KeyAttestationCaller); ok {
		if instance.TenantID != caller.TenantID ||
			(instance.UserID != nil && caller.UserID != "" && instance.UserID.String() != caller.UserID) {
			s.logger.Warn("wallet instance does not belong to the key attestation caller; ignoring its evidence",
				zap.String("wallet_instance_id", walletInstanceID))
			return nil, storage.ErrNotFound
		}
	}
	return instance, nil
}

// platformEvidenceMaxAge is how long after its last WIA an instance's
// platform attestation may still back a Key Attestation: the effective WIA
// lifetime (lifetime_seconds capped by wia.max_expiry_seconds), exactly what
// signWIA applies.
func (s *WalletProviderService) platformEvidenceMaxAge() time.Duration {
	d, _ := effectiveWIALifetime(s.cfg)
	return d
}

// SetAssessor installs the assurance policy used when
// wallet_provider.attestation.assurance.enabled is true.
func (s *WalletProviderService) SetAssessor(a *assurance.Assessor) {
	if a != nil {
		// iso_18045 also accepts the legacy SIROS vocabulary
		// ("software", "hardware", ...) the clients send, mapped exactly
		// as the non-policy path maps it.
		a.NormalizeClaim = func(schemeID, raw string) string {
			if schemeID == config.DefaultLevelSchemeID {
				v, _ := isoAttackPotential(raw, false)
				return v
			}
			return raw
		}
	}
	s.assessor = a
}

func (s *WalletProviderService) assuranceEnabled() bool {
	return s.cfg != nil && s.cfg.WalletProvider.Attestation.Assurance.Enabled
}

// assuranceFacts gathers what the backend itself verified for this request
// (per-key FIDO2 records, the instance's platform attestation source) and,
// separately, what the client claimed. Verified facts never come from the
// request.
func (s *WalletProviderService) assuranceFacts(ctx context.Context, walletInstanceID string, jwks []map[string]interface{}, secProps *SecurityProperties) assurance.Facts {
	var f assurance.Facts

	if walletInstanceID != "" && s.instances != nil {
		instance, err := s.lookupOwnedInstance(ctx, walletInstanceID)
		switch {
		case err == nil:
			if instance.AttestationSource != "" {
				f.Platform = &assurance.PlatformVerified{Source: instance.AttestationSource, AppID: instance.VerifiedAppID}
			}
		case !errors.Is(err, storage.ErrNotFound):
			s.logger.Warn("failed to look up wallet instance for assurance evidence", zap.Error(err))
		}
	}

	f.Fido2 = s.fido2Evidence(ctx, jwks)

	if secProps != nil {
		f.Claims = assurance.Claims{
			Plugin:             secProps.Plugin,
			KeyStorage:         secProps.KeyStorage,
			UserAuthentication: secProps.UserAuthentication,
			Certification:      secProps.Certification,
		}
	}
	return f
}

// batchThumbprints returns the RFC 7638 thumbprint of every key, or false
// when any key is malformed or unsupported (it then cannot have evidence).
func batchThumbprints(jwks []map[string]interface{}) ([]string, bool) {
	out := make([]string, 0, len(jwks))
	for _, j := range jwks {
		tp, err := jwk.Thumbprint(j)
		if err != nil {
			return nil, false
		}
		out = append(out, tp)
	}
	return out, true
}

// fido2Evidence returns the fido2 slot for a batch: only when EVERY key has a
// durably verified FIDO2 record, and all records agree on the AAGUID (a
// mixed batch has no single model to assert, so it is treated as
// unverified). User verification is "present" only when EVERY record carries
// the authenticator's user-verified flag.
func (s *WalletProviderService) fido2Evidence(ctx context.Context, jwks []map[string]interface{}) *assurance.Fido2Verified {
	tps, ok := batchThumbprints(jwks)
	if !ok {
		return nil
	}
	return s.fido2EvidenceFor(ctx, tps, nil)
}

// fido2EvidenceFor is fido2Evidence over thumbprints. overlay, when set, is
// a record the backend verified in this very request but did not persist (the
// preview's dry run); it answers for its own thumbprint, every other key is
// looked up in the store.
func (s *WalletProviderService) fido2EvidenceFor(ctx context.Context, thumbprints []string, overlay *domain.KeyAttestationRecord) *assurance.Fido2Verified {
	if len(thumbprints) == 0 || (s.keyAttestations == nil && overlay == nil) {
		return nil
	}
	aaguid := ""
	uv := true
	for i, thumbprint := range thumbprints {
		var rec *domain.KeyAttestationRecord
		if overlay != nil && overlay.KeyThumbprint == thumbprint {
			rec = overlay
		} else {
			if s.keyAttestations == nil {
				return nil
			}
			var err error
			rec, err = s.keyAttestations.GetByKeyThumbprint(ctx, thumbprint)
			if err != nil {
				if !errors.Is(err, storage.ErrNotFound) {
					s.logger.Warn("failed to look up key attestation for assurance evidence", zap.Error(err))
				}
				return nil
			}
		}
		if i == 0 {
			aaguid = rec.AAGUID
		} else if rec.AAGUID != aaguid {
			return nil
		}
		uv = uv && rec.UV
	}
	out := &assurance.Fido2Verified{AAGUID: aaguid}
	if uv {
		out.UV = assurance.UVPresent
	}
	return out
}

// assuranceBucketIndex maps a level's bucket onto the KA status list index.
func assuranceBucketIndex(b assurance.Bucket) int {
	switch b {
	case assurance.BucketHigh:
		return statusIndexKAHigh
	case assurance.BucketMiddle:
		return statusIndexKAModerate
	default:
		return statusIndexKABasic
	}
}

// applyAssurance runs the policy and returns the normalized security
// properties plus the key_storage_status index. The audit line records the
// rule ids, policy hash, schema version and chosen values, never the nonce.
func (s *WalletProviderService) applyAssurance(ctx context.Context, walletInstanceID string, jwks []map[string]interface{}, secProps *SecurityProperties) (*SecurityProperties, int, error) {
	if s.assessor == nil {
		return nil, 0, ErrAssuranceUnavailable
	}
	out := s.assessor.Assess(ctx, s.assuranceFacts(ctx, walletInstanceID, jwks, secProps))

	for _, err := range out.Errors {
		s.logger.Warn("assurance decider error treated as deny", zap.Error(err))
	}
	s.logger.Info("key attestation assurance decision",
		zap.String("wallet_instance_id", walletInstanceID),
		zap.Int("keys", len(jwks)),
		zap.String("policy_hash", out.PolicyVersion),
		zap.Int("schema_version", out.SchemaVersion),
		zap.Strings("rule_ids", out.RuleIDs()),
		zap.String("key_storage", out.KeyStorage.Value),
		zap.String("key_storage_granted", out.KeyStorage.Granted),
		zap.String("key_storage_claimed", out.KeyStorage.ClaimedLevel),
		zap.Strings("key_storage_rules", out.KeyStorage.RuleIDs),
		zap.String("user_authentication", out.UserAuthentication.Value),
		zap.String("user_authentication_granted", out.UserAuthentication.Granted),
		zap.String("user_authentication_claimed", out.UserAuthentication.ClaimedLevel),
		zap.Strings("user_authentication_rules", out.UserAuthentication.RuleIDs),
		zap.String("certification_entry", out.CertificationName),
		zap.Strings("certification_rules", out.CertificationRule),
	)

	props := &SecurityProperties{
		KeyStorage:         []string{out.KeyStorage.Value},
		UserAuthentication: []string{out.UserAuthentication.Value},
		Certification:      out.Certification,
	}
	idx := assuranceBucketIndex(out.KeyStorage.Scheme.StatusBucket(out.KeyStorage.LevelIndex))
	return props, idx, nil
}
