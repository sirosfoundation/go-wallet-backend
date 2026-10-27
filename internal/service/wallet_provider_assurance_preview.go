package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// SetFIDO2Verifier installs the FIDO2 attestation verifier the assurance
// preview runs in dry-run mode.
func (s *WalletProviderService) SetFIDO2Verifier(v *FIDO2AttestationService) { s.fido2 = v }

// AssurancePreviewRequest is what a wallet submits to learn what a Key
// Attestation and a Wallet Instance Attestation would carry for it.
type AssurancePreviewRequest struct {
	// WalletInstanceID is optional. When set it must be an active wallet
	// instance of the caller (storage.ErrNotFound otherwise, so a foreign or
	// unknown instance is indistinguishable).
	WalletInstanceID string
	// JWKS are the keys the wallet would attest. Optional: when empty and a
	// FIDO2 attestation is submitted, the attested key is the batch.
	JWKS []map[string]interface{}
	// SecurityProperties are the claimed fields, as in a KA request.
	SecurityProperties *SecurityProperties
	// FIDO2 is the attestation the wallet would submit for registration. It
	// is verified here by the real verifier but never stored.
	FIDO2 *FIDO2AttestationRequest
}

// AssurancePreview is the dry-run result. Nothing was persisted and no
// attestation was issued.
type AssurancePreview struct {
	KeyStorage         []string    `json:"key_storage"`
	UserAuthentication []string    `json:"user_authentication"`
	Certification      interface{} `json:"certification"`
	// WIAProfile is the attestation_source value a WIA would carry.
	WIAProfile string `json:"wia_profile"`
	// WIAIssue is false when the policy would refuse the WIA.
	WIAIssue bool `json:"wia_issue"`
	// PolicyVersion is the policy hash; empty with the policy disabled.
	PolicyVersion string `json:"policy_version"`
	// SchemaVersion is the evidence schema version; 0 with the policy disabled.
	SchemaVersion int `json:"schema_version"`
	// AssuranceEnabled is false when these are the values the legacy
	// (pre-policy) path would produce.
	AssuranceEnabled bool `json:"assurance_enabled"`
	// FIDO2Verified reports whether the submitted FIDO2 attestation was
	// verified here and used as evidence. A submission that cannot be
	// verified (verifier disabled) counts for nothing.
	FIDO2Verified bool `json:"fido2_verified"`
}

// PreviewAssurance runs the same verifier and the same assessor as the real
// KA and WIA paths on the submitted facts, in dry-run mode: no record is
// stored, no WIA or KA is issued, no decision metric is recorded.
//
// Evidence discipline is the real path's: the FIDO2 attestation is verified
// here by FIDO2AttestationService (a failure is ErrFIDO2AttestationInvalid);
// the platform source is the caller's own wallet instance's; everything the
// caller merely states is claimed evidence.
func (s *WalletProviderService) PreviewAssurance(ctx context.Context, req *AssurancePreviewRequest) (*AssurancePreview, error) {
	if req == nil {
		req = &AssurancePreviewRequest{}
	}

	source, appID := "", ""
	if req.WalletInstanceID != "" && s.instances != nil {
		instance, err := s.lookupOwnedInstance(ctx, req.WalletInstanceID)
		if err != nil {
			return nil, err
		}
		source, appID = instance.AttestationSource, instance.VerifiedAppID
	}

	var overlay *domain.KeyAttestationRecord
	if req.FIDO2 != nil && s.fido2 != nil && s.fido2.IsEnabled() {
		rec, err := s.fido2.VerifyEvidence(ctx, req.FIDO2)
		if err != nil {
			return nil, err
		}
		overlay = rec
		// The dry run must answer what the real registration would leave in
		// place: a stored record that the submission would not supersede
		// (weaker or absent evidence is never written over it) wins.
		if s.keyAttestations != nil {
			if stored, err := s.keyAttestations.GetByKeyThumbprint(ctx, rec.KeyThumbprint); err == nil {
				if !rec.Supersedes(stored) {
					overlay = stored
				}
			} else if !errors.Is(err, storage.ErrNotFound) {
				// Without the stored record the dry run cannot say whether the
				// submission would replace it; a wrong preview is worse than none.
				return nil, fmt.Errorf("look up stored key evidence: %w", err)
			}
		}
	}

	var thumbprints []string
	if len(req.JWKS) > 0 {
		tps, ok := batchThumbprints(req.JWKS)
		if ok {
			thumbprints = tps
		}
	} else if overlay != nil {
		thumbprints = []string{overlay.KeyThumbprint}
	}

	out := &AssurancePreview{FIDO2Verified: overlay != nil, AssuranceEnabled: s.assuranceEnabled()}

	// What a WIA would carry assuming the wallet attests the way its
	// instance last did; an instance that never attested natively gets the
	// backend baseline.
	wiaSource := source
	if wiaSource == "" {
		wiaSource = "backend_attested"
	}

	if !s.assuranceEnabled() {
		trusted := false
		if req.SecurityProperties != nil {
			// A FIDO2 attestation verified in this request vouches for the
			// batch just as a stored record would.
			trusted = s.keyAttestationTrustsBatchWith(ctx, req.WalletInstanceID, req.JWKS, overlay) ||
				(len(req.JWKS) == 0 && overlay != nil && isFIDO2KeyEvidence(overlay))
		}
		n := normalizeSecurityProperties(req.SecurityProperties, trusted)
		out.KeyStorage, out.UserAuthentication, out.Certification = n.KeyStorage, n.UserAuthentication, n.Certification
		out.WIAProfile, out.WIAIssue = wiaSource, true
		return out, nil
	}

	if s.assessor == nil {
		return nil, ErrAssuranceUnavailable
	}

	kaFacts := assurance.Facts{Fido2: s.fido2EvidenceFor(ctx, req.WalletInstanceID, thumbprints, overlay)}
	if source != "" {
		kaFacts.Platform = &assurance.PlatformVerified{Source: source, AppID: appID}
	}
	if sp := req.SecurityProperties; sp != nil {
		kaFacts.Claims = assurance.Claims{
			Plugin: sp.Plugin, KeyStorage: sp.KeyStorage,
			UserAuthentication: sp.UserAuthentication, Certification: sp.Certification,
		}
	}
	// The WIA request carries no claims and no FIDO2 submission: its facts are
	// the platform source plus whatever verified evidence the store holds for
	// the instance key (the instance id is its thumbprint), exactly as
	// GenerateWIA builds them. The dry-run overlay never applies here.
	wiaFacts := assurance.Facts{Platform: &assurance.PlatformVerified{Source: wiaSource, AppID: appID}}
	if req.WalletInstanceID != "" && s.keyAttestations != nil {
		if rec, err := s.keyAttestations.GetByKeyThumbprint(ctx, req.WalletInstanceID); err == nil {
			if caller, ok := ctx.Value(callerCtxKey{}).(KeyAttestationCaller); ok && !instanceEvidenceInScope(rec, caller.TenantID, caller.UserID) {
				rec = nil
			}
			// The preview cannot answer 503: evidence that cannot be
			// re-checked (or no longer stands) is absent, the lowest tier.
			if rec != nil {
				var uerr error
				if rec, uerr = s.keyChecker.usable(ctx, s.keyAttestations, rec); uerr != nil {
					s.logger.Warn("instance key evidence cannot be re-checked; treating as none in the preview", zap.Error(uerr))
					rec = nil
				}
			}
			wiaFacts.Fido2 = fido2VerifiedFromRecord(rec)
			wiaFacts.InstanceKey = instanceKeyVerifiedFromRecord(rec)
		} else if !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("instance key evidence lookup failed; treating as none", zap.Error(err))
		}
	}

	ka, _ := s.assessor.Simulate(ctx, kaFacts)
	_, wia := s.assessor.Simulate(ctx, wiaFacts)
	for _, err := range append(append([]error{}, ka.Errors...), wia.Errors...) {
		s.logger.Warn("assurance decider error treated as deny", zap.Error(err))
	}

	out.KeyStorage = []string{ka.KeyStorage.Value}
	out.UserAuthentication = []string{ka.UserAuthentication.Value}
	out.Certification = ka.Certification
	out.WIAProfile, out.WIAIssue = wia.Profile.Value, wia.Issue
	out.PolicyVersion, out.SchemaVersion = ka.PolicyVersion, ka.SchemaVersion
	s.logger.Info("assurance preview",
		zap.String("wallet_instance_id", req.WalletInstanceID),
		zap.String("policy_hash", ka.PolicyVersion),
		zap.Strings("ka_rule_ids", ka.RuleIDs()),
		zap.Strings("wia_rule_ids", wia.RuleIDs()),
		zap.Bool("fido2_verified", overlay != nil),
	)
	return out, nil
}
