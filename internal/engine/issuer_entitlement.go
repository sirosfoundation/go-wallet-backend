package engine

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// entitlementFor applies the ARF §6.6.2.3 provider checks to resolved issuer
// metadata: is the signing certificate a WRPAC, is the registration
// certificate signed by a trusted registrar, does it describe this provider,
// and is it registered for the configurations being offered.
//
// It is a different question from the PDP's trust decision. A trusted issuer
// can still be unregistered for what it is proposing to issue, so this runs in
// addition to trust, not instead of it.
//
// auth is the outcome of authenticating the registration certificate's signer
// (see authenticateRegistration); its claims are not used unless it is
// issuertrust.AuthVerified.
//
// Returns nil only when the mode is off. Otherwise a decision is always made:
// metadata that was never signed by a certificate chain yields a finding, and
// in fail mode that is a refusal, not a pass.
func entitlementFor(mode issuertrust.Mode, meta *metadataResult, configIDs []string, auth entitlementAuth) *issuertrust.Decision {
	if mode == issuertrust.ModeOff {
		return nil
	}
	return issuertrust.Evaluate(issuertrust.Input{
		Chain:            issuertrust.ChainFromX5C(meta.SignerX5C),
		RegistrationCert: issuermetadata.RegistrationCertificate(meta.Raw),
		Offers:           issuertrust.OffersFor(meta.Raw, configIDs),
		ChainAnchored:    auth.chainAnchored,
		RegistrationAuth: auth.registration,
	}, mode)
}

// entitlementAuth is what the trust path established about the two documents
// the check reads. The zero value establishes nothing.
type entitlementAuth struct {
	registration  issuertrust.AuthResult // the registration certificate's signer
	chainAnchored bool                   // the chain that signed the metadata (the WRPAC)
}

// chainAnchored reports whether the trust path accepts the chain that signed
// the metadata. The issuer trust decision already made covers it when that was
// the chain evaluated; but extractIssuerKeyMaterial prefers mdoc_iacas_uri, so
// for an mdoc issuer the decision was about other certificates and the
// metadata signer has to be asked about separately, as an issuer. Without a
// PDP, or on any evaluation problem, it is not anchored.
func (h *OID4VCIHandler) chainAnchored(ctx context.Context, issuer string, meta *metadataResult) bool {
	if len(meta.SignerX5C) == 0 {
		return false
	}
	if slices.Equal(meta.SignerX5C, h.trustEvaluatedX5C) {
		return true // the decision made before this check was about this chain
	}
	if h.TrustSvc == nil || h.Config == nil {
		return false
	}
	endpoint := h.Config.Trust.GetIssuerPDPURL()
	if endpoint == "" {
		return false
	}
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		ctx = trust.ContextWithTenant(ctx, h.Flow.Session.TenantID)
	}
	info, err := h.TrustSvc.EvaluateIssuer(ctx, issuer, endpoint, &trust.KeyMaterial{Type: "x5c", X5C: meta.SignerX5C})
	return err == nil && info != nil && info.Trusted && !info.EvaluationFailed
}

// authenticateRegistration verifies the registration certificate's signature
// and asks the issuer PDP whether its signer is a trusted Registrar. The trust
// decision is the PDP's (ADR-012); with no PDP configured, or any evaluation
// error, the result is "unverified", which entitlementFor reports as a finding
// and, in fail mode, refuses.
func (h *OID4VCIHandler) authenticateRegistration(ctx context.Context, issuer string, meta *metadataResult) issuertrust.AuthResult {
	token := issuermetadata.RegistrationCertificate(meta.Raw)
	if token == "" || h.TrustSvc == nil || h.Config == nil {
		return issuertrust.AuthUnchecked
	}
	endpoint := h.Config.Trust.GetIssuerPDPURL()
	if endpoint == "" {
		return issuertrust.AuthUnchecked
	}
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		ctx = trust.ContextWithTenant(ctx, h.Flow.Session.TenantID)
	}
	return issuertrust.AuthenticateRegistrationCert(ctx, token, func(ctx context.Context, km *trust.KeyMaterial) (bool, error) {
		info, err := h.TrustSvc.EvaluateRegistrar(ctx, issuer, endpoint, km)
		if err != nil {
			return false, err
		}
		if info.EvaluationFailed {
			return false, fmt.Errorf("registrar evaluation failed")
		}
		return info.Trusted, nil
	})
}

// checkIssuerEntitlement enforces entitlementFor for a flow. It returns an
// error only when the decision refuses issuance; in warn mode the findings are
// logged and reported to the client, and the flow continues.
//
// The configurations checked are offer.CredentialConfigurationIDs, and
// awaitCredentialSelection lets the flow select nothing else, so what is
// issued is what was checked.
func (h *OID4VCIHandler) checkIssuerEntitlement(ctx context.Context, issuer string, meta *metadataResult, offer *CredentialOffer) error {
	mode := issuertrust.ParseMode(h.Config.AuthZENProxy.IssuerEntitlementMode)
	if mode == issuertrust.ModeOff {
		return nil
	}
	d := entitlementFor(mode, meta, offer.CredentialConfigurationIDs, entitlementAuth{
		registration:  h.authenticateRegistration(ctx, issuer, meta),
		chainAnchored: h.chainAnchored(ctx, issuer, meta),
	})
	if d == nil {
		return nil
	}

	if len(d.Findings) > 0 {
		// Codes only: finding text and issuer-controlled values stay out of the
		// log, as they do out of the client payload beyond the bounded fields.
		h.Logger.Warn("Issuer entitlement findings",
			zap.String("issuer", issuer),
			zap.String("mode", string(d.Mode)),
			zap.Bool("allowed", d.Allowed),
			zap.Bool("truncated", d.FindingsTruncated),
			zap.Strings("codes", findingCodeStrings(d)))
		// Additive to the issuer trust report: it deliberately does not set
		// issuer_trust_evaluated, which is what the SDKs key their trust report
		// on, so it can never be read as a trust decision.
		_ = h.Progress(StepTrustEvaluated, map[string]interface{}{
			"issuer_entitlement_evaluated": true,
			"issuer":                       issuer,
			"issuer_entitlement":           d.Summary(),
		})
	}

	if d.Allowed {
		return nil
	}
	return fmt.Errorf("issuer is not registered to issue the requested credential: %s", strings.Join(findingCodeStrings(d), ", "))
}

func findingCodeStrings(d *issuertrust.Decision) []string {
	codes := make([]string, 0, len(d.Findings))
	for _, f := range d.Findings {
		codes = append(codes, string(f.Code))
	}
	return codes
}
