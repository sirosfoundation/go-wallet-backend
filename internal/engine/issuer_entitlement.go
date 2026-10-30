package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// errIssuerNotEntitled is what checkIssuerEntitlement returns for a refusal, so
// the caller can tell it from anything else going wrong.
var errIssuerNotEntitled = errors.New("issuer is not registered to issue the requested credential")

// entitlementFor applies the ARF §6.6.2.3 provider checks (see
// issuertrust.Assess, which /v1/resolve calls too) to resolved issuer
// metadata: is the signing certificate a trusted WRPAC, is the registration
// certificate signed by a trusted registrar, does it describe this provider,
// and is it registered for the configurations being offered.
//
// It is a different question from the PDP's trust decision. A trusted issuer
// can still be unregistered for what it is proposing to issue, so this runs in
// addition to trust, not instead of it.
//
// The offered configurations are read from the parsed metadata, the same
// configurations awaitCredentialSelection accepts, not from a second reading
// of the raw document: what can be selected is what is checked.
//
// Returns nil only when the mode is off.
func entitlementFor(ctx context.Context, mode issuertrust.Mode, meta *metadataResult, configIDs []string, registrar issuertrust.RegistrarTrust, chainAnchored bool) *issuertrust.Decision {
	configs := map[string]issuertrust.ConfigView{}
	if meta.Metadata != nil {
		for id, c := range meta.Metadata.CredentialConfigurationsSupported {
			configs[id] = issuertrust.ConfigView{Format: c.Format, VCT: c.VCT, Doctype: c.Doctype}
		}
	}
	return issuertrust.Assess(ctx, issuertrust.Source{
		Metadata:      meta.Raw,
		SignerX5C:     meta.SignerX5C,
		ChainAnchored: chainAnchored,
		Registrar:     registrar,
		Configs:       configs,
		IDs:           configIDs,
	}, mode)
}

// registrarTrust is the RegistrarTrust the engine uses: the issuer PDP,
// action trust.RegistrarAction (ADR-012). With no PDP, or on any evaluation
// error, the answer is "cannot tell", never "trusted".
func (h *OID4VCIHandler) registrarTrust(issuer string) issuertrust.RegistrarTrust {
	if h.TrustSvc == nil || h.Config == nil {
		return nil
	}
	endpoint := h.Config.Trust.GetIssuerPDPURL()
	if endpoint == "" {
		return nil
	}
	return func(ctx context.Context, km *trust.KeyMaterial) (bool, error) {
		info, err := h.TrustSvc.EvaluateRegistrar(h.withTenant(ctx), issuer, endpoint, km)
		if err != nil {
			return false, err
		}
		if info.EvaluationFailed {
			return false, errors.New("registrar evaluation failed")
		}
		return info.Trusted, nil
	}
}

func (h *OID4VCIHandler) withTenant(ctx context.Context) context.Context {
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		return trust.ContextWithTenant(ctx, h.Flow.Session.TenantID)
	}
	return ctx
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
	info, err := h.TrustSvc.EvaluateIssuer(h.withTenant(ctx), issuer, endpoint, &trust.KeyMaterial{Type: "x5c", X5C: meta.SignerX5C})
	return err == nil && info != nil && info.Trusted && !info.EvaluationFailed
}

// checkIssuerEntitlement enforces entitlementFor for a flow. It returns
// errIssuerNotEntitled (with the decision, for the caller to report) only when
// the decision refuses issuance; in warn mode the findings are logged and
// reported to the client, and the flow continues.
//
// The configurations checked are offer.CredentialConfigurationIDs, and
// awaitCredentialSelection lets the flow select nothing else, so what is
// issued is what was checked.
func (h *OID4VCIHandler) checkIssuerEntitlement(ctx context.Context, issuer string, meta *metadataResult, offer *CredentialOffer) (*issuertrust.Decision, error) {
	mode := issuertrust.ParseMode(h.Config.EffectiveIssuerEntitlementMode())
	if mode == issuertrust.ModeOff {
		return nil, nil
	}
	d := entitlementFor(ctx, mode, meta, offer.CredentialConfigurationIDs, h.registrarTrust(issuer), h.chainAnchored(ctx, issuer, meta))
	if d == nil {
		return nil, nil
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
		return d, nil
	}
	return d, fmt.Errorf("%w: %s", errIssuerNotEntitled, strings.Join(findingCodeStrings(d), ", "))
}

// failNotEntitled reports an entitlement refusal to the client: code
// ISSUER_NOT_ENTITLED, the fixed message, and details carrying the issuer and
// the same bounded decision the progress message carries.
func (h *OID4VCIHandler) failNotEntitled(issuer string, d *issuertrust.Decision) {
	details := map[string]interface{}{"issuer": issuer}
	if d != nil {
		details["issuer_entitlement"] = d.Summary()
	}
	_ = h.ErrorWithDetails(StepEvaluatingTrust, ErrCodeIssuerNotEntitled, ErrCodeIssuerNotEntitled.UserFacingMessage(), details)
}

func findingCodeStrings(d *issuertrust.Decision) []string {
	codes := make([]string, 0, len(d.Findings))
	for _, f := range d.Findings {
		codes = append(codes, string(f.Code))
	}
	return codes
}
