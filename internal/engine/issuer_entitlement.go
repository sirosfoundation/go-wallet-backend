package engine

import (
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
)

// entitlementFor applies the ARF §6.6.2.3 provider checks to resolved issuer
// metadata: is the signing certificate a WRPAC, does the registration
// certificate describe this provider, and is it registered for the
// configurations being offered.
//
// It is a different question from the PDP's trust decision. A trusted issuer
// can still be unregistered for what it is proposing to issue, so this runs in
// addition to trust, not instead of it.
//
// Returns nil only when the mode is off. Otherwise a decision is always made:
// metadata that was never signed by a certificate chain yields a finding, and
// in fail mode that is a refusal, not a pass.
func entitlementFor(mode issuertrust.Mode, meta *metadataResult, configIDs []string) *issuertrust.Decision {
	if mode == issuertrust.ModeOff {
		return nil
	}
	return issuertrust.Evaluate(issuertrust.Input{
		Chain:            issuertrust.ChainFromX5C(meta.SignerX5C),
		RegistrationCert: issuermetadata.RegistrationCertificate(meta.Raw),
		Offers:           issuertrust.OffersFor(meta.Raw, configIDs),
	}, mode)
}

// checkIssuerEntitlement enforces entitlementFor for a flow. It returns an
// error only when the decision refuses issuance; in warn mode the findings are
// logged and reported to the client, and the flow continues.
func (h *OID4VCIHandler) checkIssuerEntitlement(issuer string, meta *metadataResult, offer *CredentialOffer) error {
	mode := issuertrust.ParseMode(h.Config.AuthZENProxy.IssuerEntitlementMode)
	d := entitlementFor(mode, meta, offer.CredentialConfigurationIDs)
	if d == nil {
		return nil
	}

	if len(d.Findings) > 0 {
		h.Logger.Warn("Issuer entitlement findings",
			zap.String("issuer", issuer),
			zap.String("mode", string(d.Mode)),
			zap.Bool("allowed", d.Allowed),
			zap.Any("findings", d.Findings))
		_ = h.Progress(StepTrustEvaluated, map[string]interface{}{
			"issuer_entitlement_evaluated": true,
			"issuer":                       issuer,
			"issuer_entitlement":           d,
		})
	}

	if d.Allowed {
		return nil
	}
	return fmt.Errorf("issuer %s is not registered to issue the requested credential: %s", issuer, describeFindings(d))
}

func describeFindings(d *issuertrust.Decision) string {
	parts := make([]string, 0, len(d.Findings))
	for _, f := range d.Findings {
		parts = append(parts, fmt.Sprintf("%s: %s", f.Code, f.Message))
	}
	return strings.Join(parts, "; ")
}
