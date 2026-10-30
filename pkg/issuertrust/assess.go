package issuertrust

import (
	"context"

	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
)

// Source is everything Assess needs about a provider. The engine and
// /v1/resolve both build one, so there is a single evaluation path and the two
// cannot drift apart.
type Source struct {
	// Metadata is the resolved metadata as published; it carries issuer_info.
	Metadata map[string]interface{}
	// SignerX5C is the x5c chain that signed the metadata, leaf first; empty
	// when it was not signed by a chain (which is a finding, in every mode).
	SignerX5C []string
	// ChainAnchored says the trust path accepted SignerX5C (see Input).
	ChainAnchored bool
	// Registrar asks the trust path whether a registration certificate's signer
	// is a trusted Registrar. Nil means there is no such path.
	Registrar RegistrarTrust
	// Configs are the configurations the flow can select, and IDs the ones it is
	// about to request (the offer, or the types a client asked about).
	Configs map[string]ConfigView
	IDs     []string
}

// Assess applies the ARF 6.6.2.3 provider checks. It returns nil only for
// ModeOff; otherwise a decision is always made, so "not checked" can only
// mean off.
func Assess(ctx context.Context, src Source, mode Mode) *Decision {
	if mode == ModeOff {
		return nil
	}
	cert := issuermetadata.RegistrationCertificate(src.Metadata)
	auth := AuthUnchecked
	if cert != "" {
		auth = AuthenticateRegistrationCert(ctx, cert, src.Registrar)
	}
	return Evaluate(Input{
		Chain:            ChainFromX5C(src.SignerX5C),
		ChainAnchored:    src.ChainAnchored,
		RegistrationCert: cert,
		RegistrationAuth: auth,
		Offers:           OffersFromConfigs(src.Configs, src.IDs),
	}, mode)
}
