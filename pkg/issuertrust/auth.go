package issuertrust

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// AuthResult is how far a registration certificate's signer was authenticated.
// The zero value is AuthUnchecked on purpose: forgetting the check must read
// as "not verified", never as a pass.
type AuthResult int

const (
	// AuthUnchecked: nobody authenticated the document (or could not).
	AuthUnchecked AuthResult = iota
	// AuthUntrustedRegistrar: the signature is valid but the trust evaluation
	// did not recognise the signer as a Registrar.
	AuthUntrustedRegistrar
	// AuthVerified: valid signature by a key the trust evaluation accepted as a
	// Registrar.
	AuthVerified
)

// RegistrarTrust asks the trust path (the go-trust PDP) whether an x5c chain
// belongs to a trusted Registrar. An error or a false answer both mean "not
// trusted"; the caller maps an evaluation that could not run to an error so it
// is never read as a denial or an approval.
type RegistrarTrust func(ctx context.Context, km *trust.KeyMaterial) (bool, error)

// AuthenticateRegistrationCert is step one of the three steps rpcert splits
// apart (verify, extract, evaluate), which that package leaves to the caller:
// it verifies the WRPRC's JWS signature against the x5c leaf in its own
// header, then asks the trust path whether that chain is a trusted Registrar.
// The trust decision stays in go-trust; nothing here holds a trust store.
//
// It never returns AuthVerified unless both succeed. The metadata signature
// does not substitute: it authenticates the metadata signer, who is the
// provider, and the provider must not be able to vouch for its own
// registration.
func AuthenticateRegistrationCert(ctx context.Context, token string, registrar RegistrarTrust) AuthResult {
	if registrar == nil {
		return AuthUnchecked
	}
	if !hasWRPRCType(token) {
		return AuthUnchecked
	}
	km, err := trust.VerifyJWTWithEmbeddedKey(token)
	if err != nil || km == nil || km.Type != "x5c" || len(km.X5C) == 0 {
		return AuthUnchecked
	}
	ok, err := registrar(ctx, km)
	if err != nil {
		return AuthUnchecked
	}
	if !ok {
		return AuthUntrustedRegistrar
	}
	return AuthVerified
}

// hasWRPRCType reports whether the JWT header declares typ rc-wrp+jwt
// (GEN-5.2.2-01), compared exactly like go-trust does.
func hasWRPRCType(token string) bool {
	head, _, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return false
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return false
	}
	return h.Typ == rpcert.WRPRCTyp
}
