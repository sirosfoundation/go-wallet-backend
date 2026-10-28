package engine

import "encoding/json"

// Values of VerifiedRequestInputs.SignatureVerification.
const (
	// SignatureVerified: the engine verified the request object's signature
	// against a key the client_id scheme binds to client_id.
	SignatureVerified = "verified"
	// SignatureDeferred: the engine could not check and left it to the
	// client (did: with no verifier PDP configured, verifier_attestation
	// with no PDP to validate the attestation). The client must not treat
	// this as verified.
	SignatureDeferred = "deferred"
	// SignatureNone: nothing the engine established binds a signature to
	// client_id (redirect_uri, or an unsigned request).
	SignatureNone = "none"
)

// VerifiedRequestInputs is the OpenID4VP request as the engine validated it.
// It is built once (evaluateVerifierTrust) and emitted identically in
// credential_selection, match_request and sign_presentation, so a client that
// has to apply a policy over a flow (for example refusing a zkp_req over a
// non-encrypted response_mode) reads the same inputs at every step.
//
// It carries no trust verdict: the client must still require
// verifier.trusted. All members are additive; older clients ignore them.
type VerifiedRequestInputs struct {
	// ClientID is the request's own client_id after the client_id match and
	// scheme-prefix checks. Not the admin-configured VP audience that
	// verifier.client_id carries.
	ClientID       string `json:"client_id"`
	ClientIDScheme string `json:"client_id_scheme,omitempty"`
	// ResponseMode is direct_post, direct_post.jwt, query, fragment, ...
	ResponseMode string `json:"response_mode,omitempty"`
	// ResponseURI is the validated response_uri (redirect_uri when the
	// request has no response_uri, as for the redirect response modes).
	ResponseURI string `json:"response_uri,omitempty"`
	// Signed is true only when SignatureVerification is "verified": a
	// request-object signature checked against a key the scheme binds to
	// client_id (x509_san_dns/x509_san_uri/x509_hash: the header x5c;
	// did: the resolved DID key, PDP path only; verifier_attestation: the
	// attestation cnf key, PDP path only). Always false for redirect_uri,
	// where a valid embedded key proves possession and nothing more.
	Signed bool `json:"signed"`
	// SignatureVerification is "verified", "deferred" or "none".
	SignatureVerification string `json:"signature_verification"`
	// ClientMetadata is the verifier's client_metadata verbatim.
	ClientMetadata json.RawMessage `json:"client_metadata,omitempty"`
}

func newVerifiedRequestInputs(authReq *AuthorizationRequest, signature string) *VerifiedRequestInputs {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}
	if authReq.ClientIDScheme == ClientIDSchemeRedirectURI {
		// A valid embedded key proves possession only.
		signature = SignatureNone
	}
	return &VerifiedRequestInputs{
		ClientID:              authReq.ClientID,
		ClientIDScheme:        authReq.ClientIDScheme,
		ResponseMode:          authReq.ResponseMode,
		ResponseURI:           responseURI,
		Signed:                signature == SignatureVerified,
		SignatureVerification: signature,
		ClientMetadata:        authReq.ClientMetadataRaw,
	}
}

// verifiedInputs returns the inputs evaluateVerifierTrust built. A request
// that never went through it gets the conservative form (nothing verified),
// never a guess at more.
func verifiedInputs(authReq *AuthorizationRequest) *VerifiedRequestInputs {
	if authReq.Verified == nil {
		authReq.Verified = newVerifiedRequestInputs(authReq, SignatureNone)
	}
	return authReq.Verified
}
