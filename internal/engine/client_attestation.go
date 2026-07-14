package engine

import (
	"context"
	"net/http"
)

// ClientAttestationProvider supplies OAuth Client Attestation credentials
// per draft-ietf-oauth-attestation-based-client-auth-04 §3.1.
//
// This interface is transport-independent: the wallet frontend/SDK always
// manages the instance key (in passkey-PRF-encrypted private data) and
// generates both the WIA and PoP. The backend simply forwards them as
// HTTP headers to the issuer's PAR/token endpoint.
//
// The two HTTP headers set are:
//   - OAuth-Client-Attestation: the WIA JWT (typ: oauth-client-attestation+jwt)
//   - OAuth-Client-Attestation-PoP: the PoP JWT (typ: oauth-client-attestation-pop+jwt)
//
// Architecture note: The instance key NEVER resides on the backend. It lives in
// the client's encrypted private data blob (protected by passkey-PRF-derived key).
// The client obtains the WIA from /wallet-provider/wia/generate and signs the PoP
// locally before passing both to the backend at flow start.
type ClientAttestationProvider interface {
	// Available reports whether attestation credentials are available for this flow.
	Available() bool

	// SetHeaders sets the OAuth-Client-Attestation and OAuth-Client-Attestation-PoP
	// headers on the given HTTP request.
	SetHeaders(ctx context.Context, req *http.Request) error

	// ClientID returns the client_id to use with this attestation
	// (the WIA sub claim = JWK Thumbprint of the instance key).
	ClientID() string
}

// TransportSuppliedAttestation implements ClientAttestationProvider by forwarding
// a WIA + PoP that were supplied by the client via the transport layer
// (WebSocket FlowStartMessage, WMP flow params, native SDK flow start).
//
// The client (frontend/SDK) is responsible for:
//  1. Obtaining the WIA from /wallet-provider/wia/generate (binding its instance key)
//  2. Generating the PoP JWT signed with its instance key (aud = issuer AS URL)
//  3. Passing both at flow start time
//
// The backend does NOT sign or modify these — it forwards them as HTTP headers.
type TransportSuppliedAttestation struct {
	WIA string // the oauth-client-attestation+jwt (client-supplied)
	PoP string // the oauth-client-attestation-pop+jwt (client-signed)
	ID  string // WIA sub claim (JWK Thumbprint of instance key)
}

func (t *TransportSuppliedAttestation) Available() bool {
	return t != nil && t.WIA != "" && t.PoP != ""
}

func (t *TransportSuppliedAttestation) ClientID() string {
	return t.ID
}

func (t *TransportSuppliedAttestation) SetHeaders(_ context.Context, req *http.Request) error {
	req.Header.Set("OAuth-Client-Attestation", t.WIA)
	req.Header.Set("OAuth-Client-Attestation-PoP", t.PoP)
	return nil
}
