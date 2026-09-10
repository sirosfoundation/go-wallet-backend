package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// clientAuthMode says who holds the DPoP key for an OID4VCI flow, and hence
// who signs the DPoP proofs and the OAuth client attestation PoPs.
//
// The client-held mode is the target design (go-wallet-backend#317,
// wallet-frontend#282): one client-held key is both the WIA `cnf` key and
// the DPoP key, and the engine asks the client for every signature via
// SignActionSignClientAuth. The legacy mode is what every client did before
// that action existed: the engine generates an ephemeral DPoP key itself and
// asks for the WIA + PoP once, then replays them.
type clientAuthMode int

const (
	// clientAuthUndecided means no request needing client authentication has
	// been sent yet; the first one probes the client with
	// SignActionSignClientAuth and settles the mode for the flow.
	clientAuthUndecided clientAuthMode = iota
	// clientAuthClientHeld means the client answered the probe with a
	// dpop_key_id and signs every DPoP proof and attestation PoP on demand.
	clientAuthClientHeld
	// clientAuthLegacy means the engine holds the DPoP key (h.dpopKey) and
	// forwards a once-requested WIA + PoP (h.attestationProvider).
	clientAuthLegacy
)

// clientAuthRequestTimeout bounds each SignActionSignClientAuth round-trip.
// A DPoP proof or attestation PoP needs no user interaction, so this is far
// below Session.RequestSign's 3-minute ceiling, and it is also what bounds
// the probe against a client that never answers unknown actions (clients
// since kotlin#154 / swift#122 answer them immediately with an empty
// response, so those fall back without waiting). A package var so tests can
// shorten it.
var clientAuthRequestTimeout = 20 * time.Second

// clientAuthNeeds says what a single outbound request must carry.
type clientAuthNeeds struct {
	// attestation asks for OAuth-Client-Attestation[-PoP] headers (PAR and
	// token requests, draft-ietf-oauth-attestation-based-client-auth §3.1).
	attestation bool
	// dpop asks for a DPoP proof (RFC 9449) over htm/htu, with ath when
	// accessToken is set (resource requests) and the current h.dpopNonce.
	dpop        bool
	htm         string
	htu         string
	accessToken string
}

// clientAuthHeaders is the resolved client authentication for one request.
type clientAuthHeaders struct {
	wia       string
	pop       string
	dpopProof string
}

// attested reports whether the request carries client attestation, which is
// what decides whether form-body client auth (private_key_jwt) is skipped.
func (c clientAuthHeaders) attested() bool { return c.wia != "" && c.pop != "" }

// apply sets the resolved headers on req.
func (c clientAuthHeaders) apply(req *http.Request) {
	if c.attested() {
		req.Header.Set("OAuth-Client-Attestation", c.wia)
		req.Header.Set("OAuth-Client-Attestation-PoP", c.pop)
	}
	if c.dpopProof != "" {
		req.Header.Set("DPoP", c.dpopProof)
	}
}

// dpopProofSigner produces RFC 9449 DPoP proofs for one issuance flow. It is
// what outlives the flow in notificationContext, so the §10 notification can
// be DPoP-bound in either mode without the notification path knowing which.
type dpopProofSigner interface {
	Proof(ctx context.Context, htm, htu, accessToken, nonce string) (string, error)
}

// localDPoPSigner signs with an engine-held key (legacy mode).
type localDPoPSigner struct {
	key *ecdsa.PrivateKey
}

func (s *localDPoPSigner) Proof(_ context.Context, htm, htu, accessToken, nonce string) (string, error) {
	return createDPoPProof(s.key, htm, htu, accessToken, nonce)
}

// clientHeldDPoPSigner asks the client for each proof (client-held mode).
// It addresses the sign request to the flow that established the key, which
// keeps working after that flow completed: the sign channel is per session,
// on both the WebSocket and the WMP transport.
type clientHeldDPoPSigner struct {
	session *Session
	flowID  string
	keyID   string
}

func (s *clientHeldDPoPSigner) Proof(ctx context.Context, htm, htu, accessToken, nonce string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, clientAuthRequestTimeout)
	defer cancel()
	resp, err := s.session.RequestSign(ctx, s.flowID, SignActionSignClientAuth, SignRequestParams{
		HTM:       htm,
		HTU:       htu,
		ATH:       accessTokenHash(accessToken),
		DPoPNonce: nonce,
		KeyID:     s.keyID,
	})
	if err != nil {
		return "", fmt.Errorf("client DPoP signing failed: %w", err)
	}
	if resp.DPoPProof == "" {
		return "", errors.New("client returned no DPoP proof")
	}
	return resp.DPoPProof, nil
}

// accessTokenHash is the DPoP `ath` claim: base64url(SHA-256(access_token)),
// RFC 9449 §4.2. Empty for an empty token (token endpoint requests).
func accessTokenHash(accessToken string) string {
	if accessToken == "" {
		return ""
	}
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// dpopSigner returns the signer for the flow's settled mode, or nil when the
// flow has no DPoP key at all (undecided, or legacy without a key).
func (h *OID4VCIHandler) dpopSigner() dpopProofSigner {
	switch h.clientAuthMode {
	case clientAuthClientHeld:
		return &clientHeldDPoPSigner{session: h.Flow.Session, flowID: h.Flow.ID, keyID: h.dpopKeyID}
	default:
		if h.dpopKey == nil {
			return nil
		}
		return &localDPoPSigner{key: h.dpopKey}
	}
}

// useLegacyClientAuth settles the flow on legacy mode, generating the
// engine-held DPoP key if the flow does not already have one (a renewal that
// presented dpop_jwk does).
func (h *OID4VCIHandler) useLegacyClientAuth() error {
	h.clientAuthMode = clientAuthLegacy
	if h.dpopKey != nil {
		return nil
	}
	key, err := generateDPoPKey()
	if err != nil {
		return fmt.Errorf("failed to generate DPoP key: %w", err)
	}
	h.dpopKey = key
	return nil
}

// resolveClientAuth obtains the client authentication material for one
// outbound request. On the first call of an undecided flow it probes the
// client with SignActionSignClientAuth carrying the real needs of that
// request, so the probe is never a wasted round-trip: a client that answers
// with a dpop_key_id has just supplied what the request needs, and one that
// does not (empty reply to an unknown action, or no reply within
// clientAuthRequestTimeout) puts the flow in legacy mode, where the engine
// generates its own DPoP key and asks for the WIA + PoP once, as before.
//
// Once settled, the mode never changes for the flow: the token is bound to
// whichever key signed the token request, so a signing failure in client-held
// mode is an error, not a downgrade.
func (h *OID4VCIHandler) resolveClientAuth(ctx context.Context, needs clientAuthNeeds) (clientAuthHeaders, error) {
	if h.clientAuthMode == clientAuthUndecided && h.dpopKey != nil {
		// A key was supplied or generated up front (a renewal presenting
		// dpop_jwk, a client that pre-resolved its attestation, tests): the
		// engine holds it, so this is a legacy flow.
		h.clientAuthMode = clientAuthLegacy
	}

	switch h.clientAuthMode {
	case clientAuthLegacy:
		return h.resolveLegacyClientAuth(ctx, needs)
	case clientAuthClientHeld:
		resp, err := h.requestClientAuth(ctx, needs)
		if err != nil {
			return clientAuthHeaders{}, err
		}
		return h.headersFromClientAuthResponse(resp, needs)
	}

	// Undecided: probe with the real request.
	resp, err := h.requestClientAuth(ctx, needs)
	if err == nil && resp.DPoPKeyID != "" {
		h.clientAuthMode = clientAuthClientHeld
		h.dpopKeyID = resp.DPoPKeyID
		h.Logger.Info("client-held DPoP key: client signs DPoP proofs and attestation PoPs on demand",
			zap.String("client_id", h.clientID))
		return h.headersFromClientAuthResponse(resp, needs)
	}
	if err != nil {
		h.Logger.Debug("sign_client_auth probe failed; falling back to engine-held DPoP key", zap.Error(err))
	} else {
		h.Logger.Debug("client does not support sign_client_auth; falling back to engine-held DPoP key")
	}
	if err := h.useLegacyClientAuth(); err != nil {
		return clientAuthHeaders{}, err
	}
	return h.resolveLegacyClientAuth(ctx, needs)
}

// requestClientAuth sends one SignActionSignClientAuth for the given needs.
func (h *OID4VCIHandler) requestClientAuth(ctx context.Context, needs clientAuthNeeds) (*SignResponseMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	params := SignRequestParams{KeyID: h.dpopKeyID}
	if needs.attestation {
		params.Audience = h.authServerIssuer // PoP aud = the AS the request is sent to
		params.Issuer = h.clientID           // WIA sub / PoP iss = this flow's effective client_id
	}
	if needs.dpop {
		params.HTM = needs.htm
		params.HTU = needs.htu
		params.ATH = accessTokenHash(needs.accessToken)
		params.DPoPNonce = h.dpopNonce
	}
	ctx, cancel := context.WithTimeout(ctx, clientAuthRequestTimeout)
	defer cancel()
	return h.RequestSign(ctx, SignActionSignClientAuth, params)
}

// headersFromClientAuthResponse validates a client-held-mode response against
// what was asked. A missing DPoP proof is fatal; missing attestation is not
// (the flow proceeds without wallet attestation, and an issuer that requires
// it rejects on its own), matching legacy behaviour.
func (h *OID4VCIHandler) headersFromClientAuthResponse(resp *SignResponseMessage, needs clientAuthNeeds) (clientAuthHeaders, error) {
	var out clientAuthHeaders
	if needs.dpop {
		if resp.DPoPProof == "" {
			return out, errors.New("client returned no DPoP proof for sign_client_auth")
		}
		out.dpopProof = resp.DPoPProof
	}
	if needs.attestation {
		if resp.ClientAttestation != "" && resp.ClientAttestationPoP != "" {
			out.wia = resp.ClientAttestation
			out.pop = resp.ClientAttestationPoP
		} else {
			h.Logger.Debug("client returned no attestation for sign_client_auth; proceeding without",
				zap.String("client_id", h.clientID))
		}
	}
	return out, nil
}

// resolveLegacyClientAuth is the pre-#317 behaviour: the WIA + PoP are
// requested once (lazily, on the first request that needs them) and replayed,
// and the DPoP proof is signed with the engine-held key.
func (h *OID4VCIHandler) resolveLegacyClientAuth(ctx context.Context, needs clientAuthNeeds) (clientAuthHeaders, error) {
	var out clientAuthHeaders
	if needs.attestation {
		if h.attestationProvider == nil && !h.legacyAttestationRequested {
			h.legacyAttestationRequested = true
			h.requestClientAttestation(ctx)
		}
		if tsa, ok := h.attestationProvider.(*TransportSuppliedAttestation); ok && tsa.Available() {
			out.wia = tsa.WIA
			out.pop = tsa.PoP
		}
	}
	if needs.dpop && h.dpopKey != nil {
		proof, err := createDPoPProof(h.dpopKey, needs.htm, needs.htu, needs.accessToken, h.dpopNonce)
		if err != nil {
			return out, fmt.Errorf("failed to create DPoP proof: %w", err)
		}
		out.dpopProof = proof
	}
	return out, nil
}

// dpopKeyIDForRefreshToken is the client-held counterpart of
// dpopJWKForRefreshToken: the key identifier the client must present back as
// FlowStartMessage.DPoPKeyID when renewing with this token. Empty when there
// is no refresh_token to pair it with or the flow is not client-held.
func (h *OID4VCIHandler) dpopKeyIDForRefreshToken(token *TokenResponse) string {
	if token.RefreshToken == "" || h.clientAuthMode != clientAuthClientHeld {
		return ""
	}
	return h.dpopKeyID
}
