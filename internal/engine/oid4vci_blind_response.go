package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"
)

// Engine-blind credential response encryption.
//
// The engine never holds a response-encryption private key. The client
// generates a fresh ephemeral key per generate_proof request and returns only
// the public JWK; the issuer's JWE is relayed to the client unread
// (decrypt_credential_response), and the client answers with control fields
// only. See docs/websocket-protocol-spec.md (issuance) for the wire format.

// maxEncryptedCredentialCount bounds the credential_count the client may
// report for one response, so a buggy client cannot make the engine emit an
// unbounded flow_complete. Real batches are far smaller (batch_size).
const maxEncryptedCredentialCount = 256

// responseEncryption is the credential response encryption negotiated for one
// issuance, and, once the client answered, the client's public key for it.
type responseEncryption struct {
	Alg      string
	Enc      string
	Required bool
	// Seed is true when the issuer advertises org.siros.secret_seed for the
	// configuration: a plain answer is then refused unread.
	Seed bool
	// JWK is the client's public response-encryption JWK, validated and
	// normalised by the engine. Empty until the client has answered.
	JWK json.RawMessage
}

// withJWK returns a copy carrying the client's key.
func (e *responseEncryption) withJWK(jwk json.RawMessage) *responseEncryption {
	c := *e
	c.JWK = jwk
	return &c
}

// params is the sign_request form of the negotiated pair.
func (e *responseEncryption) params() *CredentialResponseEncryptionParams {
	return &CredentialResponseEncryptionParams{Alg: e.Alg, Enc: e.Enc, Required: e.Required}
}

// requestMember is the credential_response_encryption member of a Credential
// (or Deferred Credential) Request.
func (e *responseEncryption) requestMember() map[string]interface{} {
	return map[string]interface{}{"enc": e.Enc, "jwk": e.JWK}
}

// negotiateResponseEncryption decides, from the issuer metadata alone, whether
// and how the credential response is to be encrypted. It returns nil when the
// issuer offers no response encryption (the response is then plain and
// engine-visible, the issuer's choice). A seed-advertising configuration
// requires encryption and fails closed here, before any request is made.
func (h *OID4VCIHandler) negotiateResponseEncryption(metadata *IssuerMetadata, config *CredentialConfig) (*responseEncryption, error) {
	seedAdvertised, seedErr := secretSeedAdvertised(config)
	if seedErr != nil {
		h.Logger.Warn("rejecting issuer metadata", zap.Error(seedErr))
		_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, "Issuer advertised malformed secret seed metadata")
		return nil, seedErr
	}
	refuseSeed := func(msg string) (*responseEncryption, error) {
		err := errors.New(msg)
		h.Logger.Warn("rejecting credential request", zap.Error(err))
		_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, "Issuer cannot deliver the secret seed over an encrypted response")
		return nil, err
	}

	encCfg := metadata.CredentialResponseEncryption
	if encCfg == nil {
		if seedAdvertised {
			return refuseSeed("issuer advertises secret seed delivery but no credential response encryption")
		}
		return nil, nil
	}

	// Negotiate a mutually supported alg/enc pair (prefer stronger encryption).
	for _, alg := range []string{"ECDH-ES", "ECDH-ES+A256KW", "ECDH-ES+A192KW", "ECDH-ES+A128KW"} {
		for _, enc := range []string{"A256GCM", "A128GCM", "A256CBC-HS512", "A128CBC-HS256"} {
			if encCfg.supportsAlg(alg) && encCfg.supportsEnc(enc) {
				return &responseEncryption{
					Alg:      alg,
					Enc:      enc,
					Required: seedAdvertised || encCfg.EncryptionRequired,
					Seed:     seedAdvertised,
				}, nil
			}
		}
	}
	if seedAdvertised {
		return refuseSeed("issuer advertises secret seed delivery but no mutually supported alg/enc pair is available")
	}
	if encCfg.EncryptionRequired {
		return nil, errors.New("issuer requires credential response encryption but no mutually supported alg/enc pair is available")
	}
	return nil, nil
}

// clientResponseEncryptionJWK validates the public JWK the client returned for
// response encryption and returns the form the engine sends to the issuer.
// The engine accepts only a public EC P-256 key; it rebuilds the JWK from the
// parsed key so that nothing but the key and the negotiated alg/use is
// forwarded. Errors never include key material.
func clientResponseEncryptionJWK(raw json.RawMessage, alg string) (json.RawMessage, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil || !jwk.Valid() {
		return nil, errors.New("client returned an invalid response-encryption JWK")
	}
	if !jwk.IsPublic() {
		return nil, errors.New("client returned a private response-encryption JWK")
	}
	pub, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok || pub == nil || pub.Curve != elliptic.P256() {
		return nil, errors.New("client response-encryption JWK is not a P-256 EC key")
	}
	if jwk.Use != "" && jwk.Use != "enc" {
		return nil, errors.New("client response-encryption JWK is not for encryption")
	}
	if jwk.Algorithm != "" && jwk.Algorithm != alg {
		return nil, errors.New("client response-encryption JWK alg does not match the negotiated alg")
	}
	jwk.Use = "enc"
	jwk.Algorithm = alg
	out, err := json.Marshal(jwk)
	if err != nil {
		return nil, errors.New("client returned an invalid response-encryption JWK")
	}
	return out, nil
}

// resolveClientEncryptionKey turns the client's answer to a generate_proof
// request into the encryption to use: nil when the client declined an
// optional encryption, an error when it declined a required one or returned
// an unusable key (fail closed, never a silent downgrade of a key we cannot
// use).
func resolveClientEncryptionKey(offer *responseEncryption, raw json.RawMessage) (*responseEncryption, error) {
	if s := strings.TrimSpace(string(raw)); s == "" || s == "null" || s == "{}" {
		if offer.Required {
			return nil, errors.New("client declined the required credential response encryption")
		}
		return nil, nil
	}
	jwk, err := clientResponseEncryptionJWK(raw, offer.Alg)
	if err != nil {
		return nil, err
	}
	return offer.withJWK(jwk), nil
}

// isCompactJWE reports whether s has the shape of a compact JWE
// (RFC 7516 §7.1): five base64url segments, of which only the encrypted key
// may be empty. It does not parse or decrypt anything.
func isCompactJWE(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 5 {
		return false
	}
	for i, p := range parts {
		if p == "" && i != 1 {
			return false
		}
		for _, c := range p {
			isB64URL := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !isB64URL {
				return false
			}
		}
	}
	return true
}

// relayEncryptedResponse hands the issuer's JWE to the client for decryption
// and returns what the client reported: a transaction_id (deferred issuance)
// or the number of credentials. The engine never sees the plaintext, and
// neither the JWE nor the client's error text is logged or placed in an error.
func (h *OID4VCIHandler) relayEncryptedResponse(ctx context.Context, jwe string, deferred bool, enc *responseEncryption) (*CredentialResponse, error) {
	if !isCompactJWE(jwe) {
		return nil, errors.New("issuer returned a malformed encrypted credential response")
	}
	resp, err := h.RequestSign(ctx, SignActionDecryptCredentialResponse, SignRequestParams{JWE: jwe, Deferred: &deferred})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New("client could not decrypt the credential response")
	}
	out := &CredentialResponse{Encrypted: true, ResponseEncryption: enc}
	switch {
	case resp.TransactionID != "" && resp.CredentialCount == 0:
		out.TransactionID = resp.TransactionID
		if resp.Interval > 0 {
			out.Interval = resp.Interval
		}
	case resp.TransactionID == "" && resp.CredentialCount >= 1 && resp.CredentialCount <= maxEncryptedCredentialCount:
		out.CredentialCount = resp.CredentialCount
	default:
		return nil, fmt.Errorf("client reported an invalid decrypted credential response: need a transaction_id or a credential_count of 1..%d", maxEncryptedCredentialCount)
	}
	return out, nil
}

// displayMetadataMembers are the members of a plain response's response-level
// credential_metadata (OpenID4VCI 1.1) the engine relays: the display-only
// ones. Everything else, in particular the namespaced org.siros.secret_seed,
// is dropped.
var displayMetadataMembers = []string{"display", "claims"}

// displayMetadata returns the allow-listed display members of a PLAIN
// response's credential_metadata, compacted, or nil. An encrypted response
// never yields any: the engine has no plaintext, and the client holds the
// metadata. A value that is not an object yields nil; no error or log ever
// quotes the content.
func displayMetadata(resp *CredentialResponse) json.RawMessage {
	if resp == nil || resp.Encrypted || len(resp.CredentialMetadata) == 0 {
		return nil
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(resp.CredentialMetadata, &members) != nil {
		return nil
	}
	out := make(map[string]json.RawMessage, len(displayMetadataMembers))
	for _, k := range displayMetadataMembers {
		if v, ok := members[k]; ok {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}
