package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"
)

// Credential Auxiliary Data (OpenID4VCI Credential Auxiliary Data v0.1).
//
// The engine never handles a secret value: an issuer delivers it in an
// encrypted response that the client decrypts. `auxiliary_data` is the one
// credential_metadata member that carries Secret Values (v0.1 section 8.4); the
// engine decides from the advertisement alone whether the response must be
// encrypted.
//
// Members of credential_metadata the engine does not know, the superseded SIROS
// ones included, are ordinary unknown members and are ignored.

// errFlowReported marks an error whose terminal flow_error has already been
// sent, so a caller does not send a second one.
var errFlowReported = errors.New("flow error already reported")

// hasAuxiliaryDataMember reports whether a response-level credential_metadata
// object has the auxiliary_data member.
func hasAuxiliaryDataMember(md json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(md, &m) != nil {
		return false
	}
	_, ok := m[auxiliaryDataMember]
	return ok
}

// refusePlainSecretMembers fails the flow when a PLAIN credential response
// carries auxiliary_data (a Secret Value must never travel unencrypted, v0.1
// section 7.1). Nothing of the content is logged.
func (h *OID4VCIHandler) refusePlainSecretMembers(md json.RawMessage) error {
	if hasAuxiliaryDataMember(md) {
		err := fmt.Errorf("%w: auxiliary_data arrived in a plain response", errFlowReported)
		h.Logger.Warn("rejecting credential response", zap.Error(err))
		_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, "Issuer returned malformed credential metadata")
		return err
	}
	return nil
}

// failSecretDelivery maps an error of secretDeliveryOf to the flow error.
func (h *OID4VCIHandler) failSecretDelivery(err error) error {
	h.Logger.Warn("rejecting issuer metadata", zap.Error(err))
	_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, "Issuer advertised malformed secret delivery metadata")
	return err
}

// configRefusal says, without sending anything, why a credential configuration
// must not be used: a malformed advertisement, or auxiliary data the wallet cannot handle
// (errAuxiliaryDataUnsupported).
func configRefusal(config *CredentialConfig) error {
	if config == nil {
		return nil
	}
	d, err := secretDeliveryOf(config)
	if err != nil {
		return err
	}
	return d.usable(config)
}

// failConfigRefusal fails the flow for an error of configRefusal.
func (h *OID4VCIHandler) failConfigRefusal(err error) error {
	if errors.Is(err, errAuxiliaryDataUnsupported) {
		h.Logger.Warn("refusing a credential configuration", zap.Error(err))
		_ = h.Error(StepRequestingCredential, ErrCodeAuxiliaryDataUnsupported, ErrCodeAuxiliaryDataUnsupported.UserFacingMessage())
		return err
	}
	return h.failSecretDelivery(err)
}

const (
	// auxiliaryDataMember is the credential_metadata member that carries
	// Credential Auxiliary Data in a response. It MUST NOT appear in issuer
	// metadata (Auxiliary Data v0.1, section 7).
	auxiliaryDataMember = "auxiliary_data"
	// auxTypeHashCommitment is the one Auxiliary Data Type the engine knows.
	// Its response entries carry a Secret Value (opening).
	auxTypeHashCommitment = "hash_commitment"
)

// What the wallet can do with a hash_commitment entry, as Auxiliary Data v0.1
// section 4.1 defines it: the hash function `alg` (sha-256) and how the claim
// at `path` represents the commitment, `encoding` (absent, base64url, base64 or
// hex). An entry with any other value is one the wallet does not recognise.
// The spec sets no limit on the number of entries or the length of a path, and
// the engine sets none.
var (
	auxSupportedAlgs      = []string{"sha-256"}
	auxSupportedEncodings = []string{"base64url", "base64", "hex"}
)

func contains(set []string, v string) bool {
	for _, x := range set {
		if x == v {
			return true
		}
	}
	return false
}

// secretDelivery is what the engine takes from one credential configuration's
// advertisement of secret delivery.
type secretDelivery struct {
	// requireEncryption: the issuer delivers secret values to the wallet, so
	// the response MUST be encrypted (Auxiliary Data v0.1 section 7.1).
	requireEncryption bool
	// toIssuer are the advertised auxiliary_data_supported.to_issuer entries
	// the wallet can send (or ignores: an unrecognised type), verbatim, for
	// the wallet to place in its key proofs. A hash_commitment entry the wallet
	// cannot send (unsupported alg or encoding) is not in it.
	toIssuer []json.RawMessage
	// toIssuerRecognised: at least one to_issuer entry is of a type the engine
	// knows (hash_commitment), so the wallet needs the credential type.
	toIssuerRecognised bool
	// toWallet are the advertised to_wallet entries, verbatim, so the client
	// can check what it receives and refuse a response that lacks an entry
	// (v0.1 section 7.2).
	toWallet []json.RawMessage
	// unusable is why the wallet must not request the Credential, if it must
	// not: a to_wallet hash_commitment entry with an alg or encoding it does
	// not recognise, or a required to_issuer entry it cannot send (v0.1
	// sections 4.1 and 5). The reason never carries the content.
	unusable string
	// requiredToIssuer: a to_issuer entry is required, so a key proof that can
	// carry auxiliary_data is needed.
	requiredToIssuer bool
}

// errAuxiliaryDataUnsupported is why a configuration cannot be used; the flow
// fails with AUXILIARY_DATA_UNSUPPORTED before any authorization or request.
var errAuxiliaryDataUnsupported = errors.New("the credential configuration needs auxiliary data this wallet cannot handle")

// usable reports whether the wallet may request the Credential: it recognises
// every to_wallet hash_commitment entry and every required to_issuer entry,
// and has a key proof type to carry a required to_issuer entry.
func (d secretDelivery) usable(config *CredentialConfig) error {
	if d.unusable != "" {
		return fmt.Errorf("%w: %s", errAuxiliaryDataUnsupported, d.unusable)
	}
	if d.requiredToIssuer && !carriesAuxiliaryData(config) {
		return fmt.Errorf("%w: a required to_issuer entry needs a jwt or attestation key proof", errAuxiliaryDataUnsupported)
	}
	return nil
}

// carriesAuxiliaryData: the configuration declares a key proof type in which
// the wallet can place auxiliary_data and the engine can inspect it.
func carriesAuxiliaryData(config *CredentialConfig) bool {
	_, jwt := config.ProofTypesSupported["jwt"]
	_, att := config.ProofTypesSupported["attestation"]
	return jwt || att
}

// errMalformedAdvertisement never carries the offending content.
var errMalformedAdvertisement = errors.New("issuer metadata secret delivery advertisement is malformed")

// secretDeliveryOf evaluates the advertisement of a credential configuration:
// auxiliary_data_supported, and a refusal of an auxiliary_data member in its
// credential_metadata. Anything malformed is an error
// (fail closed); an absent advertisement is the zero value.
func secretDeliveryOf(config *CredentialConfig) (secretDelivery, error) {
	var d secretDelivery
	if config == nil {
		return d, nil
	}
	if err := checkIssuerCredentialMetadata(config.CredentialMetadata); err != nil {
		return d, err
	}
	if len(config.AuxiliaryDataSupported) > 0 {
		aux, err := parseAuxiliaryDataSupported(config.AuxiliaryDataSupported)
		if err != nil {
			return d, err
		}
		d.requireEncryption = d.requireEncryption || aux.toWalletSecret
		d.toIssuer = aux.toIssuer
		d.toIssuerRecognised = aux.toIssuerRecognised
		d.toWallet = aux.toWallet
		d.unusable = aux.unusable
		d.requiredToIssuer = aux.requiredToIssuer
	}
	return d, nil
}

// checkIssuerCredentialMetadata refuses an auxiliary_data member in issuer
// metadata (it MUST NOT appear in Credential Issuer Metadata, v0.1 section 7:
// errMalformedAdvertisement). A
// document that is not an object is not judged here.
func checkIssuerCredentialMetadata(credentialMetadata json.RawMessage) error {
	if len(credentialMetadata) == 0 {
		return nil
	}
	var md map[string]json.RawMessage
	if json.Unmarshal(credentialMetadata, &md) != nil {
		return nil
	}
	if _, has := md[auxiliaryDataMember]; has {
		return fmt.Errorf("%w: %s in credential_metadata", errMalformedAdvertisement, auxiliaryDataMember)
	}
	return nil
}

// AdvertisementMalformed reports whether the secret delivery advertisement of
// one credential configuration (a JSON object) is malformed, so that the
// configuration is not offered. A document that does not decode as a
// configuration is not judged here.
func AdvertisementMalformed(configuration json.RawMessage) bool {
	// Read only the two members the advertisement lives in, by exact key, so
	// that a type error in an unrelated member (say "format":123) cannot
	// disable the check.
	var m map[string]json.RawMessage
	if json.Unmarshal(configuration, &m) != nil || m == nil {
		return false // not a JSON object: not judged here
	}
	_, err := secretDeliveryOf(&CredentialConfig{
		CredentialMetadata:     m["credential_metadata"],
		AuxiliaryDataSupported: m["auxiliary_data_supported"],
	})
	return err != nil
}

type auxAdvertisement struct {
	toWalletSecret     bool
	toWallet           []json.RawMessage
	toIssuer           []json.RawMessage
	toIssuerRecognised bool
	unusable           string
	requiredToIssuer   bool
}

// auxSupportedWire is auxiliary_data_supported (Auxiliary Data v0.1 section 5).
type auxSupportedWire struct {
	ToWallet json.RawMessage `json:"to_wallet"`
	ToIssuer json.RawMessage `json:"to_issuer"`
}

// auxEntryWire is the part of an auxiliary data entry the engine reads. Other
// members are the type's own and pass through verbatim.
type auxEntryWire struct {
	Type     string          `json:"type"`
	Alg      json.RawMessage `json:"alg"`
	Encoding json.RawMessage `json:"encoding"`
	Path     json.RawMessage `json:"path"`
	Required json.RawMessage `json:"required"`
}

// parseAuxiliaryDataSupported validates auxiliary_data_supported: an object with
// at least one of to_wallet and to_issuer, each a non-empty array of entries; an
// entry is an object with a string type, at most one entry per type and path;
// to_issuer entries may carry a boolean required. A hash_commitment entry needs
// a string alg and a claims path, and never an opening or commitment (values,
// not metadata). A recipient ignores an entry of an unrecognised type (section
// 3): of it only the type is checked, and required when it is in to_issuer (a
// required entry the wallet cannot send makes the configuration unusable). The
// returned toIssuer entries are verbatim.
func parseAuxiliaryDataSupported(raw json.RawMessage) (*auxAdvertisement, error) {
	var top auxSupportedWire
	if err := json.Unmarshal(raw, &top); err != nil || string(raw) == "null" {
		return nil, fmt.Errorf("%w: auxiliary_data_supported is not an object", errMalformedAdvertisement)
	}
	if top.ToWallet == nil && top.ToIssuer == nil {
		return nil, fmt.Errorf("%w: auxiliary_data_supported has neither to_wallet nor to_issuer", errMalformedAdvertisement)
	}
	out := &auxAdvertisement{}
	if top.ToWallet != nil {
		entries, rawEntries, err := parseAuxEntries(top.ToWallet, "to_wallet")
		if err != nil {
			return nil, err
		}
		out.toWalletSecret = hasHashCommitment(entries)
		out.toWallet = rawEntries
		// Every to_wallet entry of a type the wallet knows must be one it can
		// check: it MUST NOT request the Credential otherwise (section 4.1).
		for _, e := range entries {
			if e.typ == auxTypeHashCommitment && !e.sendable {
				out.unusable = "a to_wallet entry has an alg or encoding this wallet does not recognise"
			}
		}
	}
	if top.ToIssuer != nil {
		entries, rawEntries, err := parseAuxEntries(top.ToIssuer, "to_issuer")
		if err != nil {
			return nil, err
		}
		for i, e := range entries {
			switch {
			case e.typ == auxTypeHashCommitment && !e.sendable:
				// MUST NOT be sent; required, it also MUST NOT be requested.
				if e.required {
					out.unusable = "a required to_issuer entry has an alg or encoding this wallet does not recognise"
				}
				continue
			case e.typ != auxTypeHashCommitment && e.required:
				out.unusable = "a required to_issuer entry is of a type this wallet does not recognise"
			}
			// The credential type is needed only for an entry the wallet will
			// send, not for one dropped above.
			out.toIssuerRecognised = out.toIssuerRecognised || e.typ == auxTypeHashCommitment
			out.requiredToIssuer = out.requiredToIssuer || e.required
			out.toIssuer = append(out.toIssuer, rawEntries[i])
		}
	}
	return out, nil
}

// hasHashCommitment reports whether any entry is of the one type the engine knows.
func hasHashCommitment(entries []auxEntry) bool {
	for _, e := range entries {
		if e.typ == auxTypeHashCommitment {
			return true
		}
	}
	return false
}

type auxEntry struct {
	typ      string
	required bool
	// sendable: a hash_commitment entry whose alg and encoding the wallet
	// recognises.
	sendable bool
}

// errAuxEntry is a malformed entry; the text says why and never carries content.
type errAuxEntry string

func (e errAuxEntry) Error() string { return string(e) }

func parseAuxEntries(raw json.RawMessage, list string) ([]auxEntry, []json.RawMessage, error) {
	bad := func(why string) ([]auxEntry, []json.RawMessage, error) {
		return nil, nil, fmt.Errorf("%w: %s %s", errMalformedAdvertisement, list, why)
	}
	var rawEntries []json.RawMessage
	if json.Unmarshal(raw, &rawEntries) != nil || len(rawEntries) == 0 {
		return bad("is not a non-empty array")
	}
	seen := make(map[string]struct{}, len(rawEntries))
	entries := make([]auxEntry, 0, len(rawEntries))
	for _, re := range rawEntries {
		e, pathKey, err := parseAuxEntry(re, list)
		if err != nil {
			return bad(err.Error())
		}
		if e.typ == auxTypeHashCommitment {
			if _, d := seen[pathKey]; d {
				return bad("has two entries of the same type and path")
			}
			seen[pathKey] = struct{}{}
		}
		entries = append(entries, e)
	}
	return entries, rawEntries, nil
}

// parseAuxEntry validates one entry and
// returns it with its duplicate-detection path key. The error text is the
// reason, without content.
func parseAuxEntry(re json.RawMessage, list string) (auxEntry, string, error) {
	var w auxEntryWire
	if json.Unmarshal(re, &w) != nil || string(re) == "null" || re[0] != '{' || w.Type == "" {
		return auxEntry{}, "", errAuxEntry("has an entry that is not an object with a string type")
	}
	if w.Type != auxTypeHashCommitment {
		// An entry of an unrecognised type is ignored (section 3): its own
		// parameters, a "commitment" or "opening" among them, are its own.
		// Only required is read, and only in to_issuer, where it must be a
		// boolean (section 5).
		if list == "to_issuer" {
			if err := checkAuxRequired(w, list); err != nil {
				return auxEntry{}, "", err
			}
		}
		return auxEntry{typ: w.Type, required: unrecognisedRequired(w, list)}, "", nil
	}
	// Values, never metadata: no opening or commitment member at any depth.
	var generic any
	if json.Unmarshal(re, &generic) != nil || containsMember(generic, "opening") || containsMember(generic, "commitment") {
		return auxEntry{}, "", errAuxEntry("has an entry carrying an opening or a commitment")
	}
	if err := checkAuxRequired(w, list); err != nil {
		return auxEntry{}, "", err
	}
	pathKey, err := auxEntryPathKey(w)
	if err != nil {
		return auxEntry{}, "", err
	}
	e := auxEntry{typ: w.Type, required: string(w.Required) == "true"}
	e.sendable = contains(auxSupportedAlgs, algOf(w)) && encodingSupported(w.Encoding)
	return e, pathKey, nil
}

// algOf returns the alg of an entry, empty when absent or not a string. Only a
// hash_commitment entry needs one; the parameters of any other type are its own.
func algOf(w auxEntryWire) string {
	var alg string
	if json.Unmarshal(w.Alg, &alg) != nil {
		return ""
	}
	return alg
}

// encodingSupported: encoding is absent, or a string the spec defines.
func encodingSupported(raw json.RawMessage) bool {
	if raw == nil {
		return true
	}
	var enc string
	return json.Unmarshal(raw, &enc) == nil && contains(auxSupportedEncodings, enc)
}

// unrecognisedRequired reports whether an entry of an unrecognised type in
// to_issuer is required. Anywhere else, and for a value that is not the boolean
// true, the entry is ignored.
func unrecognisedRequired(w auxEntryWire, list string) bool {
	return list == "to_issuer" && string(w.Required) == "true"
}

// checkAuxRequired: only to_issuer entries may carry required, and it is a boolean.
func checkAuxRequired(w auxEntryWire, list string) error {
	if w.Required == nil {
		return nil
	}
	if list != "to_issuer" {
		return errAuxEntry("has a required member")
	}
	var req bool
	if json.Unmarshal(w.Required, &req) != nil || string(w.Required) == "null" {
		return errAuxEntry("has a required member that is not a boolean")
	}
	return nil
}

// auxEntryPathKey returns the duplicate-detection key of an entry's path.
func auxEntryPathKey(w auxEntryWire) (string, error) {
	if w.Type == auxTypeHashCommitment {
		if algOf(w) == "" {
			return "", errAuxEntry("has a hash_commitment entry without a string alg")
		}
		p, ok := claimsPathKey(w.Path)
		if !ok {
			return "", errAuxEntry("has a hash_commitment entry without a valid claims path")
		}
		return p, nil
	}
	return "", nil
}

// claimsPathKey validates a claims path pointer (OpenID4VCI Appendix C): a
// non-empty array of strings, nulls and non-negative integers. It returns the
// compacted JSON for duplicate detection.
func claimsPathKey(raw json.RawMessage) (string, bool) {
	var p []json.RawMessage
	if json.Unmarshal(raw, &p) != nil || len(p) == 0 {
		return "", false
	}
	// Decode every element so the key is independent of how the issuer spelled
	// it (escapes, whitespace, number form).
	norm := make([]interface{}, 0, len(p))
	for _, el := range p {
		var s *string
		if json.Unmarshal(el, &s) == nil {
			if s == nil {
				norm = append(norm, nil)
			} else {
				norm = append(norm, *s)
			}
			continue
		}
		var n uint64
		if json.Unmarshal(el, &n) != nil {
			return "", false
		}
		norm = append(norm, n)
	}
	b, err := json.Marshal(norm)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// errAuxiliaryDataProof is wrapped by every error checkProofsForwardNoOpening
// returns; the flow then fails with AUXILIARY_DATA_PROOF_INVALID. Errors never
// include a commitment or opening value.
var errAuxiliaryDataProof = errors.New("key proofs cannot be forwarded: auxiliary_data is not safe to relay")

func auxProofErr(why string) error { return fmt.Errorf("%w: %s", errAuxiliaryDataProof, why) }

// checkProofsForwardNoOpening is the engine's one check on the auxiliary_data
// of the key proofs the client returned, made before they are forwarded to the
// issuer: no hash_commitment entry carries an `opening`. An opening is the
// secret the commitment hides and the engine must never relay a secret, so this
// is the engine's own safety property, not an acceptance rule.
//
// Whether the entries are acceptable (the same entries in every proof, a match
// with an advertised to_issuer entry by path and alg, the commitment length,
// every required entry sent; Credential Auxiliary Data section 6.4) is the
// issuer's to decide and is deliberately not re-implemented here, so the two
// cannot drift apart.
//
// inspect is true when the issuer advertised to_issuer entries: the engine then
// has promised to look at the proofs, so a proof it cannot inspect (a type other
// than jwt or attestation, an unreadable JWT, an auxiliary_data claim that is
// not an array of objects) is refused rather than forwarded unexamined. With
// nothing advertised an unreadable proof is left to the issuer's own proof
// verification, while a readable one is still checked.
func checkProofsForwardNoOpening(proofs []ProofObject, inspect bool) error {
	for _, proof := range proofs {
		var token string
		switch proof.ProofType {
		case "jwt":
			token = proof.JWT
		case "attestation":
			token = proof.Attestation
		default:
			if inspect {
				return auxProofErr("proof type cannot be inspected for an opening")
			}
			continue
		}
		claim, has, err := proofAuxiliaryDataClaim(token)
		if err != nil {
			if inspect {
				return err
			}
			continue
		}
		if !has {
			continue
		}
		// Numbers stay numbers (json.Number): a valid claim such as
		// {"alg":1e400} must not fail on a float64 overflow in a scan that
		// only looks for member names.
		var v any
		dec := json.NewDecoder(bytes.NewReader(claim))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return auxProofErr("auxiliary_data is not valid JSON")
		}
		if containsMember(v, "opening") {
			return auxProofErr("a proof entry carries an opening")
		}
		if _, isArray := v.([]any); !isArray {
			return auxProofErr("auxiliary_data is not an array")
		}
	}
	return nil
}

// proofClaimsWire is the claim of a proof payload the engine reads.
type proofClaimsWire struct {
	AuxiliaryData json.RawMessage `json:"auxiliary_data"`
}

// proofAuxiliaryDataClaim returns the auxiliary_data claim of a compact JWT's
// payload, and whether it is present.
func proofAuxiliaryDataClaim(token string) (json.RawMessage, bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false, auxProofErr("proof is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false, auxProofErr("proof payload is not base64url")
	}
	var claims proofClaimsWire
	if err := json.Unmarshal(payload, &claims); err != nil || string(bytes.TrimSpace(payload)) == "null" {
		return nil, false, auxProofErr("proof payload is not a JSON object")
	}
	return claims.AuxiliaryData, claims.AuxiliaryData != nil, nil
}
