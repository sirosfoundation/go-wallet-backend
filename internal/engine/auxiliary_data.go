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
// The superseded SIROS members (see legacySecretMembers) are not supported.
// They are refused, not ignored: ignoring an advertisement of one would make
// the engine ask for no response encryption and let a seed travel in clear.

// legacySecretMembers are the superseded secret-bearing credential_metadata
// members, refused for at least one release (LEGACY_SECRET_MEMBER). The names
// are the ones the Swift and Kotlin SDKs refuse.
var legacySecretMembers = []string{
	"org.siros.secret_seed",
	"org.siros.holder_commitments",
	"org.siros.psc",
	"holder_commitments",
	"secret_members",
}

// isLegacySecretMember reports whether name is a superseded member, in any
// letter case (fail closed).
func isLegacySecretMember(name string) bool {
	for _, n := range legacySecretMembers {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

// errLegacySecretMember never carries the offending content. The flow fails
// with LEGACY_SECRET_MEMBER.
var errLegacySecretMember = errors.New("a superseded secret-bearing credential_metadata member is not supported")

// hasLegacySecretMember reports whether a credential_metadata object has a
// superseded member. A value that is not a JSON object has none.
func hasLegacySecretMember(md json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(md, &m) != nil {
		return false
	}
	for k := range m {
		if isLegacySecretMember(k) {
			return true
		}
	}
	return false
}

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
// section 7.1) or a superseded member. Nothing of the content is logged.
func (h *OID4VCIHandler) refusePlainSecretMembers(md json.RawMessage) error {
	if hasLegacySecretMember(md) {
		return h.failLegacySecretMember(errors.New("credential response carries a superseded secret-bearing member"))
	}
	if hasAuxiliaryDataMember(md) {
		err := errors.New("auxiliary_data arrived in a plain response")
		h.Logger.Warn("rejecting credential response", zap.Error(err))
		_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, "Issuer returned malformed credential metadata")
		return err
	}
	return nil
}

// failLegacySecretMember fails the flow with LEGACY_SECRET_MEMBER. The error
// text and the log line carry no content from the issuer or the client.
func (h *OID4VCIHandler) failLegacySecretMember(err error) error {
	h.Logger.Warn("refusing a superseded secret-bearing member", zap.Error(err))
	_ = h.Error(StepRequestingCredential, ErrCodeLegacySecretMember, ErrCodeLegacySecretMember.UserFacingMessage())
	return fmt.Errorf("%w", errLegacySecretMember)
}

// failSecretDelivery maps an error of secretDeliveryOf to the flow error.
func (h *OID4VCIHandler) failSecretDelivery(err error) error {
	if errors.Is(err, errLegacySecretMember) {
		return h.failLegacySecretMember(err)
	}
	h.Logger.Warn("rejecting issuer metadata", zap.Error(err))
	_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, "Issuer advertised malformed secret delivery metadata")
	return err
}

// refuseLegacySecretMember refuses to use a credential configuration that
// advertises a superseded secret-bearing member, before any authorization.
func (h *OID4VCIHandler) refuseLegacySecretMember(config *CredentialConfig) error {
	if config != nil && hasLegacySecretMember(config.CredentialMetadata) {
		return h.failLegacySecretMember(errLegacySecretMember)
	}
	return nil
}

const (
	// auxiliaryDataMember is the credential_metadata member that carries
	// Credential Auxiliary Data in a response. It MUST NOT appear in issuer
	// metadata (Auxiliary Data v0.1, section 7).
	auxiliaryDataMember = "auxiliary_data"
	// auxTypeHashCommitment is the one Auxiliary Data Type the engine knows.
	// Its response entries carry a Secret Value (opening).
	auxTypeHashCommitment = "hash_commitment"
	maxAuxEntries         = 16
	maxAuxPathLen         = 16
)

// secretDelivery is what the engine takes from one credential configuration's
// advertisement of secret delivery.
type secretDelivery struct {
	// requireEncryption: the issuer delivers secret values to the wallet, so
	// the response MUST be encrypted (Auxiliary Data v0.1 section 7.1).
	requireEncryption bool
	// toIssuer are the advertised auxiliary_data_supported.to_issuer entries,
	// verbatim, for the wallet to place in its key proofs.
	toIssuer []json.RawMessage
	// toIssuerRecognised: at least one to_issuer entry is of a type the engine
	// knows (hash_commitment), so the wallet needs the credential type.
	toIssuerRecognised bool
}

// errMalformedAdvertisement never carries the offending content.
var errMalformedAdvertisement = errors.New("issuer metadata secret delivery advertisement is malformed")

// secretDeliveryOf evaluates the advertisement of a credential configuration:
// auxiliary_data_supported, and a refusal of any superseded member in its
// credential_metadata (errLegacySecretMember). Anything malformed is an error
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
	}
	return d, nil
}

// checkIssuerCredentialMetadata refuses a superseded member in issuer metadata
// (errLegacySecretMember) and an auxiliary_data member (it MUST NOT appear in
// Credential Issuer Metadata, v0.1 section 7: errMalformedAdvertisement). A
// document that is not an object is not judged here.
func checkIssuerCredentialMetadata(credentialMetadata json.RawMessage) error {
	if len(credentialMetadata) == 0 {
		return nil
	}
	var md map[string]json.RawMessage
	if json.Unmarshal(credentialMetadata, &md) != nil {
		return nil
	}
	for k := range md {
		if isLegacySecretMember(k) {
			return errLegacySecretMember
		}
	}
	if err := checkUnambiguous(credentialMetadata, -1); err != nil {
		return fmt.Errorf("%w: credential_metadata is ambiguous", errMalformedAdvertisement)
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
	if checkUnambiguous(configuration, 1) != nil {
		return true
	}
	_, err := secretDeliveryOf(&CredentialConfig{
		CredentialMetadata:     m["credential_metadata"],
		AuxiliaryDataSupported: m["auxiliary_data_supported"],
	})
	return err != nil
}

// UnmarshalJSON decodes a credential configuration. The names of its own
// top-level members must be unambiguous (see decodeStrict): the two members
// the advertisement lives in are otherwise read by a case-insensitive field
// match that another reader may not make.
func (c *CredentialConfig) UnmarshalJSON(data []byte) error {
	type plain CredentialConfig // no methods: avoids recursion
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	if err := checkUnambiguous(data, 1); err != nil {
		return fmt.Errorf("%w: ambiguous member names", errMalformedAdvertisement)
	}
	*c = CredentialConfig(p)
	return nil
}

type auxAdvertisement struct {
	toWalletSecret     bool
	toIssuer           []json.RawMessage
	toIssuerRecognised bool
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
	Alg      string          `json:"alg"`
	Path     json.RawMessage `json:"path"`
	Required json.RawMessage `json:"required"`
}

// parseAuxiliaryDataSupported validates auxiliary_data_supported: an object with
// at least one of to_wallet and to_issuer, each a non-empty array of entries; an
// entry is an object with a string type, at most one entry per type and path;
// to_issuer entries may carry a boolean required. A hash_commitment entry needs
// a string alg and a claims path, and never an opening or commitment (values,
// not metadata). Entries of an unrecognised type are kept (a recipient ignores
// them) but must still be objects with a type. The returned toIssuer entries
// are verbatim.
func parseAuxiliaryDataSupported(raw json.RawMessage) (*auxAdvertisement, error) {
	var top auxSupportedWire
	if err := decodeStrict(raw, &top); err != nil || string(raw) == "null" {
		return nil, fmt.Errorf("%w: auxiliary_data_supported is not an unambiguous object", errMalformedAdvertisement)
	}
	if top.ToWallet == nil && top.ToIssuer == nil {
		return nil, fmt.Errorf("%w: auxiliary_data_supported has neither to_wallet nor to_issuer", errMalformedAdvertisement)
	}
	out := &auxAdvertisement{}
	if top.ToWallet != nil {
		entries, _, err := parseAuxEntries(top.ToWallet, "to_wallet")
		if err != nil {
			return nil, err
		}
		out.toWalletSecret = hasHashCommitment(entries)
	}
	if top.ToIssuer != nil {
		entries, rawEntries, err := parseAuxEntries(top.ToIssuer, "to_issuer")
		if err != nil {
			return nil, err
		}
		out.toIssuer = rawEntries
		out.toIssuerRecognised = hasHashCommitment(entries)
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
	typ string
}

// errAuxEntry is a malformed entry; the text says why and never carries content.
type errAuxEntry string

func (e errAuxEntry) Error() string { return string(e) }

func parseAuxEntries(raw json.RawMessage, list string) ([]auxEntry, []json.RawMessage, error) {
	bad := func(why string) ([]auxEntry, []json.RawMessage, error) {
		return nil, nil, fmt.Errorf("%w: %s %s", errMalformedAdvertisement, list, why)
	}
	var rawEntries []json.RawMessage
	if json.Unmarshal(raw, &rawEntries) != nil || len(rawEntries) == 0 || len(rawEntries) > maxAuxEntries {
		return bad("is not a non-empty array of bounded size")
	}
	seen := make(map[string]struct{}, len(rawEntries))
	entries := make([]auxEntry, 0, len(rawEntries))
	for _, re := range rawEntries {
		e, pathKey, err := parseAuxEntry(re, list)
		if err != nil {
			return bad(err.Error())
		}
		dup := e.typ + "\x00" + pathKey
		if _, d := seen[dup]; d {
			return bad("has two entries of the same type and path")
		}
		seen[dup] = struct{}{}
		entries = append(entries, e)
	}
	return entries, rawEntries, nil
}

// parseAuxEntry validates one entry (already unambiguous, see decodeStrict) and
// returns it with its duplicate-detection path key. The error text is the
// reason, without content.
func parseAuxEntry(re json.RawMessage, list string) (auxEntry, string, error) {
	var w auxEntryWire
	if json.Unmarshal(re, &w) != nil || string(re) == "null" || re[0] != '{' || w.Type == "" {
		return auxEntry{}, "", errAuxEntry("has an entry that is not an object with a string type")
	}
	// Values, never metadata: no opening or commitment member at any depth,
	// whatever the entry's type.
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
	return auxEntry{typ: w.Type}, pathKey, nil
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
		if w.Alg == "" {
			return "", errAuxEntry("has a hash_commitment entry without a string alg")
		}
		p, ok := claimsPathKey(w.Path)
		if !ok {
			return "", errAuxEntry("has a hash_commitment entry without a valid claims path")
		}
		return p, nil
	}
	if w.Path == nil {
		return "", nil
	}
	// Unrecognised type: only duplicate detection, on the decoded
	// value so escapes and whitespace cannot hide a duplicate.
	var v interface{}
	if json.Unmarshal(w.Path, &v) != nil {
		return "", errAuxEntry("has an entry with an invalid path")
	}
	norm, err := json.Marshal(v)
	if err != nil {
		return "", errAuxEntry("has an entry with an invalid path")
	}
	return string(norm), nil
}

// claimsPathKey validates a claims path pointer (OpenID4VCI Appendix C): a
// non-empty array of strings, nulls and non-negative integers. It returns the
// compacted JSON for duplicate detection.
func claimsPathKey(raw json.RawMessage) (string, bool) {
	var p []json.RawMessage
	if json.Unmarshal(raw, &p) != nil || len(p) == 0 || len(p) > maxAuxPathLen {
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
// verification, while a readable one is still checked, and an ambiguous one
// (see decodeStrict) is never forwarded.
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
			if inspect || errors.Is(err, errAmbiguousJSON) {
				return err
			}
			continue
		}
		if !has {
			continue
		}
		var v any
		if err := json.Unmarshal(claim, &v); err != nil {
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
// payload, and whether it is present. An ambiguous payload (see decodeStrict)
// is an error wrapping errAmbiguousJSON and errAuxiliaryDataProof.
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
	if err := decodeStrict(payload, &claims); err != nil || string(bytes.TrimSpace(payload)) == "null" {
		if errors.Is(err, errAmbiguousJSON) {
			return nil, false, fmt.Errorf("%w: %w", errAuxiliaryDataProof, errAmbiguousJSON)
		}
		return nil, false, auxProofErr("proof payload is not a JSON object")
	}
	return claims.AuxiliaryData, claims.AuxiliaryData != nil, nil
}
