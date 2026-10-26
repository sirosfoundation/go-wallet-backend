package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// Secret-bearing credential_metadata members and the OpenID4VCI Credential
// Auxiliary Data advertisement.
//
// The engine never handles a secret value: an issuer delivers it in an
// encrypted response that the client decrypts. The engine only decides, from
// member NAMES, whether a response or metadata member is secret. Which names
// those are is configuration (issuance.secret_members) so that a move of the
// standard to another member name needs no code change.

// secretMembers is the configured set; see SetSecretMembers.
var secretMembers atomic.Pointer[map[string]struct{}]

func init() {
	// The same names as config.DefaultSecretMembers (the engine's own tests and
	// any embedder that never calls SetSecretMembers get them).
	SetSecretMembers([]string{secretSeedMember, auxiliaryDataMember})
}

// SetSecretMembers replaces the set of credential_metadata member names the
// engine treats as secret-bearing. It is called once at startup from the
// validated configuration and is safe for concurrent use.
func SetSecretMembers(names []string) {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	secretMembers.Store(&set)
}

// isSecretMember reports whether name is a configured secret-bearing member.
func isSecretMember(name string) bool {
	set := secretMembers.Load()
	if set == nil {
		return false
	}
	_, ok := (*set)[name]
	return ok
}

// hasSecretMember reports whether a response-level credential_metadata object
// has any configured secret-bearing member. A value that is not a JSON object
// has none.
func hasSecretMember(md json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(md, &m) != nil {
		return false
	}
	for k := range m {
		if isSecretMember(k) {
			return true
		}
	}
	return false
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
	// the response MUST be encrypted (Auxiliary Data v0.1 section 7.1, or the
	// legacy member).
	requireEncryption bool
	// toIssuer are the advertised auxiliary_data_supported.to_issuer entries,
	// verbatim, for the wallet to place in its key proofs.
	toIssuer []json.RawMessage
}

// errMalformedAdvertisement never carries the offending content.
var errMalformedAdvertisement = errors.New("issuer metadata secret delivery advertisement is malformed")

// secretDeliveryOf evaluates the advertisement of a credential configuration:
// the legacy credential_metadata member (when configured as secret-bearing) and
// auxiliary_data_supported. Anything malformed is an error (fail closed); an
// absent advertisement is the zero value.
func secretDeliveryOf(config *CredentialConfig) (secretDelivery, error) {
	var d secretDelivery
	if config == nil {
		return d, nil
	}
	if present, ok := SecretSeedAdvertisement(config.CredentialMetadata); present {
		if !ok {
			return d, fmt.Errorf("%w: %s", errMalformedAdvertisement, secretSeedMember)
		}
		d.requireEncryption = true
	}
	// Any other configured secret member in issuer metadata is malformed:
	// secret members never appear there.
	if len(config.CredentialMetadata) > 0 {
		var md map[string]json.RawMessage
		if json.Unmarshal(config.CredentialMetadata, &md) == nil {
			for k := range md {
				if k != secretSeedMember && isSecretMember(k) {
					return d, fmt.Errorf("%w: %s in credential_metadata", errMalformedAdvertisement, k)
				}
			}
		}
	}
	if len(config.AuxiliaryDataSupported) > 0 {
		aux, err := parseAuxiliaryDataSupported(config.AuxiliaryDataSupported)
		if err != nil {
			return d, err
		}
		d.requireEncryption = d.requireEncryption || aux.toWalletSecret
		d.toIssuer = aux.toIssuer
	}
	return d, nil
}

// AdvertisementMalformed reports whether the secret delivery advertisement of
// one credential configuration (a JSON object) is malformed, so that the
// configuration is not offered. A document that does not decode as a
// configuration is not judged here.
func AdvertisementMalformed(configuration json.RawMessage) bool {
	// Read only the two members the advertisement lives in, by exact key, so
	// that a type error in an unrelated member (say "format":123) cannot
	// disable the check.
	cm, aux, err := advertisementMembers(configuration)
	if err != nil {
		if errors.Is(err, errMalformedAdvertisement) {
			return true
		}
		return false // not a JSON object: not judged here
	}
	_, err = secretDeliveryOf(&CredentialConfig{CredentialMetadata: cm, AuxiliaryDataSupported: aux})
	return err != nil
}

// advertisementMembers extracts credential_metadata and
// auxiliary_data_supported from a credential configuration by EXACT key.
// encoding/json matches struct fields case-insensitively (and folds characters
// such as U+017F to "s"), so a second, benign-looking key could otherwise
// shadow the real member for one reader and not for another. A configuration
// with any other key that case-folds to either name is malformed: fail closed.
func advertisementMembers(configuration json.RawMessage) (cm, aux json.RawMessage, err error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(configuration, &m); err != nil || m == nil {
		return nil, nil, errors.New("credential configuration is not an object")
	}
	for k := range m {
		for _, name := range []string{"credential_metadata", "auxiliary_data_supported"} {
			if k != name && strings.EqualFold(k, name) {
				return nil, nil, fmt.Errorf("%w: ambiguous %s member", errMalformedAdvertisement, name)
			}
		}
	}
	return m["credential_metadata"], m["auxiliary_data_supported"], nil
}

// UnmarshalJSON decodes a credential configuration, taking the two
// advertisement members by exact key (see advertisementMembers) rather than
// through encoding/json's case-insensitive field matching.
func (c *CredentialConfig) UnmarshalJSON(data []byte) error {
	type plain CredentialConfig // no methods: avoids recursion
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	cm, aux, err := advertisementMembers(data)
	if err != nil {
		return err
	}
	p.CredentialMetadata, p.AuxiliaryDataSupported = cm, aux
	*c = CredentialConfig(p)
	return nil
}

type auxAdvertisement struct {
	toWalletSecret bool
	toIssuer       []json.RawMessage
}

// parseAuxiliaryDataSupported validates auxiliary_data_supported (Auxiliary
// Data v0.1 section 5): an object with at least one of to_wallet and to_issuer,
// each a non-empty array of entries; an entry is an object with a string type,
// at most one entry per type and path; to_issuer entries may carry a boolean
// required. A hash_commitment entry needs a string alg and a claims path, and
// never an opening or commitment (values, not metadata). Entries of an
// unrecognised type are kept (a recipient ignores them) but must still be
// objects with a type. The returned toIssuer entries are verbatim.
func parseAuxiliaryDataSupported(raw json.RawMessage) (*auxAdvertisement, error) {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || top == nil {
		return nil, fmt.Errorf("%w: auxiliary_data_supported is not an object", errMalformedAdvertisement)
	}
	toWallet, hasW := top["to_wallet"]
	toIssuer, hasI := top["to_issuer"]
	if !hasW && !hasI {
		return nil, fmt.Errorf("%w: auxiliary_data_supported has neither to_wallet nor to_issuer", errMalformedAdvertisement)
	}
	out := &auxAdvertisement{}
	if hasW {
		entries, _, err := parseAuxEntries(toWallet, "to_wallet")
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.typ == auxTypeHashCommitment {
				out.toWalletSecret = true
			}
		}
	}
	if hasI {
		_, rawEntries, err := parseAuxEntries(toIssuer, "to_issuer")
		if err != nil {
			return nil, err
		}
		out.toIssuer = rawEntries
	}
	return out, nil
}

// auxEntryMembers are the members of an auxiliary data entry the engine knows.
var auxEntryMembers = []string{"type", "alg", "path", "required", "opening", "commitment"}

type auxEntry struct {
	typ string
}

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
		var m map[string]json.RawMessage
		if json.Unmarshal(re, &m) != nil || m == nil {
			return bad("has an entry that is not an object")
		}
		// A member spelled in another case ("Opening", "TYPE") is read as the
		// canonical one by a case-insensitive decoder: refuse the entry.
		for k := range m {
			for _, name := range auxEntryMembers {
				if k != name && strings.EqualFold(k, name) {
					return bad("has an entry with a case-variant member name")
				}
			}
		}
		// Values, never metadata, whatever the entry's type.
		if hasMemberFold(m, "opening") {
			return bad("has an entry carrying an opening")
		}
		if hasMemberFold(m, "commitment") {
			return bad("has an entry carrying a commitment")
		}
		var typ string
		if json.Unmarshal(m["type"], &typ) != nil || typ == "" {
			return bad("has an entry without a string type")
		}
		e := auxEntry{typ: typ}
		if rawReq, ok := m["required"]; ok {
			if list != "to_issuer" {
				return bad("has a required member")
			}
			var req *bool // JSON null decodes to nil: not a boolean
			if json.Unmarshal(rawReq, &req) != nil || req == nil {
				return bad("has a required member that is not a boolean")
			}
		}
		pathKey := ""
		if typ == auxTypeHashCommitment {
			var alg string
			if json.Unmarshal(m["alg"], &alg) != nil || alg == "" {
				return bad("has a hash_commitment entry without a string alg")
			}
			p, ok := claimsPathKey(m["path"])
			if !ok {
				return bad("has a hash_commitment entry without a valid claims path")
			}
			pathKey = p
		} else if p, has := m["path"]; has {
			// Unrecognised type: only duplicate detection, on the decoded
			// value so escapes and whitespace cannot hide a duplicate.
			var v interface{}
			if json.Unmarshal(p, &v) != nil {
				return bad("has an entry with an invalid path")
			}
			norm, err := json.Marshal(v)
			if err != nil {
				return bad("has an entry with an invalid path")
			}
			pathKey = string(norm)
		}
		dup := typ + "\x00" + pathKey
		if _, d := seen[dup]; d {
			return bad("has two entries of the same type and path")
		}
		seen[dup] = struct{}{}
		entries = append(entries, e)
	}
	return entries, rawEntries, nil
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
// verification, while a readable one is still scanned.
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
			// An ambiguous claim (the member twice, or in two letter cases) is
			// read differently by different decoders: never forwarded.
			if inspect || errors.Is(err, errAmbiguousAuxClaim) {
				return err
			}
			continue
		}
		if !has {
			continue
		}
		var decoded interface{}
		if json.Unmarshal(claim, &decoded) != nil {
			return auxProofErr("auxiliary_data is not valid JSON")
		}
		// The member name is matched in any letter case, at any depth and in
		// an entry of any type, and a repeated member cannot hide it: a key
		// that is present is found whichever duplicate a decoder keeps.
		if hasOpeningKey(decoded) {
			return auxProofErr("a proof entry carries an opening")
		}
		if _, isArray := decoded.([]interface{}); !isArray {
			return auxProofErr("auxiliary_data is not an array")
		}
	}
	return nil
}

// hasMemberFold reports whether m has a member named name under ANY case
// spelling. encoding/json matches struct fields case-insensitively, so a
// downstream decoder reads "Opening" or "OPENING" as the opening: an exact-key
// lookup would let it through.
func hasMemberFold(m map[string]json.RawMessage, name string) bool {
	for k := range m {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

// hasOpeningKey reports whether any object in v, at any depth, has a member
// named "opening" in any letter case.
func hasOpeningKey(v interface{}) bool {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			if strings.EqualFold(k, "opening") || hasOpeningKey(child) {
				return true
			}
		}
	case []interface{}:
		for _, child := range t {
			if hasOpeningKey(child) {
				return true
			}
		}
	}
	return false
}

// errAmbiguousAuxClaim: the payload has the auxiliary_data member more than
// once, in any letter case.
var errAmbiguousAuxClaim = errors.New("ambiguous auxiliary_data claim")

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
	// Walk the top-level members one by one so a repeated or case-variant
	// auxiliary_data member is seen (a map keeps only one of them).
	dec := json.NewDecoder(bytes.NewReader(payload))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false, auxProofErr("proof payload is not a JSON object")
	}
	var claim json.RawMessage
	found := false
	for dec.More() {
		keyTok, err := dec.Token()
		key, isString := keyTok.(string)
		if err != nil || !isString {
			return nil, false, auxProofErr("proof payload is not a JSON object")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false, auxProofErr("proof payload is not a JSON object")
		}
		if strings.EqualFold(key, auxiliaryDataMember) {
			if found || key != auxiliaryDataMember {
				return nil, false, fmt.Errorf("%w: %w", errAuxiliaryDataProof, errAmbiguousAuxClaim)
			}
			claim, found = value, true
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, false, auxProofErr("proof payload is not a JSON object")
	}
	return claim, found, nil
}
