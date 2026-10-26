package engine

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// toIssuerRecognised: at least one to_issuer entry is of a type the engine
	// knows (hash_commitment), so the wallet needs the credential type.
	toIssuerRecognised bool
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
		d.toIssuerRecognised = aux.toIssuerRecognised
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
	toWalletSecret     bool
	toIssuer           []json.RawMessage
	toIssuerRecognised bool
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
	for k := range top {
		for _, name := range []string{"to_wallet", "to_issuer"} {
			if k != name && strings.EqualFold(k, name) {
				return nil, fmt.Errorf("%w: ambiguous %s member", errMalformedAdvertisement, name)
			}
		}
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
		entries, rawEntries, err := parseAuxEntries(toIssuer, "to_issuer")
		if err != nil {
			return nil, err
		}
		out.toIssuer = rawEntries
		for _, e := range entries {
			if e.typ == auxTypeHashCommitment {
				out.toIssuerRecognised = true
			}
		}
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
		// Values, never metadata: no opening or commitment member at any depth,
		// in any letter case, whatever the entry's type (a raw token walk, so a
		// repeated member cannot shadow it).
		if values, _, err := scanMemberNames(re, "opening", "commitment"); err != nil || values {
			return bad("has an entry carrying an opening or a commitment")
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
		// The member name is matched in any letter case, at any depth and in
		// an entry of any type, on the raw token stream so that a repeated
		// member (which a map decode would discard) cannot hide it.
		hasOpening, isArray, err := scanClaimForOpening(claim)
		if err != nil {
			return auxProofErr("auxiliary_data is not valid JSON")
		}
		if hasOpening {
			return auxProofErr("a proof entry carries an opening")
		}
		if !isArray {
			return auxProofErr("auxiliary_data is not an array")
		}
	}
	return nil
}

// scanClaimForOpening walks the raw JSON of a claim token by token, so no
// repeated member is discarded, and reports whether any object at any depth has
// a member named "opening" in any letter case, and whether the claim is an array.
func scanClaimForOpening(raw json.RawMessage) (hasOpening, isArray bool, err error) {
	hasOpening, isArray, _, err = walkMembers(raw, "opening")
	return hasOpening, isArray, err
}

// scanMemberNames is the token walk behind scanClaimForOpening for any set of
// member names.
func scanMemberNames(raw json.RawMessage, names ...string) (found, isArray bool, err error) {
	found, isArray, _, err = walkMembers(raw, names...)
	return found, isArray, err
}

// walkMembers walks raw JSON token by token. It reports whether any object at
// any depth has a member whose name equals one of names in any letter case,
// whether the document is an array, and whether any object repeats a member
// name. A decode into maps would drop the repeated member, which is why the
// token stream is used.
func walkMembers(raw json.RawMessage, names ...string) (found, isArray, duplicate bool, err error) {
	type frame struct {
		obj, expectKey bool
		keys           map[string]struct{}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var stack []frame
	first := true
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return false, false, false, err
		}
		if first {
			d, ok := tok.(json.Delim)
			isArray = ok && d == '['
			first = false
		}
		top := len(stack) - 1
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if top >= 0 && stack[top].obj {
					stack[top].expectKey = true // this container is the member's value
				}
				f := frame{obj: d == '{', expectKey: d == '{'}
				if f.obj {
					f.keys = map[string]struct{}{}
				}
				stack = append(stack, f)
			default:
				if top >= 0 {
					stack = stack[:top]
				}
			}
			continue
		}
		if top >= 0 && stack[top].obj {
			if stack[top].expectKey {
				if key, ok := tok.(string); ok {
					if _, seen := stack[top].keys[key]; seen {
						duplicate = true
					}
					stack[top].keys[key] = struct{}{}
					for _, n := range names {
						if strings.EqualFold(key, n) {
							found = true
						}
					}
				}
				stack[top].expectKey = false
			} else {
				stack[top].expectKey = true
			}
		}
	}
	if len(stack) != 0 {
		return false, false, false, io.ErrUnexpectedEOF
	}
	return found, isArray, duplicate, nil
}

// SignedMetadataMayCarryOpening reports whether a signed_metadata JWT (kept
// verbatim by the resolver) might carry a secret the decoded document does not
// show: its payload has a member named "opening" in any letter case at any
// depth, repeats a member name in any object (the decoded document keeps only
// one of the repeats, so a configured secret member or an opening in the other
// would go unseen), or cannot be read. The
// resolver decodes the payload into maps before the advertisement is checked,
// and a map drops a repeated member, so the check of the decoded document
// cannot see what the original payload still holds; the JWT is scanned on its
// raw tokens instead. An unreadable token is treated as carrying one (fail
// closed).
func SignedMetadataMayCarryOpening(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return true
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return true
	}
	found, _, duplicate, err := walkMembers(payload, "opening")
	return err != nil || found || duplicate
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
	// Nothing may follow the object: a decoder that stops after the first
	// value would see a different claim set than one that reads on.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		// Ambiguous like a repeated claim: never forwarded, inspected or not.
		return nil, false, fmt.Errorf("%w: %w", errAuxiliaryDataProof, errAmbiguousAuxClaim)
	}
	return claim, found, nil
}
