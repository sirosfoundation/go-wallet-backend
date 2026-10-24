package engine

import (
	"encoding/json"
	"errors"
	"fmt"
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
	// requiredToIssuer: at least one to_issuer entry has required=true.
	requiredToIssuer bool
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
		d.requiredToIssuer = aux.requiredToIssuer
	}
	return d, nil
}

// AdvertisementMalformed reports whether the secret delivery advertisement of
// one credential configuration (a JSON object) is malformed, so that the
// configuration is not offered. A document that does not decode as a
// configuration is not judged here.
func AdvertisementMalformed(configuration json.RawMessage) bool {
	// Decode only the two members the advertisement lives in, so that a type
	// error in an unrelated member (say "format":123) cannot disable the check.
	var cfg struct {
		CredentialMetadata     json.RawMessage `json:"credential_metadata"`
		AuxiliaryDataSupported json.RawMessage `json:"auxiliary_data_supported"`
	}
	if json.Unmarshal(configuration, &cfg) != nil {
		return false
	}
	_, err := secretDeliveryOf(&CredentialConfig{
		CredentialMetadata:     cfg.CredentialMetadata,
		AuxiliaryDataSupported: cfg.AuxiliaryDataSupported,
	})
	return err != nil
}

type auxAdvertisement struct {
	toWalletSecret   bool
	toIssuer         []json.RawMessage
	requiredToIssuer bool
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
		entries, rawEntries, err := parseAuxEntries(toIssuer, "to_issuer")
		if err != nil {
			return nil, err
		}
		out.toIssuer = rawEntries
		for _, e := range entries {
			if e.required {
				out.requiredToIssuer = true
			}
		}
	}
	return out, nil
}

type auxEntry struct {
	typ      string
	required bool
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
			e.required = *req
		}
		pathKey := ""
		if typ == auxTypeHashCommitment {
			var alg string
			if json.Unmarshal(m["alg"], &alg) != nil || alg == "" {
				return bad("has a hash_commitment entry without a string alg")
			}
			if _, has := m["opening"]; has {
				return bad("has a hash_commitment entry carrying an opening")
			}
			if _, has := m["commitment"]; has {
				return bad("has a hash_commitment entry carrying a commitment")
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
