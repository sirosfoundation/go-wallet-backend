// Package advertisement validates the SIROS extension members of an issuer's
// credential_metadata (org.siros.secret_seed, org.siros.holder_commitments).
// The AuthZEN proxy uses it to drop credential configurations whose
// advertisement is malformed before the metadata reaches a wallet.
package advertisement

import (
	"encoding/json"
	"regexp"
)

const (
	maxSeedNamespaces     = 8  // privatedata-spec 5A.1/5A.4: 1..8 namespaces
	maxSeedNamespaceBytes = 64 // privatedata-spec 5A.1: 1..64 UTF-8 bytes

	// secretSeedMember is the SIROS extension member of credential_metadata.
	// Consumers only read the issuer-metadata advertisement of it
	// ({"namespaces": [...]}); a delivered seed travels in the encrypted
	// response and is handled by the client alone.
	secretSeedMember = "org.siros.secret_seed"
)

// SecretSeedAdvertisement inspects the credential_metadata of one credential
// configuration of the issuer metadata for the org.siros.secret_seed member.
// present reports whether the member exists; ok is true only for the valid
// advertisement form {"namespaces": [1..8 distinct names of 1..64 bytes, none
// "namespaces"]} (privatedata-spec 5A.4). Anything else, in particular a member
// carrying hex or other values instead of a name list, is malformed
// (present && !ok). A credential_metadata that is not an object has no member.
func SecretSeedAdvertisement(credentialMetadata json.RawMessage) (present, ok bool) {
	if len(credentialMetadata) == 0 {
		return false, false
	}
	var md map[string]json.RawMessage
	if json.Unmarshal(credentialMetadata, &md) != nil {
		return false, false
	}
	raw, present := md[secretSeedMember]
	if !present {
		return false, false
	}
	var adv map[string]json.RawMessage
	if json.Unmarshal(raw, &adv) != nil || len(adv) != 1 {
		return true, false
	}
	var ns []string
	if json.Unmarshal(adv["namespaces"], &ns) != nil || len(ns) == 0 || len(ns) > maxSeedNamespaces {
		return true, false
	}
	seen := make(map[string]struct{}, len(ns))
	for _, n := range ns {
		if !validSeedNamespace(n) {
			return true, false
		}
		if _, dup := seen[n]; dup {
			return true, false
		}
		seen[n] = struct{}{}
	}
	return true, true
}

// validSeedNamespace: 1..64 bytes, and not the name "namespaces", which is
// reserved for the issuer-metadata advertisement (5A.1).
func validSeedNamespace(n string) bool {
	return n != "" && n != "namespaces" && len(n) <= maxSeedNamespaceBytes
}

const (
	holderCommitmentsMember    = "org.siros.holder_commitments"
	maxHolderCommitments       = 4
	maxHolderCommitmentNameLen = 32
)

var holderCommitmentNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// validHolderCommitmentName: a short lowercase name that does not look like a
// hex value (16 or more hex characters), so a value can never pass as a name.
func validHolderCommitmentName(n string) bool {
	if n == "" || len(n) > maxHolderCommitmentNameLen || !holderCommitmentNameRE.MatchString(n) {
		return false
	}
	if len(n) >= 16 {
		allHex := true
		for _, c := range n {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				allHex = false
				break
			}
		}
		if allHex {
			return false
		}
	}
	return true
}

// HolderCommitmentsAdvertisement inspects the credential_metadata of one
// credential configuration for the org.siros.holder_commitments member. present
// reports whether the member exists; ok is true only for the valid form
// {"commitments": [1..4 distinct short names]}. Anything else (extra members,
// values instead of names, hex-looking strings, wrong counts) is malformed
// (present && !ok). Unknown but well-formed names are kept in names.
func HolderCommitmentsAdvertisement(credentialMetadata json.RawMessage) (present bool, names []string, ok bool) {
	if len(credentialMetadata) == 0 {
		return false, nil, false
	}
	var md map[string]json.RawMessage
	if json.Unmarshal(credentialMetadata, &md) != nil {
		return false, nil, false
	}
	raw, present := md[holderCommitmentsMember]
	if !present {
		return false, nil, false
	}
	var adv map[string]json.RawMessage
	if json.Unmarshal(raw, &adv) != nil || len(adv) != 1 {
		return true, nil, false
	}
	var ns []string
	if json.Unmarshal(adv["commitments"], &ns) != nil || len(ns) == 0 || len(ns) > maxHolderCommitments {
		return true, nil, false
	}
	seen := make(map[string]struct{}, len(ns))
	for _, n := range ns {
		if !validHolderCommitmentName(n) {
			return true, nil, false
		}
		if _, dup := seen[n]; dup {
			return true, nil, false
		}
		seen[n] = struct{}{}
	}
	return true, ns, true
}
