package issuermetadata

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/sirosfoundation/go-wallet-backend/pkg/strictjson"
)

// The resolver decodes an issuer's metadata document into maps, which keep only
// the last of a repeated member and match nothing case-insensitively. A document
// that says one thing in its first "to_wallet" and another in its second is
// therefore read as the second here and possibly as the first by the issuer or
// another reader. For the members that decide whether the wallet demands
// encryption or sends auxiliary data, that difference is a security decision, so
// the raw bytes are checked once, here, before they are decoded
// (pkg/strictjson):
//
//   - the document's own member names, and the whole of credential_response_encryption
//     and credential_request_encryption, must be unambiguous, and so must the
//     names of credential_configurations_supported: these have no per-configuration
//     scope, so a violation fails the fetch;
//   - for each credential configuration, its own member names and the whole of
//     auxiliary_data_supported, credential_metadata and proof_types_supported
//     must be unambiguous: a configuration that is not is NOT OFFERED (removed
//     from the returned metadata, reported in ResolveResult.AmbiguousConfigurations).
//
// Other members (display, claims, ...) are not judged: a repeated member there
// changes no decision about secrets.

// documentSecurityMembers are document-level members read whole.
var documentSecurityMembers = []string{"credential_response_encryption", "credential_request_encryption"}

// configurationSecurityMembers are the members of a credential configuration
// read whole.
var configurationSecurityMembers = []string{"auxiliary_data_supported", "credential_metadata", "proof_types_supported"}

// checkEnvelope checks the raw outer document of a JSON response before any
// of its members is used: its own member names (signed_metadata, jwks,
// jwks_uri, ...) and the whole of an inline jwks, which selects the key the
// signed_metadata JWT is verified with. An error fails the fetch.
func checkEnvelope(body []byte) error {
	if err := strictjson.Walk(body, 1, strictjson.All); err != nil {
		return fmt.Errorf("issuer metadata has an ambiguous member name: %w", err)
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	if jwks, ok := doc["jwks"]; ok {
		if err := strictjson.Check(jwks, -1); err != nil {
			return fmt.Errorf("issuer metadata jwks is ambiguous: %w", err)
		}
	}
	return nil
}

// dropAmbiguousConfigurations checks data, the JSON document claims was decoded
// from, and removes from claims every credential configuration whose
// security-relevant members are ambiguous. It returns the removed ids, sorted.
// An error means the document is ambiguous where no configuration can be
// dropped for it; the caller fails the fetch.
func dropAmbiguousConfigurations(data []byte, claims map[string]interface{}) ([]string, error) {
	_, rawConfigs, err := checkDocumentLevel(data)
	if err != nil || rawConfigs == nil {
		return nil, err
	}
	var configs map[string]json.RawMessage
	if json.Unmarshal(rawConfigs, &configs) != nil {
		return nil, nil // not an object: the consumers judge that
	}
	ccs, _ := claims["credential_configurations_supported"].(map[string]interface{})
	var removed []string
	for id, raw := range configs {
		if configurationAmbiguous(raw) {
			delete(ccs, id)
			removed = append(removed, id)
		}
	}
	sort.Strings(removed)
	return removed, nil
}

// checkDocumentLevel checks the parts of the document that have no
// per-configuration scope (an error fails the fetch) and returns the raw
// credential_configurations_supported, nil when absent.
func checkDocumentLevel(data []byte) (map[string]json.RawMessage, json.RawMessage, error) {
	if err := strictjson.Walk(data, 1, strictjson.All); err != nil {
		return nil, nil, fmt.Errorf("issuer metadata has an ambiguous member name: %w", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("parsing issuer metadata: %w", err)
	}
	for _, name := range documentSecurityMembers {
		if raw, ok := doc[name]; ok {
			if err := strictjson.Check(raw, -1); err != nil {
				return nil, nil, fmt.Errorf("issuer metadata member %s is ambiguous: %w", name, err)
			}
		}
	}
	rawConfigs := doc["credential_configurations_supported"]
	if rawConfigs == nil {
		return doc, nil, nil
	}
	// Two configurations with one id: which one is meant cannot be told.
	if err := strictjson.Walk(rawConfigs, 1, 0); err != nil {
		return nil, nil, fmt.Errorf("issuer metadata has a repeated credential configuration id: %w", err)
	}
	return doc, rawConfigs, nil
}

// configurationAmbiguous reports whether a credential configuration's own member
// names or any of its security-relevant members are ambiguous. A configuration
// that is not an object is not judged here.
func configurationAmbiguous(raw json.RawMessage) bool {
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return false
	}
	if strictjson.Check(raw, 1) != nil {
		return true
	}
	for _, name := range configurationSecurityMembers {
		if sub, ok := members[name]; ok && strictjson.Check(sub, -1) != nil {
			return true
		}
	}
	return false
}
