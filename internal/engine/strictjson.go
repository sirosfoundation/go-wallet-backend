package engine

import (
	"encoding/json"

	"github.com/sirosfoundation/go-wallet-backend/pkg/strictjson"
)

// The strict decoding step lives in pkg/strictjson (shared with the issuer
// metadata resolver). These are the engine's names for it.
var errAmbiguousJSON = strictjson.ErrAmbiguous

func decodeStrict(data []byte, v any) error { return strictjson.Decode(data, v) }

func checkUnambiguous(data []byte, depth int) error { return strictjson.Check(data, depth) }

func containsMember(v any, name string) bool { return strictjson.ContainsMember(v, name) }

// decodeCredentialResponse decodes a plain credential response. The credentials
// in it are opaque (their claims and JSON-LD contexts follow their own formats,
// and may legitimately have a member such as "Type"): only the response's own
// member names, and the whole of its credential_metadata (where a secret could
// hide), must be unambiguous.
func decodeCredentialResponse(data []byte, v *CredentialResponse) error {
	if err := strictjson.Check(data, 1); err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	if len(v.CredentialMetadata) > 0 {
		return strictjson.Check(v.CredentialMetadata, -1)
	}
	return nil
}
