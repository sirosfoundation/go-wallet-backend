package engine

import (
	"strings"

	"github.com/sirosfoundation/go-wallet-backend/pkg/strictjson"
)

// The strict decoding step lives in pkg/strictjson. The engine uses it for the
// credential offer only: a third party writes the offer and both the client and
// the engine read it, so an ambiguity could make the two readings differ. Every
// other document has one author, who already holds what a differing reading
// would protect, and is decoded with encoding/json.

func decodeStrict(data []byte, v any) error { return strictjson.Decode(data, v) }

// containsMember reports whether a decoded JSON value has a member of the given
// name, at any depth. The comparison ignores letter case: a Go decoder reads
// "Opening" as the member "opening", so the engine must not let one pass.
func containsMember(v any, name string) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, el := range x {
			if strings.EqualFold(k, name) || containsMember(el, name) {
				return true
			}
		}
	case []any:
		for _, el := range x {
			if containsMember(el, name) {
				return true
			}
		}
	}
	return false
}
