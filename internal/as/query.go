package as

import (
	"fmt"
	"sort"
	"strings"
)

// BuildTokenQuery converts a token request into a SPOCP S-expression query.
// The query has the form: (token (key value) (key value) ...)
// Keys are sorted lexicographically for deterministic evaluation.
func BuildTokenQuery(sub, aud, tenantID string, tac TAC, acr string) string {
	claims := make(map[string]string)

	if sub != "" {
		claims["sub"] = sub
	}
	if aud != "" {
		claims["aud"] = aud
	}
	if tenantID != "" {
		claims["tenant_id"] = tenantID
	}
	if tac != "" {
		claims["tac"] = string(tac)
	}
	if acr != "" {
		claims["acr"] = acr
	}

	// Sort keys for deterministic output.
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("(5:token")
	for _, k := range keys {
		v := claims[k]
		fmt.Fprintf(&sb, " (%d:%s %d:%s)", len(k), k, len(v), v)
	}
	sb.WriteString(")")

	return sb.String()
}
