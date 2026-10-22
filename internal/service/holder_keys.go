package service

import "github.com/sirosfoundation/go-wallet-backend/internal/domain"

// holderKeySet lists every key a user's holder data may be stored under,
// deduped and in a stable order: the known keys (the stored DID, a tombstone's
// DID), the canonical domain.HolderDID(userID) the HTTP credential handlers
// write under (a stored DID can be empty or differ), and the bare user id
// (legacy fallback). Account deletion, the revoke cascade and the reconcile
// probe all use it so they cannot drift.
func holderKeySet(userID domain.UserID, known ...string) []string {
	candidates := append(append([]string(nil), known...), domain.HolderDID(userID.String()), userID.String())
	seen := make(map[string]bool, len(candidates))
	var keys []string
	for _, k := range candidates {
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
	}
	return keys
}
