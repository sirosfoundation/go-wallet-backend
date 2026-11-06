package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// ErrPrivateDataOwnership is returned when an uploaded private-data container
// cannot be shown to belong to the user it would be stored for: it is not a
// valid container, it has no prfKeys, or none of its prfKeys[].credentialId
// is one of the user's registered WebAuthn credentials. Handlers map it to
// HTTP 422 with PrivateDataOwnershipErrorCode (distinct from the 412 ETag
// conflict).
var ErrPrivateDataOwnership = errors.New("private data does not belong to user")

// PrivateDataOwnershipErrorCode is the stable machine-readable error code
// sent to clients alongside HTTP 422 for ErrPrivateDataOwnership.
const PrivateDataOwnershipErrorCode = "private_data_ownership"

// taggedBinaryKey is the key of the tagged binary representation
// {"$b64u": "<base64url-no-padding>"} used by the privatedata container.
const taggedBinaryKey = "$b64u"

func ownershipError(reason string) error {
	return fmt.Errorf("%w: %s", ErrPrivateDataOwnership, reason)
}

// looksLikeCompactJWE reports whether s has the shape of a compact JWE:
// five dot-separated parts with a non-empty protected header and ciphertext.
func looksLikeCompactJWE(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 5 && parts[0] != "" && parts[3] != ""
}

// decodeBase64Any decodes s with the first encoding that accepts it.
func decodeBase64Any(s string, encs ...*base64.Encoding) ([]byte, bool) {
	for _, enc := range encs {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// storedCredentialIDs returns the raw credential ID bytes of a stored
// credential: its CredentialID bytes when set, plus the ID text decoded under
// every base64 variant (url/std, padded or not), so accounts that store the
// ID in another encoding, or without CredentialID bytes, are still recognised.
func storedCredentialIDs(c domain.WebauthnCredential) [][]byte {
	var out [][]byte
	if len(c.CredentialID) > 0 {
		out = append(out, c.CredentialID)
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(c.ID); err == nil && len(b) > 0 {
			out = append(out, b)
		}
	}
	return out
}

// containerCredentialIDs extracts the prfKeys[].credentialId values (as raw
// bytes) from a privatedata container {mainKey, prfKeys[], jwe}. It fails closed: any
// deviation from the expected shape is an error. The error text never
// contains container contents.
func containerCredentialIDs(data []byte) ([][]byte, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, ownershipError("not valid JSON")
	}
	obj, ok := root.(map[string]any)
	if !ok {
		return nil, ownershipError("container is not a JSON object")
	}
	// mainKey is only checked when present: older wallet-frontend containers
	// omit it. When present it must be an object.
	if mk, present := obj["mainKey"]; present {
		if _, ok := mk.(map[string]any); !ok {
			return nil, ownershipError("mainKey is not an object")
		}
	}
	// jwe MUST be present and MUST be a compact JWE (five dot-separated
	// parts; for A256GCMKW the encrypted-key part is empty). Nothing is
	// decrypted; this only refuses blobs that can never be unlocked.
	jwe, ok := obj["jwe"].(string)
	if !ok || !looksLikeCompactJWE(jwe) {
		return nil, ownershipError("jwe missing or not a compact JWE")
	}
	prfKeys, ok := obj["prfKeys"].([]any)
	if !ok {
		return nil, ownershipError("prfKeys missing or not an array")
	}
	if len(prfKeys) == 0 {
		return nil, ownershipError("prfKeys is empty")
	}

	ids := make([][]byte, 0, len(prfKeys))
	for _, entry := range prfKeys {
		entryObj, ok := entry.(map[string]any)
		if !ok {
			return nil, ownershipError("prfKeys entry is not an object")
		}
		tagged, ok := entryObj["credentialId"].(map[string]any)
		if !ok || len(tagged) != 1 {
			return nil, ownershipError("credentialId is not tagged binary")
		}
		str, ok := tagged[taggedBinaryKey].(string)
		if !ok {
			return nil, ownershipError("credentialId is not tagged binary")
		}
		raw, ok := decodeBase64Any(str, base64.RawURLEncoding, base64.URLEncoding)
		if !ok || len(raw) == 0 {
			return nil, ownershipError("credentialId is not valid base64url")
		}
		ids = append(ids, raw)
	}
	return ids, nil
}

// validatePrivateDataOwnership checks that the private-data container belongs
// to the user: it must be a well-formed container and at least one
// prfKeys[].credentialId must be among the user's registered credentials.
// Entries for credentials the user no longer (or does not yet) have are
// tolerated as long as one entry matches. Callers that add or remove a
// credential must call it with the user's credential list as it will be after
// the change.
//
// Only the user id and a reason are logged, never container contents.
func validatePrivateDataOwnership(logger *zap.Logger, userID domain.UserID, creds []domain.WebauthnCredential, data []byte) error {
	ids, err := containerCredentialIDs(data)
	if err == nil {
		registered := make(map[string]struct{}, len(creds))
		for _, c := range creds {
			for _, b := range storedCredentialIDs(c) {
				registered[string(b)] = struct{}{}
			}
		}
		for _, id := range ids {
			if _, ok := registered[string(id)]; ok {
				return nil
			}
		}
		err = ownershipError("no prfKeys credentialId matches a registered credential")
	}
	if logger != nil {
		logger.Warn("Private data rejected",
			zap.String("user_id", userID.String()),
			zap.String("reason", err.Error()))
	}
	return err
}
