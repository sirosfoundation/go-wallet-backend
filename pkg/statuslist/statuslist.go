// Package statuslist builds the compressed, always-empty (all-VALID) bit
// string for an IETF Token Status List (the `lst` value inside a
// status_list JWT's payload) - not the JWT itself, which the service layer
// (RegisterWalletProviderStatusListRoute) wraps this value in.
//
// Every WIA's `client_status` and every KA's `key_storage_status` does
// reference an index in this list (CS-04 §7.1.2/§7.1.3 require the claims),
// but no bit in it is ever set: this wallet provider does not implement
// WIA/KA revocation-chaining (see AttestationConfig's type-level comment in
// pkg/config), so the list is permanently all-VALID and the compressed
// value this package returns is a constant. What actually bounds exposure
// from a compromised or revoked wallet instance is the short WIA/KA
// lifetime, not this list.
package statuslist

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"fmt"
)

// EmptyCompressedList returns the base64url-encoded (no padding), raw
// DEFLATE-compressed (RFC 1951) byte array for a 1-bit-per-status list of
// size n, with every status set to 0 (VALID) — the `lst` value of a Token
// Status List's `status_list` claim.
func EmptyCompressedList(n int) (string, error) {
	if n <= 0 {
		n = 1
	}
	// 1 bit per status, packed 8 to a byte; all-zero bytes represent "VALID"
	// for every entry regardless of packing order, so no bit-level packing
	// logic is needed beyond sizing the buffer.
	raw := make([]byte, (n+7)/8)

	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return "", fmt.Errorf("create deflate writer: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return "", fmt.Errorf("compress status list: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalize status list compression: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}
