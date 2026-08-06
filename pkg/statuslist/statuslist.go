// Package statuslist builds the compressed, always-empty (all-VALID) bit
// string for an IETF Token Status List (the `lst` value inside a
// status_list JWT's payload) - not the JWT itself, which the service layer
// (RegisterWalletProviderStatusListRoute) wraps this value in.
//
// This wallet provider does not implement WIA/KA revocation-chaining (see
// AttestationConfig's type-level comment in pkg/config) — nothing it issues
// ever references a status list index. This package exists purely so the
// wallet provider can still publish a validly-shaped, always-empty status
// list for interop completeness (some deployments expect a Wallet Provider
// to expose one), without any WIA/KA depending on it.
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
