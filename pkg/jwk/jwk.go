// Package jwk provides generic JSON Web Key helpers (RFC 7517/7638) that
// don't have anything specific to WIA/OID4VCI about them, so they can be
// reused anywhere a JWK map needs a thumbprint or an EC public key parsed
// out of it.
package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Thumbprint computes the JWK Thumbprint (RFC 7638) for the given EC JWK.
func Thumbprint(jwk map[string]interface{}) (string, error) {
	// For EC keys, thumbprint input is {"crv":"...","kty":"EC","x":"...","y":"..."}
	kty, _ := jwk["kty"].(string)
	if kty != "EC" {
		return "", fmt.Errorf("unsupported key type for JKT: %s", kty)
	}

	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)

	if crv == "" || x == "" || y == "" {
		return "", errors.New("incomplete EC JWK (missing crv, x, or y)")
	}

	// RFC 7638: JSON with lexicographic order of required members.
	// Using a struct with ordered fields ensures deterministic serialization.
	thumbprintInput := struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{
		Crv: crv,
		Kty: kty,
		X:   x,
		Y:   y,
	}

	data, err := json.Marshal(thumbprintInput)
	if err != nil {
		return "", fmt.Errorf("marshal JKT input: %w", err)
	}

	hash := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// ParseECPublicKey parses an EC public key from a JWK map.
// Only P-256 is currently accepted.
func ParseECPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	if kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}

	crv, _ := jwk["crv"].(string)
	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)

	if crv == "" || xB64 == "" || yB64 == "" {
		return nil, errors.New("incomplete EC JWK")
	}

	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve %q: only P-256 is accepted", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	curve := CurveForName(crv)
	if curve == nil {
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	pubKey, err := BuildECPublicKeyFromCoordinates(curve, xBytes, yBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid EC point: %w", err)
	}
	return pubKey, nil
}

// BuildECPublicKeyFromCoordinates builds an *ecdsa.PublicKey from decoded
// x/y coordinate bytes for the given curve, matching RFC 7518 §6.2.1.2's
// fixed-length encoding: shorter values (a leading zero byte omitted by
// some real-world producers) are left-padded to the curve's coordinate
// size, and anything longer is rejected outright - both to reject a
// malformed/adversarial JWK claiming an oversized coordinate and to bound
// the uncompressed-point allocation below to small curve-fixed constants.
// Curve-agnostic (any curve elliptic.Curve/ecdsa.ParseUncompressedPublicKey
// accepts) so callers needing P-384/P-521 support beyond ParseECPublicKey's
// P-256-only scope can still share this one coordinate-handling
// implementation.
func BuildECPublicKeyFromCoordinates(curve elliptic.Curve, xBytes, yBytes []byte) (*ecdsa.PublicKey, error) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(xBytes) > byteLen || len(yBytes) > byteLen {
		return nil, fmt.Errorf("coordinate too large: x=%d y=%d (expected <= %d)", len(xBytes), len(yBytes), byteLen)
	}

	for len(xBytes) < byteLen {
		xBytes = append([]byte{0}, xBytes...)
	}
	for len(yBytes) < byteLen {
		yBytes = append([]byte{0}, yBytes...)
	}

	// SEC1 uncompressed point format (0x04 || X || Y) - RFC 7518 §6.2.1.2.
	uncompressed := make([]byte, 1+2*byteLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1:1+byteLen], xBytes)
	copy(uncompressed[1+byteLen:], yBytes)

	return ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
}

// CurveForName returns the elliptic curve for the given JWK crv name.
// Only P-256 is currently supported.
func CurveForName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	default:
		return nil
	}
}
