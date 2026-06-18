package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// CryptoSignerES256 implements jwt.SigningMethod for any crypto.Signer with an
// ECDSA P-256 key. This enables PKCS#11, HSM, and other hardware-backed signers
// to be used with golang-jwt.
type CryptoSignerES256 struct {
	signer crypto.Signer
}

// NewCryptoSignerES256 wraps a crypto.Signer (must have an *ecdsa.PublicKey on P-256).
func NewCryptoSignerES256(s crypto.Signer) (*CryptoSignerES256, error) {
	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signer public key is not *ecdsa.PublicKey")
	}
	if pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signer curve is %v, expected P-256", pub.Curve.Params().Name)
	}
	return &CryptoSignerES256{signer: s}, nil
}

func (m *CryptoSignerES256) Verify(signingString string, sig []byte, key interface{}) error {
	return jwt.SigningMethodES256.Verify(signingString, sig, key)
}

// Sign implements jwt.SigningMethod. The key parameter is intentionally ignored:
// the real private key is held inside the crypto.Signer (which may be PKCS#11
// or HSM-backed and non-exportable). Callers MUST pass nil as the key via
// SignToken(); passing a non-nil key is rejected to prevent silent misuse.
func (m *CryptoSignerES256) Sign(signingString string, key interface{}) ([]byte, error) {
	if key != nil {
		return nil, fmt.Errorf("CryptoSignerES256.Sign: key must be nil (signing key is held by the internal crypto.Signer); got %T", key)
	}

	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signingString))
	digest := hasher.Sum(nil)

	sigBytes, err := m.signer.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("crypto.Signer.Sign: %w", err)
	}

	// The signature from crypto.Signer is ASN.1 DER-encoded.
	// golang-jwt ES256 expects raw (r||s) format, 64 bytes for P-256.
	r, s, err := parseASN1Signature(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ASN.1 signature: %w", err)
	}

	keyBytes := 32 // P-256 = 256 bits / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	out := make([]byte, 2*keyBytes)
	copy(out[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(out[2*keyBytes-len(sBytes):], sBytes)

	return out, nil
}

func (m *CryptoSignerES256) Alg() string {
	return "ES256"
}

// SignToken signs a jwt.Token using the wrapped crypto.Signer.
// Use this instead of token.SignedString() when the key is HSM-backed.
func (m *CryptoSignerES256) SignToken(token *jwt.Token) (string, error) {
	token.Method = m
	// Pass nil as the key — our Sign() ignores it and uses the internal signer
	return token.SignedString(nil)
}

// parseASN1Signature parses a DER-encoded ECDSA signature into (r, s).
func parseASN1Signature(sig []byte) (*big.Int, *big.Int, error) {
	var seq struct {
		R *big.Int
		S *big.Int
	}
	rest, err := asn1.Unmarshal(sig, &seq)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal ASN.1 signature: %w", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("trailing data after ASN.1 signature")
	}
	if seq.R == nil || seq.S == nil {
		return nil, nil, fmt.Errorf("nil r or s in ASN.1 signature")
	}
	return seq.R, seq.S, nil
}
