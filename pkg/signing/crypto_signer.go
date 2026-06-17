package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

func (m *CryptoSignerES256) Sign(signingString string, key interface{}) ([]byte, error) {
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
	// ASN.1 SEQUENCE { INTEGER r, INTEGER s }
	if len(sig) < 6 || sig[0] != 0x30 {
		return nil, nil, fmt.Errorf("invalid ASN.1 signature")
	}

	// Parse outer SEQUENCE
	pos := 2 // skip tag + length byte (simplified; works for short form)
	if sig[1]&0x80 != 0 {
		// Long form length — not expected for ECDSA sigs but handle gracefully
		lenBytes := int(sig[1] & 0x7f)
		pos = 2 + lenBytes
	}

	// Parse r INTEGER
	if pos >= len(sig) || sig[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for r")
	}
	pos++
	rLen := int(sig[pos])
	pos++
	r := new(big.Int).SetBytes(sig[pos : pos+rLen])
	pos += rLen

	// Parse s INTEGER
	if pos >= len(sig) || sig[pos] != 0x02 {
		return nil, nil, fmt.Errorf("expected INTEGER tag for s")
	}
	pos++
	sLen := int(sig[pos])
	pos++
	s := new(big.Int).SetBytes(sig[pos : pos+sLen])

	return r, s, nil
}
