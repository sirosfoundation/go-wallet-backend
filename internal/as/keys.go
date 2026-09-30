package as

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

// KeyManager manages asymmetric signing keys for the AS.
// It supports multiple active keys identified by kid for rotation.
type KeyManager struct {
	mu      sync.RWMutex
	keys    map[string]*SigningKey // kid → key
	active  string                 // kid of the current signing key
	jwksSet jose.JSONWebKeySet     // cached JWKS for the endpoint
}

// SigningKey pairs a crypto.Signer with its kid and algorithm.
type SigningKey struct {
	Kid       string
	Signer    crypto.Signer
	Algorithm jose.SignatureAlgorithm
	PublicKey crypto.PublicKey
}

// NewKeyManager creates a KeyManager and loads the initial signing key.
func NewKeyManager(keyPath string) (*KeyManager, error) {
	km := &KeyManager{
		keys: make(map[string]*SigningKey),
	}

	sk, err := loadSigningKeyFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("as: failed to load signing key: %w", err)
	}

	km.keys[sk.Kid] = sk
	km.active = sk.Kid
	km.rebuildJWKS()

	return km, nil
}

// ActiveKey returns the current active signing key.
func (km *KeyManager) ActiveKey() *SigningKey {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keys[km.active]
}

// JWKS returns the cached JSON Web Key Set containing all public keys.
// Returns a defensive copy to prevent callers from mutating internal state.
func (km *KeyManager) JWKS() jose.JSONWebKeySet {
	km.mu.RLock()
	defer km.mu.RUnlock()
	copy := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(km.jwksSet.Keys)),
	}
	for i, k := range km.jwksSet.Keys {
		copy.Keys[i] = k
	}
	return copy
}

// AddKey adds a signing key. If activate is true, it becomes the active key.
func (km *KeyManager) AddKey(sk *SigningKey, activate bool) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.keys[sk.Kid] = sk
	if activate {
		km.active = sk.Kid
	}
	km.rebuildJWKS()
}

// RemoveKey removes a key by kid. Cannot remove the active key.
func (km *KeyManager) RemoveKey(kid string) error {
	km.mu.Lock()
	defer km.mu.Unlock()
	if kid == km.active {
		return fmt.Errorf("as: cannot remove active key %q", kid)
	}
	delete(km.keys, kid)
	km.rebuildJWKS()
	return nil
}

// rebuildJWKS rebuilds the cached JWKS.
// Must be called with mu held (write lock), or during construction before sharing.
func (km *KeyManager) rebuildJWKS() {
	var keys []jose.JSONWebKey
	for _, sk := range km.keys {
		jwk := jose.JSONWebKey{
			Key:       sk.PublicKey,
			KeyID:     sk.Kid,
			Algorithm: string(sk.Algorithm),
			Use:       "sig",
		}
		keys = append(keys, jwk)
	}
	km.jwksSet = jose.JSONWebKeySet{Keys: keys}
}

// loadSigningKeyFromFile reads a PEM-encoded private key and returns a SigningKey.
// Supported key types: ECDSA P-256, ECDSA P-384, Ed25519.
func loadSigningKeyFromFile(path string) (*SigningKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := parsePrivateKey(block)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key from %s: %w", path, err)
	}

	return newSigningKey(key)
}

// parsePrivateKey parses a PEM block into a crypto.Signer.
func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key does not implement crypto.Signer")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// newSigningKey creates a SigningKey from a crypto.Signer, auto-detecting the
// algorithm from the signer's public key (so HSM-backed signers whose concrete
// type is not *ecdsa.PrivateKey work too). The kid is the RFC 7638 JWK
// thumbprint of the public key.
func newSigningKey(signer crypto.Signer) (*SigningKey, error) {
	if signer == nil {
		return nil, fmt.Errorf("nil signer")
	}
	pub := signer.Public()
	var alg jose.SignatureAlgorithm

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k == nil {
			return nil, fmt.Errorf("signer has a nil public key")
		}
		switch k.Curve {
		case elliptic.P256():
			alg = jose.ES256
		case elliptic.P384():
			alg = jose.ES384
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key length %d", len(k))
		}
		alg = jose.EdDSA
	default:
		return nil, fmt.Errorf("unsupported key type %T", pub)
	}

	jwk := jose.JSONWebKey{Key: pub}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute key thumbprint: %w", err)
	}

	return &SigningKey{
		Kid:       base64.RawURLEncoding.EncodeToString(tp),
		Signer:    signer,
		Algorithm: alg,
		PublicKey: pub,
	}, nil
}

// NewKeyManagerFromSigner creates a KeyManager whose active key is an
// arbitrary crypto.Signer (for example a PKCS#11 HSM key).
func NewKeyManagerFromSigner(signer crypto.Signer) (*KeyManager, error) {
	sk, err := newSigningKey(signer)
	if err != nil {
		return nil, fmt.Errorf("as: unsupported signing key: %w", err)
	}
	km := &KeyManager{keys: map[string]*SigningKey{sk.Kid: sk}, active: sk.Kid}
	km.rebuildJWKS()
	return km, nil
}

// Close releases resources held by signers (e.g. PKCS#11 sessions).
func (km *KeyManager) Close() error {
	km.mu.RLock()
	defer km.mu.RUnlock()
	var first error
	for _, sk := range km.keys {
		if c, ok := sk.Signer.(interface{ Close() error }); ok {
			if err := c.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

// joseKey returns the key value to hand to jose.NewSigner: software keys go
// through directly, any other crypto.Signer (HSM) is wrapped in an
// OpaqueSigner.
func (sk *SigningKey) joseKey() interface{} {
	switch sk.Signer.(type) {
	case *ecdsa.PrivateKey, ed25519.PrivateKey:
		return sk.Signer
	}
	return &opaqueSigner{signer: sk.Signer, alg: sk.Algorithm, kid: sk.Kid}
}

// opaqueSigner adapts a crypto.Signer to jose.OpaqueSigner.
type opaqueSigner struct {
	signer crypto.Signer
	alg    jose.SignatureAlgorithm
	kid    string
}

func (o *opaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: o.signer.Public(), KeyID: o.kid, Algorithm: string(o.alg), Use: "sig"}
}

func (o *opaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{o.alg}
}

// SignPayload signs payload and returns the JWS signature encoding (raw r||s
// for ECDSA). The result is verified against the public key before it is
// returned, so a misbehaving token can never yield an unverifiable JWT.
func (o *opaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != o.alg {
		return nil, fmt.Errorf("as: signer supports %s, not %s", o.alg, alg)
	}
	switch pub := o.signer.Public().(type) {
	case *ecdsa.PublicKey:
		var h crypto.Hash
		if alg == jose.ES384 {
			h = crypto.SHA384
		} else {
			h = crypto.SHA256
		}
		hh := h.New()
		hh.Write(payload)
		digest := hh.Sum(nil)
		sig, err := o.signer.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, err
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		raw, err := ecdsaSigToRaw(sig, size)
		if err != nil {
			return nil, err
		}
		if !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(raw[:size]), new(big.Int).SetBytes(raw[size:])) {
			return nil, fmt.Errorf("as: signer produced an invalid signature")
		}
		return raw, nil
	case ed25519.PublicKey:
		sig, err := o.signer.Sign(rand.Reader, payload, crypto.Hash(0))
		if err != nil {
			return nil, err
		}
		if !ed25519.Verify(pub, payload, sig) {
			return nil, fmt.Errorf("as: signer produced an invalid signature")
		}
		return sig, nil
	}
	return nil, fmt.Errorf("as: unsupported public key type %T", o.signer.Public())
}

// ecdsaSigToRaw converts an ASN.1 DER ECDSA signature (what crypto.Signer
// returns) to fixed-width r||s, left-padding r and s to size bytes. The input is
// always parsed as DER and anything that is not exactly one valid DER
// SEQUENCE of two positive INTEGERs is rejected: a raw r||s of length 2*size is
// NOT accepted, because a valid DER signature can also be exactly 2*size bytes
// (e.g. two 29-byte components for P-256) and the two cannot be told apart by
// length.
func ecdsaSigToRaw(sig []byte, size int) ([]byte, error) {
	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return nil, fmt.Errorf("as: malformed ECDSA signature from signer (expected ASN.1 DER)")
	}
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || parsed.R.BitLen() > size*8 || parsed.S.BitLen() > size*8 {
		return nil, fmt.Errorf("as: ECDSA signature component out of range")
	}
	raw := make([]byte, 2*size)
	parsed.R.FillBytes(raw[:size])
	parsed.S.FillBytes(raw[size:])
	return raw, nil
}
