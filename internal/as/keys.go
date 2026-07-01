package as

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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

// newSigningKey creates a SigningKey from a crypto.Signer, auto-detecting the algorithm.
func newSigningKey(signer crypto.Signer) (*SigningKey, error) {
	var alg jose.SignatureAlgorithm
	var kid string

	switch k := signer.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			alg = jose.ES256
		case elliptic.P384():
			alg = jose.ES384
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
		// kid from public key thumbprint
		jwk := jose.JSONWebKey{Key: k.Public()}
		tp, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("failed to compute key thumbprint: %w", err)
		}
		kid = base64.RawURLEncoding.EncodeToString(tp)
	case ed25519.PrivateKey:
		alg = jose.EdDSA
		jwk := jose.JSONWebKey{Key: k.Public()}
		tp, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("failed to compute key thumbprint: %w", err)
		}
		kid = base64.RawURLEncoding.EncodeToString(tp)
	default:
		return nil, fmt.Errorf("unsupported key type %T", signer)
	}

	return &SigningKey{
		Kid:       kid,
		Signer:    signer,
		Algorithm: alg,
		PublicKey: signer.Public(),
	}, nil
}
