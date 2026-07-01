package as

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeKeyPEM(t *testing.T, dir, filename string, key interface{}, blockType string) string {
	t.Helper()
	var der []byte
	var err error

	switch blockType {
	case "EC PRIVATE KEY":
		der, err = x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	case "PRIVATE KEY":
		der, err = x509.MarshalPKCS8PrivateKey(key)
	default:
		t.Fatalf("unknown block type %q", blockType)
	}
	require.NoError(t, err)

	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	err = pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
	require.NoError(t, err)
	return path
}

func TestNewKeyManager_ECDSA_P256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec.pem", key, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	sk := km.ActiveKey()
	require.NotNil(t, sk)
	assert.Equal(t, jose.ES256, sk.Algorithm)
	assert.NotEmpty(t, sk.Kid)
	assert.NotNil(t, sk.Signer)
	assert.NotNil(t, sk.PublicKey)
}

func TestNewKeyManager_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ed.pem", priv, "PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	sk := km.ActiveKey()
	require.NotNil(t, sk)
	assert.Equal(t, jose.EdDSA, sk.Algorithm)
	assert.NotEmpty(t, sk.Kid)
}

func TestNewKeyManager_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec384.pem", key, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	sk := km.ActiveKey()
	require.NotNil(t, sk)
	assert.Equal(t, jose.ES384, sk.Algorithm)
}

func TestNewKeyManager_InvalidFile(t *testing.T) {
	_, err := NewKeyManager("/nonexistent/path.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read key file")
}

func TestNewKeyManager_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	err := os.WriteFile(path, []byte("not a pem file"), 0600)
	require.NoError(t, err)

	_, err = NewKeyManager(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PEM block")
}

func TestKeyManager_JWKS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec.pem", key, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	jwks := km.JWKS()
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, km.ActiveKey().Kid, jwks.Keys[0].KeyID)
	assert.Equal(t, "sig", jwks.Keys[0].Use)
	assert.Equal(t, string(jose.ES256), jwks.Keys[0].Algorithm)
}

func TestKeyManager_AddKey(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec.pem", key1, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	originalKid := km.ActiveKey().Kid

	// Add a second key without activating
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sk2, err := newSigningKey(key2)
	require.NoError(t, err)

	km.AddKey(sk2, false)

	// Active key unchanged
	assert.Equal(t, originalKid, km.ActiveKey().Kid)
	// JWKS has both keys
	assert.Len(t, km.JWKS().Keys, 2)
}

func TestKeyManager_AddKey_Activate(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec.pem", key1, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sk2, err := newSigningKey(key2)
	require.NoError(t, err)

	km.AddKey(sk2, true)

	// Active key changed
	assert.Equal(t, sk2.Kid, km.ActiveKey().Kid)
}

func TestKeyManager_RemoveKey(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	dir := t.TempDir()
	path := writeKeyPEM(t, dir, "ec.pem", key1, "EC PRIVATE KEY")

	km, err := NewKeyManager(path)
	require.NoError(t, err)

	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sk2, err := newSigningKey(key2)
	require.NoError(t, err)

	km.AddKey(sk2, false)
	require.Len(t, km.JWKS().Keys, 2)

	// Remove non-active key
	err = km.RemoveKey(sk2.Kid)
	require.NoError(t, err)
	assert.Len(t, km.JWKS().Keys, 1)

	// Cannot remove active key
	err = km.RemoveKey(km.ActiveKey().Kid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot remove active key")
}
