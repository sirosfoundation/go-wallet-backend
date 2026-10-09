package as

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

// fakeHSM wraps a crypto.Signer so its concrete type is NOT *ecdsa.PrivateKey,
// like a PKCS#11 signer. It returns ASN.1 DER ECDSA signatures.
type fakeHSM struct {
	inner  crypto.Signer
	closed bool
	mutate func([]byte) []byte
	err    error
}

func (f *fakeHSM) Public() crypto.PublicKey { return f.inner.Public() }
func (f *fakeHSM) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	sig, err := f.inner.Sign(r, d, o)
	if err == nil && f.mutate != nil {
		sig = f.mutate(sig)
	}
	return sig, err
}
func (f *fakeHSM) Close() error { f.closed = true; return nil }

func newFakeKM(t *testing.T, inner crypto.Signer) (*KeyManager, *fakeHSM) {
	t.Helper()
	h := &fakeHSM{inner: inner}
	km, err := NewKeyManagerFromSigner(h)
	require.NoError(t, err)
	return km, h
}

func issueAndVerify(t *testing.T, km *KeyManager) {
	t.Helper()
	ti := NewTokenIssuer(km, "iss", func(string) time.Duration { return time.Minute })
	raw, err := ti.Issue("sub", "wallet-backend", "t1", "rw", "")
	require.NoError(t, err)
	claims, err := ti.ParseAndVerify(raw, []string{"wallet-backend"})
	require.NoError(t, err)
	assert.Equal(t, "sub", claims.Subject)
}

func TestKeyManagerFromSigner_HSMWrapped(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)

	for name, tc := range map[string]struct {
		s   crypto.Signer
		alg jose.SignatureAlgorithm
	}{"P256": {p256, jose.ES256}, "P384": {p384, jose.ES384}, "Ed25519": {ed, jose.EdDSA}} {
		t.Run(name, func(t *testing.T) {
			km, h := newFakeKM(t, tc.s)
			sk := km.ActiveKey()
			assert.Equal(t, tc.alg, sk.Algorithm)
			// kid is the same thumbprint a file key would get.
			ref, err := newSigningKey(tc.s)
			require.NoError(t, err)
			assert.Equal(t, ref.Kid, sk.Kid)
			issueAndVerify(t, km)
			require.Len(t, km.JWKS().Keys, 1)
			assert.NoError(t, km.Close())
			assert.True(t, h.closed)
		})
	}
}

func TestNewSigningKey_Rejects(t *testing.T) {
	_, err := newSigningKey(nil)
	assert.Error(t, err)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, err = newSigningKey(p521)
	assert.ErrorContains(t, err, "curve")
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err = newSigningKey(rk)
	assert.ErrorContains(t, err, "unsupported key type")
	_, err = newSigningKey(nilPublicSigner{}) // signer exposing no public key
	assert.Error(t, err)
	_, err = NewKeyManagerFromSigner(rk)
	assert.Error(t, err)
	_, err = newSigningKey(&fakeHSM{inner: &fakeShortEd{}})
	assert.ErrorContains(t, err, "length")
}

// nilPublicSigner is a test-local signer whose Public() is nil; it behaves the
// same in default and -tags pkcs11 builds (unlike signing.PKCS11Signer{}).
type nilPublicSigner struct{}

func (nilPublicSigner) Public() crypto.PublicKey { return nil }
func (nilPublicSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("x")
}

type fakeShortEd struct{}

func (fakeShortEd) Public() crypto.PublicKey { return ed25519.PublicKey{1, 2} }
func (fakeShortEd) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("x")
}

func TestIssue_SignerFailures(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	km, h := newFakeKM(t, k)
	ti := NewTokenIssuer(km, "iss", func(string) time.Duration { return time.Minute })

	h.err = errors.New("hsm down")
	_, err := ti.Issue("s", "a", "t", "r", "")
	assert.Error(t, err)

	// Signer output that is not ASN.1 DER is rejected by go-jose's adapter.
	h.err = nil
	h.mutate = func([]byte) []byte { return []byte{1, 2, 3} }
	_, err = ti.Issue("s", "a", "t", "r", "")
	assert.Error(t, err)
}

// A DER-signing signer's tokens verify with go-jose against the published
// JWKS, carry the kid and the expected alg, and are refused under another alg.
func TestIssue_HSMStyleTokensVerifyAgainstJWKS(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for name, tc := range map[string]struct {
		s     crypto.Signer
		alg   jose.SignatureAlgorithm
		other jose.SignatureAlgorithm
	}{
		"ES256": {p256, jose.ES256, jose.ES384},
		"ES384": {p384, jose.ES384, jose.ES256},
		"EdDSA": {ed, jose.EdDSA, jose.ES256},
	} {
		t.Run(name, func(t *testing.T) {
			km, _ := newFakeKM(t, tc.s)
			ti := NewTokenIssuer(km, "iss", func(string) time.Duration { return time.Minute })
			for i := 0; i < 64; i++ { // r/s of varying DER length
				raw, err := ti.Issue("sub", "aud", "t1", "rw", "")
				require.NoError(t, err)

				_, err = jose.ParseSigned(raw, []jose.SignatureAlgorithm{tc.other})
				assert.Error(t, err, "wrong alg must be refused")

				jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{tc.alg})
				require.NoError(t, err)
				assert.Equal(t, tc.alg, jose.SignatureAlgorithm(jws.Signatures[0].Header.Algorithm))
				assert.Equal(t, km.ActiveKey().Kid, jws.Signatures[0].Header.KeyID)
				set := km.JWKS()
				jwk := set.Key(jws.Signatures[0].Header.KeyID)
				require.Len(t, jwk, 1)
				_, err = jws.Verify(jwk[0].Key)
				require.NoError(t, err)
			}
		})
	}
}

func TestNewConfiguredKeyManager(t *testing.T) {
	// both configured
	_, err := newConfiguredKeyManager(&config.ASConfig{SigningKeyPath: "/x", SigningKeyPKCS11: &config.PKCS11SigningConfig{}})
	assert.ErrorContains(t, err, "mutually exclusive")

	orig := newPKCS11Signer
	defer func() { newPKCS11Signer = orig }()

	// HSM open fails -> refuse
	newPKCS11Signer = func(*signing.PKCS11Config) (crypto.Signer, error) { return nil, errors.New("no token") }
	_, err = newConfiguredKeyManager(&config.ASConfig{SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "m"}})
	assert.ErrorContains(t, err, "no token")

	// HSM key of unsupported type -> refuse and close
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	h := &fakeHSM{inner: rk}
	newPKCS11Signer = func(*signing.PKCS11Config) (crypto.Signer, error) { return h, nil }
	_, err = newConfiguredKeyManager(&config.ASConfig{SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "m"}})
	assert.Error(t, err)
	assert.True(t, h.closed)

	// Ed25519 via PKCS#11 -> refuse clearly and close (real backend cannot sign it)
	_, edk, _ := ed25519.GenerateKey(rand.Reader)
	he := &fakeHSM{inner: edk}
	newPKCS11Signer = func(*signing.PKCS11Config) (crypto.Signer, error) { return he, nil }
	_, err = newConfiguredKeyManager(&config.ASConfig{SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "m"}})
	assert.ErrorContains(t, err, "supports only ECDSA")
	assert.ErrorContains(t, err, "Ed25519")
	assert.True(t, he.closed)

	// P-384 via PKCS#11 works
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	newPKCS11Signer = func(*signing.PKCS11Config) (crypto.Signer, error) { return &fakeHSM{inner: k384}, nil }
	km384, err := newConfiguredKeyManager(&config.ASConfig{SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "m"}})
	require.NoError(t, err)
	issueAndVerify(t, km384)

	// success, config passed through
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var got *signing.PKCS11Config
	newPKCS11Signer = func(c *signing.PKCS11Config) (crypto.Signer, error) { got = c; return &fakeHSM{inner: k}, nil }
	km, err := newConfiguredKeyManager(&config.ASConfig{SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "m", SlotID: 2, PIN: "p", KeyLabel: "l", PoolSize: 3}})
	require.NoError(t, err)
	assert.Equal(t, &signing.PKCS11Config{ModulePath: "m", SlotID: 2, PIN: "p", KeyLabel: "l", PoolSize: 3}, got)
	issueAndVerify(t, km)
	assert.NoError(t, (&ASModule{KeyManager: km}).Close())
	var nilm *ASModule
	assert.NoError(t, nilm.Close())
}

func TestNewConfiguredKeyManager_PINFile(t *testing.T) {
	orig := newPKCS11Signer
	defer func() { newPKCS11Signer = orig }()
	called := false
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var got *signing.PKCS11Config
	newPKCS11Signer = func(c *signing.PKCS11Config) (crypto.Signer, error) {
		called = true
		got = c
		return &fakeHSM{inner: k}, nil
	}

	// Missing PIN file: clear error, HSM never opened, path not leaked.
	dir := t.TempDir()
	_, err := newConfiguredKeyManager(&config.ASConfig{SigningKeyPKCS11: &config.PKCS11SigningConfig{
		ModulePath: "m", KeyLabel: "l", PINPath: filepath.Join(dir, "no-such-pin-file")}})
	require.Error(t, err)
	assert.ErrorContains(t, err, "pin_path")
	assert.NotContains(t, err.Error(), "no-such-pin-file")
	assert.False(t, called)

	// Present PIN file is read lazily and passed to the signer.
	pinFile := filepath.Join(dir, "pin")
	require.NoError(t, os.WriteFile(pinFile, []byte("4321\n"), 0o600))
	km, err := newConfiguredKeyManager(&config.ASConfig{SigningKeyPKCS11: &config.PKCS11SigningConfig{
		ModulePath: "m", KeyLabel: "l", PINPath: pinFile}})
	require.NoError(t, err)
	assert.Equal(t, "4321", got.PIN)
	assert.NoError(t, (&ASModule{KeyManager: km}).Close())
}
