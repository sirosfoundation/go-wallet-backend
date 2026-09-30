package as

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
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
			assert.IsType(t, &opaqueSigner{}, sk.joseKey())
			issueAndVerify(t, km)
			require.Len(t, km.JWKS().Keys, 1)
			assert.NoError(t, km.Close())
			assert.True(t, h.closed)
		})
	}
}

func TestSigningKey_JoseKeyNativePassThrough(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sk, err := newSigningKey(k)
	require.NoError(t, err)
	assert.Same(t, k, sk.joseKey())
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
	_, err = newSigningKey(&signing.PKCS11Signer{}) // stub build: nil public key
	if err == nil {
		t.Skip("built with pkcs11 tag")
	}
	_, err = NewKeyManagerFromSigner(rk)
	assert.Error(t, err)
	_, err = newSigningKey(&fakeHSM{inner: &fakeShortEd{}})
	assert.ErrorContains(t, err, "length")
}

type fakeShortEd struct{}

func (fakeShortEd) Public() crypto.PublicKey { return ed25519.PublicKey{1, 2} }
func (fakeShortEd) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("x")
}

func TestOpaqueSigner_FailClosed(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	km, h := newFakeKM(t, k)
	ti := NewTokenIssuer(km, "iss", func(string) time.Duration { return time.Minute })

	h.err = errors.New("hsm down")
	_, err := ti.Issue("s", "a", "t", "r", "")
	assert.Error(t, err)

	h.err = nil
	h.mutate = func(sig []byte) []byte { // valid DER, wrong signature
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		bad, _ := other.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
		return bad
	}
	_, err = ti.Issue("s", "a", "t", "r", "")
	assert.ErrorContains(t, err, "invalid signature")

	h.mutate = func([]byte) []byte { return []byte{1, 2, 3} }
	_, err = ti.Issue("s", "a", "t", "r", "")
	assert.ErrorContains(t, err, "malformed")

	o := &opaqueSigner{signer: h, alg: jose.ES256}
	_, err = o.SignPayload([]byte("x"), jose.ES384)
	assert.Error(t, err)
	assert.Equal(t, []jose.SignatureAlgorithm{jose.ES256}, o.Algs())
}

func TestEcdsaSigToRaw(t *testing.T) {
	type rs struct{ R, S *big.Int }
	mk := func(rb, sb int, rTop, sTop byte) []byte {
		r := make([]byte, rb)
		s := make([]byte, sb)
		for i := range r {
			r[i] = 0x11
		}
		for i := range s {
			s[i] = 0x22
		}
		r[0], s[0] = rTop, sTop
		der, err := asn1.Marshal(rs{new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)})
		require.NoError(t, err)
		return der
	}

	// Every byte-length edge: short components (leading zeros stripped by DER),
	// full-width, high bit set (DER adds a 0x00 pad byte).
	for _, tc := range []struct {
		name         string
		rb, sb       int
		rTop, sTop   byte
		wantDERLen64 bool
	}{
		{"full width, high bits clear", 32, 32, 0x11, 0x22, false},
		{"full width, high bit set", 32, 32, 0xF1, 0xE2, false},
		{"r short", 20, 32, 0x11, 0x22, false},
		{"s short", 32, 1, 0x11, 0x02, false},
		{"both 29 bytes: DER is exactly 2*size", 29, 29, 0x11, 0x22, true},
		{"both 1 byte", 1, 1, 0x05, 0x07, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der := mk(tc.rb, tc.sb, tc.rTop, tc.sTop)
			if tc.wantDERLen64 {
				require.Equal(t, 64, len(der), "test vector must hit the ambiguous length")
			}
			raw, err := ecdsaSigToRaw(der, 32)
			require.NoError(t, err)
			require.Len(t, raw, 64)
			var p rs
			_, err = asn1.Unmarshal(der, &p)
			require.NoError(t, err)
			assert.Equal(t, 0, new(big.Int).SetBytes(raw[:32]).Cmp(p.R))
			assert.Equal(t, 0, new(big.Int).SetBytes(raw[32:]).Cmp(p.S))
		})
	}

	// A raw 64-byte r||s is not DER and must be rejected, not passed through.
	_, err := ecdsaSigToRaw(bytes.Repeat([]byte{0x11}, 64), 32)
	assert.Error(t, err)

	der, _ := asn1.Marshal(rs{big.NewInt(0), big.NewInt(1)})
	_, err = ecdsaSigToRaw(der, 32)
	assert.Error(t, err)
	der, _ = asn1.Marshal(rs{new(big.Int).Lsh(big.NewInt(1), 300), big.NewInt(1)})
	_, err = ecdsaSigToRaw(der, 32)
	assert.Error(t, err)
	der, _ = asn1.Marshal(rs{big.NewInt(5), big.NewInt(7)})
	_, err = ecdsaSigToRaw(append(der, 0), 32)
	assert.Error(t, err, "trailing bytes")
	_, err = ecdsaSigToRaw(nil, 32)
	assert.Error(t, err)
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
