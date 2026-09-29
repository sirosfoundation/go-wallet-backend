package as

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/signing"
)

// A failure after the key manager is built (here: unreadable rules dir) must
// release the HSM sessions, so a retried init cannot leak them.
func TestNewASModule_ClosesHSMOnLaterFailure(t *testing.T) {
	orig := newPKCS11Signer
	defer func() { newPKCS11Signer = orig }()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := &fakeHSM{inner: k}
	newPKCS11Signer = func(*signing.PKCS11Config) (crypto.Signer, error) { return h, nil }

	cfg := &config.ASConfig{
		SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "m", KeyLabel: "l", PIN: "1"},
		SessionStore:     "memory",
		RulesDir:         t.TempDir() + "/does-not-exist",
	}
	m, err := NewASModule(context.Background(), cfg, &config.JWTConfig{Secret: "0123456789abcdef0123456789abcdef", Issuer: "i"},
		nil, nil, nil, nil, zap.NewNop())
	require.Error(t, err)
	assert.Nil(t, m)
	assert.True(t, h.closed, "HSM signer must be closed when NewASModule fails")
}

func TestNewASModule_SessionStoreFailureClosesHSM(t *testing.T) {
	orig := newPKCS11Signer
	defer func() { newPKCS11Signer = orig }()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := &fakeHSM{inner: k}
	newPKCS11Signer = func(*signing.PKCS11Config) (crypto.Signer, error) { return h, nil }
	cfg := &config.ASConfig{
		SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "m", KeyLabel: "l", PIN: "1"},
		SessionStore:     "bogus",
	}
	_, err := NewASModule(context.Background(), cfg, &config.JWTConfig{Issuer: "i"}, nil, nil, nil, nil, zap.NewNop())
	require.Error(t, err)
	assert.True(t, h.closed)
}
