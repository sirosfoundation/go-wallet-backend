package as

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"runtime"
	"strings"
	"testing"
	"time"

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

// sessionCleanupGoroutines counts goroutines parked in the memory session
// store's cleanup loop.
func sessionCleanupGoroutines() int {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	return strings.Count(string(buf), "created by github.com/sirosfoundation/go-wallet-backend/internal/as.(*MemorySessionStore).StartCleanup")
}

func waitCleanupGoroutines(t *testing.T, want int) {
	t.Helper()
	require.Eventually(t, func() bool { return sessionCleanupGoroutines() == want },
		2*time.Second, 10*time.Millisecond, "session cleanup goroutines")
}

func TestNewASModule_NoCleanupGoroutineLeak(t *testing.T) {
	base := sessionCleanupGoroutines()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	orig := newPKCS11Signer
	defer func() { newPKCS11Signer = orig }()
	newPKCS11Signer = func(*signing.PKCS11Config) (crypto.Signer, error) { return &fakeHSM{inner: k}, nil }
	jwtCfg := &config.JWTConfig{Secret: "0123456789abcdef0123456789abcdef", Issuer: "i"}
	mk := func(rules string) *config.ASConfig {
		return &config.ASConfig{
			SigningKeyPKCS11: &config.PKCS11SigningConfig{ModulePath: "m", KeyLabel: "l", PIN: "1"},
			SessionStore:     "memory",
			RulesDir:         rules,
		}
	}

	// Construction failure after the session store started.
	for i := 0; i < 3; i++ {
		_, err := NewASModule(context.Background(), mk(t.TempDir()+"/does-not-exist"), jwtCfg, nil, nil, nil, nil, zap.NewNop())
		require.Error(t, err)
	}
	waitCleanupGoroutines(t, base)

	// Normal shutdown.
	m, err := NewASModule(context.Background(), mk(""), jwtCfg, nil, nil, nil, nil, zap.NewNop())
	require.NoError(t, err)
	assert.Equal(t, base+1, sessionCleanupGoroutines())
	require.NoError(t, m.Close())
	waitCleanupGoroutines(t, base)
}
