package as

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// The in-memory storage backend has no MongoDB database, so session storage
// falls back to memory unless "mongodb" is demanded, which is then an error.
func TestNewSessionStore_SelectionWithoutMongo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := memory.NewStore()

	for _, mode := range []string{"", "auto", "memory"} {
		s, err := newSessionStore(ctx, &config.ASConfig{SessionStore: mode}, store, zap.NewNop())
		require.NoError(t, err, mode)
		assert.IsType(t, &MemorySessionStore{}, s, mode)
	}

	_, err := newSessionStore(ctx, &config.ASConfig{SessionStore: "mongodb"}, store, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires the MongoDB storage backend")

	_, err = newSessionStore(ctx, &config.ASConfig{SessionStore: "redis"}, store, zap.NewNop())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown value")
}

func TestMemorySessionStore_DeleteByUser(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	require.NoError(t, store.Create(ctx, testSession("a1", "alice")))
	require.NoError(t, store.Create(ctx, testSession("a2", "alice")))
	require.NoError(t, store.Create(ctx, testSession("b1", "bob")))

	require.NoError(t, store.DeleteByUser(ctx, "alice"))

	a1, _ := store.Get(ctx, "a1")
	a2, _ := store.Get(ctx, "a2")
	b1, _ := store.Get(ctx, "b1")
	assert.True(t, a1.Revoked)
	assert.True(t, a2.Revoked)
	assert.True(t, b1.IsValid())
}

func TestHashSessionID(t *testing.T) {
	jti, err := GenerateSessionID()
	require.NoError(t, err)
	h := HashSessionID(jti)
	assert.NotEqual(t, jti, h)
	assert.Equal(t, h, HashSessionID(jti), "deterministic")
	assert.Len(t, h, 43, "base64url SHA-256 without padding")
}
