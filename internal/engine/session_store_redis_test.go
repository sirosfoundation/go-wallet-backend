package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestRedisStore(t *testing.T) (*RedisSessionStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	store, err := NewRedisSessionStore(&RedisSessionConfig{
		Address:    mr.Addr(),
		KeyPrefix:  "t:",
		DefaultTTL: time.Hour,
	}, zap.NewNop())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store, mr
}

func redisSess(id, tenant, user string, ttl time.Duration) *SessionData {
	return &SessionData{ID: id, TenantID: tenant, UserID: user, ExpiresAt: time.Now().Add(ttl)}
}

func TestRedisSessionStore_PutGetByUserDelete(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	require.NoError(t, store.Put(ctx, redisSess("s1", "t1", "u1", time.Hour)))
	got, err := store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "s1", got.ID)
	_, err = store.GetByUser(ctx, "t2", "u1")
	assert.ErrorIs(t, err, ErrSessionNotFound)

	require.NoError(t, store.Delete(ctx, "s1"))
	_, err = store.GetByUser(ctx, "t1", "u1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

// Deleting a superseded session must not remove the pointer to its
// replacement.
func TestRedisSessionStore_DeleteKeepsReplacementPointer(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	require.NoError(t, store.Put(ctx, redisSess("old", "t1", "u1", time.Hour)))
	require.NoError(t, store.Put(ctx, redisSess("new", "t1", "u1", time.Hour)))
	require.NoError(t, store.Delete(ctx, "old"))

	got, err := store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "new", got.ID)
}

// cmdRecorder records every command that references a given key.
type cmdRecorder struct {
	mu   sync.Mutex
	key  string
	cmds []string
}

func (h *cmdRecorder) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *cmdRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, c := range cmds {
			h.record(c)
		}
		return next(ctx, cmds)
	}
}
func (h *cmdRecorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.record(cmd)
		return next(ctx, cmd)
	}
}
func (h *cmdRecorder) record(c redis.Cmder) {
	for _, a := range c.Args() {
		if s, ok := a.(string); ok && s == h.key {
			h.mu.Lock()
			h.cmds = append(h.cmds, c.Name())
			h.mu.Unlock()
			return
		}
	}
}

// The pointer compare-and-delete must be a single atomic Redis operation. A
// separate GET followed by DEL leaves a window in which another replica can
// repoint the key to a live replacement that the DEL then removes. That
// interleaving cannot be forced deterministically against miniredis, so this
// asserts the structural property instead: the only commands that touch the
// pointer during Delete are the script (eval/evalsha), never a bare GET/DEL.
func TestRedisSessionStore_DeletePointerUsesSingleAtomicScript(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()
	require.NoError(t, store.Put(ctx, redisSess("s1", "t1", "u1", time.Hour)))

	rec := &cmdRecorder{key: store.userKey("t1", "u1")}
	store.client.AddHook(rec)
	require.NoError(t, store.Delete(ctx, "s1"))

	require.NotEmpty(t, rec.cmds)
	for _, c := range rec.cmds {
		assert.Contains(t, []string{"evalsha", "eval"}, c, "pointer touched by non-atomic command")
	}
}

func TestRedisSessionStore_DeleteRemovesOwnPointer(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	require.NoError(t, store.Put(ctx, redisSess("s1", "t1", "u1", time.Hour)))
	require.NoError(t, store.Delete(ctx, "s1"))
	assert.False(t, mr.Exists(store.userKey("t1", "u1")))
}
