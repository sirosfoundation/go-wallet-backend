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

// advanceRedis moves both key TTLs and the server clock (Redis TIME, used by
// the user-set script) forward.
func advanceRedis(mr *miniredis.Miniredis, d time.Duration) {
	mr.SetTime(time.Now().Add(d))
	mr.FastForward(d)
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

func TestRedisSessionStore_UserSetHasTTLMatchingLongestSession(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	uset := store.userSetKey("u1")

	require.NoError(t, store.Put(ctx, redisSess("s1", "t1", "u1", 10*time.Minute)))
	require.NoError(t, store.Put(ctx, redisSess("s2", "t2", "u1", 30*time.Minute)))
	ttl := mr.TTL(uset)
	assert.InDelta(t, (30 * time.Minute).Seconds(), ttl.Seconds(), 5, "set TTL tracks longest-lived member")

	// A shorter session added later must not shorten the set's life.
	require.NoError(t, store.Put(ctx, redisSess("s3", "t3", "u1", time.Minute)))
	assert.InDelta(t, (30 * time.Minute).Seconds(), mr.TTL(uset).Seconds(), 5)

	// Once every session has expired the set disappears by itself.
	advanceRedis(mr, 31*time.Minute)
	assert.False(t, mr.Exists(uset))
}

func TestRedisSessionStore_PutPrunesExpiredMembers(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	uset := store.userSetKey("u1")

	require.NoError(t, store.Put(ctx, redisSess("short", "t1", "u1", time.Minute)))
	require.NoError(t, store.Put(ctx, redisSess("long", "t2", "u1", time.Hour)))
	// Simulate a process that died without Delete: the session key expires
	// by TTL, the set member remains.
	advanceRedis(mr, 2*time.Minute)
	members, err := mr.ZMembers(uset)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"short", "long"}, members)

	require.NoError(t, store.Put(ctx, redisSess("fresh", "t3", "u1", time.Hour)))
	members, err = mr.ZMembers(uset)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"long", "fresh"}, members, "expired member pruned on add")
}

func TestRedisSessionStore_DeleteByUserHandlesStaleMembers(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()

	require.NoError(t, store.Put(ctx, redisSess("gone", "t1", "u1", time.Minute)))
	require.NoError(t, store.Put(ctx, redisSess("live", "t2", "u1", time.Hour)))
	require.NoError(t, store.Put(ctx, redisSess("other", "t1", "u2", time.Hour)))
	advanceRedis(mr, 2*time.Minute)

	require.NoError(t, store.DeleteByUser(ctx, "u1"))
	_, err := store.Get(ctx, "live")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	assert.False(t, mr.Exists(store.userSetKey("u1")))
	assert.False(t, mr.Exists(store.userKey("t2", "u1")))
	// Another user is untouched.
	_, err = store.Get(ctx, "other")
	assert.NoError(t, err)
}

func TestRedisSessionStore_DeleteRemovesUserSetMember(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	require.NoError(t, store.Put(ctx, redisSess("s1", "t1", "u1", time.Hour)))
	require.NoError(t, store.Put(ctx, redisSess("s2", "t2", "u1", time.Hour)))
	require.NoError(t, store.Delete(ctx, "s1"))
	members, err := mr.ZMembers(store.userSetKey("u1"))
	require.NoError(t, err)
	assert.Equal(t, []string{"s2"}, members)
}

func TestRedisSessionStore_UpdateExtendsUserSetExpiry(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	s := redisSess("s1", "t1", "u1", 10*time.Minute)
	require.NoError(t, store.Put(ctx, s))
	s.ExpiresAt = time.Now().Add(2 * time.Hour)
	require.NoError(t, store.Update(ctx, s))
	assert.InDelta(t, (2 * time.Hour).Seconds(), mr.TTL(store.userSetKey("u1")).Seconds(), 5)
}
