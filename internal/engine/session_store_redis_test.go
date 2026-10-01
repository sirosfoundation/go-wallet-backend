package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

// seedLegacySession writes a session exactly as the previous release did: the
// session key, an unescaped `user:<userID>` pointer and a raw-tenant set; no
// tenant-scoped pointer and no userall index.
func seedLegacySession(t *testing.T, store *RedisSessionStore, s *SessionData, ttl time.Duration) {
	t.Helper()
	ctx := context.Background()
	data, err := json.Marshal(s)
	require.NoError(t, err)
	require.NoError(t, store.client.Set(ctx, store.sessionKey(s.ID), data, ttl).Err())
	require.NoError(t, store.client.Set(ctx, store.legacyUserKey(s.UserID), s.ID, ttl).Err())
	require.NoError(t, store.client.SAdd(ctx, store.legacyTenantKey(s.TenantID), s.ID).Err())
}

func TestRedisSessionStore_LegacyGetByUserFallsBackAndBackfills(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	seedLegacySession(t, store, redisSess("old", "t1", "u1", time.Hour), time.Hour)

	got, err := store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "old", got.ID)

	// Backfilled: new pointer and index exist and now carry the TTL.
	assert.True(t, mr.Exists(store.userKey("t1", "u1")))
	members, err := mr.ZMembers(store.userSetKey("u1"))
	require.NoError(t, err)
	assert.Equal(t, []string{"old"}, members)

	// Works without the legacy pointer afterwards.
	mr.Del(store.legacyUserKey("u1"))
	got, err = store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "old", got.ID)
}

func TestRedisSessionStore_LegacyPointerOtherTenantNotReturned(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	seedLegacySession(t, store, redisSess("old", "t1", "u1", time.Hour), time.Hour)

	_, err := store.GetByUser(ctx, "t2", "u1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	assert.False(t, mr.Exists(store.userKey("t2", "u1")), "must not backfill for another tenant")
	assert.False(t, mr.Exists(store.userSetKey("u1")))
}

func TestRedisSessionStore_LegacyEmptyTenantNormalised(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()
	seedLegacySession(t, store, redisSess("old", "", "u1", time.Hour), time.Hour)

	got, err := store.GetByUser(ctx, normalizeTenant(""), "u1")
	require.NoError(t, err)
	assert.Equal(t, "old", got.ID)
}

func TestRedisSessionStore_LegacyDeleteByUser(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	seedLegacySession(t, store, redisSess("old", "t1", "u1", time.Hour), time.Hour)
	require.NoError(t, store.Put(ctx, redisSess("new", "t2", "u1", time.Hour)))
	seedLegacySession(t, store, redisSess("other", "t1", "u2", time.Hour), time.Hour)

	require.NoError(t, store.DeleteByUser(ctx, "u1"))

	assert.False(t, mr.Exists(store.sessionKey("old")))
	assert.False(t, mr.Exists(store.sessionKey("new")))
	assert.False(t, mr.Exists(store.legacyUserKey("u1")))
	assert.False(t, mr.Exists(store.userKey("t2", "u1")))
	members, _ := mr.SMembers(store.legacyTenantKey("t1"))
	assert.Equal(t, []string{"other"}, members)
	assert.True(t, mr.Exists(store.sessionKey("other")), "other users untouched")
}

func TestRedisSessionStore_LegacyDeleteRemovesLegacyPointer(t *testing.T) {
	store, mr := newTestRedisStore(t)
	seedLegacySession(t, store, redisSess("old", "t1", "u1", time.Hour), time.Hour)

	require.NoError(t, store.Delete(context.Background(), "old"))
	assert.False(t, mr.Exists(store.legacyUserKey("u1")))
	assert.False(t, mr.Exists(store.sessionKey("old")))
}

func TestRedisSessionStore_LegacyDeleteKeepsLegacyPointerToOtherSession(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	seedLegacySession(t, store, redisSess("old", "t1", "u1", time.Hour), time.Hour)
	require.NoError(t, store.Put(ctx, redisSess("new", "t2", "u1", time.Hour)))

	require.NoError(t, store.Delete(ctx, "new"))
	assert.True(t, mr.Exists(store.legacyUserKey("u1")))
}

func TestRedisSessionStore_LegacyPointerExpires(t *testing.T) {
	store, mr := newTestRedisStore(t)
	seedLegacySession(t, store, redisSess("old", "t1", "u1", time.Hour), time.Hour)

	advanceRedis(mr, 2*time.Hour)
	_, err := store.GetByUser(context.Background(), "t1", "u1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	require.NoError(t, store.DeleteByUser(context.Background(), "u1"))
}

// A replica that Puts a newer session between GetByUser's pointer miss and
// the legacy backfill must keep its pointer: the backfill is SET NX.
func TestRedisSessionStore_LegacyBackfillDoesNotOverwriteNewerPointer(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	seedLegacySession(t, store, redisSess("old", "t1", "u1", time.Hour), time.Hour)

	// The interleaving: the pointer miss has happened; now another replica
	// Puts a newer session before the legacy path runs its backfill.
	require.NoError(t, store.Put(ctx, redisSess("new", "t1", "u1", time.Hour)))
	got, err := store.getByLegacyUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "old", got.ID, "legacy path returns the session it read")

	ptr, err := mr.Get(store.userKey("t1", "u1"))
	require.NoError(t, err)
	assert.Equal(t, "new", ptr, "newer pointer must survive the backfill")
	cur, err := store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "new", cur.ID)

	// Memberships were still added, so DeleteByUser finds both.
	members, err := mr.ZMembers(store.userSetKey("u1"))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"old", "new"}, members)
}

func TestRedisSessionStore_DeleteByUserRemovesEverythingInBatches(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	n := deleteBatchSize*2 + 7 // several batches
	for i := 0; i < n; i++ {
		require.NoError(t, store.Put(ctx, redisSess(fmt.Sprintf("s%d", i), fmt.Sprintf("t%d", i%3), "u1", time.Hour)))
	}
	require.NoError(t, store.Put(ctx, redisSess("keep", "t0", "u2", time.Hour)))

	require.NoError(t, store.DeleteByUser(ctx, "u1"))

	for i := 0; i < n; i++ {
		assert.False(t, mr.Exists(store.sessionKey(fmt.Sprintf("s%d", i))))
	}
	assert.False(t, mr.Exists(store.userSetKey("u1")))
	for i := 0; i < 3; i++ {
		assert.False(t, mr.Exists(store.userKey(fmt.Sprintf("t%d", i), "u1")))
	}
	assert.True(t, mr.Exists(store.sessionKey("keep")))
	assert.True(t, mr.Exists(store.userKey("t0", "u2")))
}

// A session Put between two DeleteByUser rounds is either removed by a later
// round of the same call, or (if it lands after the final empty check) stays
// indexed so a later DeleteByUser finds it.
func TestRedisSessionStore_PutDuringDeleteByUserStaysDiscoverable(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	for i := 0; i < deleteBatchSize+5; i++ {
		require.NoError(t, store.Put(ctx, redisSess(fmt.Sprintf("s%d", i), "t1", "u1", time.Hour)))
	}

	// Round 1: a Put lands between batches; the same call must pick it up.
	puts := 0
	store.betweenDeleteBatches = func() {
		if puts == 0 {
			puts++
			require.NoError(t, store.Put(ctx, redisSess("mid", "t2", "u1", time.Hour)))
		}
	}
	require.NoError(t, store.DeleteByUser(ctx, "u1"))
	assert.False(t, mr.Exists(store.sessionKey("mid")), "mid-call Put seen by a later round")
	assert.False(t, mr.Exists(store.userSetKey("u1")))

	// A Put after the final empty check creates a fresh set that indexes it.
	store.betweenDeleteBatches = nil
	require.NoError(t, store.Put(ctx, redisSess("late", "t2", "u1", time.Hour)))
	members, err := mr.ZMembers(store.userSetKey("u1"))
	require.NoError(t, err)
	assert.Equal(t, []string{"late"}, members)
	require.NoError(t, store.DeleteByUser(ctx, "u1"))
	assert.False(t, mr.Exists(store.sessionKey("late")))
	assert.False(t, mr.Exists(store.userKey("t2", "u1")))
}

// The set must not be deleted while a member exists.
func TestRedisSessionStore_DeleteUserSetIfEmptyKeepsNonEmptySet(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	require.NoError(t, store.Put(ctx, redisSess("s1", "t1", "u1", time.Hour)))
	done, err := deleteUserSetIfEmptyScript.Run(ctx, store.client, []string{store.userSetKey("u1")}).Int()
	require.NoError(t, err)
	assert.Equal(t, 0, done)
	assert.True(t, mr.Exists(store.userSetKey("u1")))
}

// Stress: Puts race DeleteByUser. Whatever interleaving happens, no session
// key may exist that is not a member of its user's set (every live session
// stays discoverable), and a final DeleteByUser leaves nothing.
func TestRedisSessionStore_ConcurrentPutDeleteByUserNoOrphans(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				_ = store.Put(ctx, redisSess(fmt.Sprintf("s-%d-%d", g, i), fmt.Sprintf("t%d", i%2), "u1", time.Hour))
			}
		}(g)
	}
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				assert.NoError(t, store.DeleteByUser(ctx, "u1"))
			}
		}()
	}
	wg.Wait()

	members := map[string]bool{}
	if mr.Exists(store.userSetKey("u1")) {
		ms, err := mr.ZMembers(store.userSetKey("u1"))
		require.NoError(t, err)
		for _, m := range ms {
			members[m] = true
		}
	}
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, "t:s-") {
			assert.True(t, members[strings.TrimPrefix(k, "t:")], "session %s exists but is not indexed", k)
		}
	}

	require.NoError(t, store.DeleteByUser(ctx, "u1"))
	for _, k := range mr.Keys() {
		assert.False(t, strings.HasPrefix(k, "t:s-"), "leftover %s", k)
	}
	assert.False(t, mr.Exists(store.userSetKey("u1")))
}

// The tenant-scoped pointer lives in a namespace disjoint from the legacy
// `user:<userID>` pointer and is injectively encoded: legacy user "default:u"
// and new (tenant "default", user "u") must never share a key or see each
// other's sessions, in either direction and across all operations.
func TestRedisSessionStore_LegacyAndScopedKeysDoNotCollide(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	assert.NotEqual(t, store.legacyUserKey("default:u"), store.userKey("default", "u"))

	// Legacy session of user "default:u" (tenant t1), written by an old replica.
	seedLegacySession(t, store, redisSess("legacy", "t1", "default:u", time.Hour), time.Hour)
	// New session for (default, u).
	require.NoError(t, store.Put(ctx, redisSess("fresh", "default", "u", time.Hour)))

	got, err := store.GetByUser(ctx, "default", "u")
	require.NoError(t, err)
	assert.Equal(t, "fresh", got.ID)
	got, err = store.GetByUser(ctx, "t1", "default:u")
	require.NoError(t, err)
	assert.Equal(t, "legacy", got.ID)

	// Deleting one never touches the other.
	require.NoError(t, store.Delete(ctx, "fresh"))
	got, err = store.GetByUser(ctx, "t1", "default:u")
	require.NoError(t, err)
	assert.Equal(t, "legacy", got.ID)

	require.NoError(t, store.Put(ctx, redisSess("fresh2", "default", "u", time.Hour)))
	require.NoError(t, store.DeleteByUser(ctx, "default:u"))
	_, err = store.Get(ctx, "legacy")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	got, err = store.GetByUser(ctx, "default", "u")
	require.NoError(t, err)
	assert.Equal(t, "fresh2", got.ID, "DeleteByUser(default:u) must not remove user u's session")

	require.NoError(t, store.DeleteByUser(ctx, "u"))
	_, err = store.GetByUser(ctx, "default", "u")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

// A legacy pointer that names another user's session (the old, ambiguous key
// scheme) is never returned, backfilled, or used to delete that session.
func TestRedisSessionStore_CollidingLegacyPointerNeverCrossesUsers(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()

	// Session of user "u" in tenant "default", but pointed at by the legacy
	// key of user "default:u"-style collisions: forge the pointer.
	require.NoError(t, store.Put(ctx, redisSess("victim", "default", "u", time.Hour)))
	require.NoError(t, store.client.Set(ctx, store.legacyUserKey("x"), "victim", time.Hour).Err())

	_, err := store.GetByUser(ctx, "default", "x")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	assert.False(t, mr.Exists(store.userKey("default", "x")), "no backfill for a foreign session")

	require.NoError(t, store.DeleteByUser(ctx, "x"))
	got, err := store.Get(ctx, "victim")
	require.NoError(t, err, "DeleteByUser(x) must not delete a legacy-pointed session of another user")
	assert.Equal(t, "u", got.UserID)
	got, err = store.GetByUser(ctx, "default", "u")
	require.NoError(t, err)
	assert.Equal(t, "victim", got.ID)
	assert.False(t, mr.Exists(store.legacyUserKey("x")), "the colliding legacy pointer itself is removed")
}

// IDs and tenants with ':' and other special characters stay isolated.
func TestRedisSessionStore_SpecialCharacterIDsAreIsolated(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()

	pairs := [][2]string{
		{"a", "b:c"}, {"a:b", "c"}, {"a:b:c", ""}, {"a", "b%3Ac"},
		{"a b", "c/d"}, {"a/b", "c d"}, {"", "x"}, {"default", "y"},
		{"t", "u:"}, {"t:", "u"}, {"%", "%25"}, {"é", "ü"},
	}
	keys := map[string]bool{}
	for i, p := range pairs {
		k := store.userKey(p[0], p[1])
		require.False(t, keys[k], "key collision for %q", p)
		keys[k] = true
		id := "s" + string(rune('A'+i))
		require.NoError(t, store.Put(ctx, redisSess(id, p[0], p[1], time.Hour)))
	}
	for i, p := range pairs {
		id := "s" + string(rune('A'+i))
		got, err := store.GetByUser(ctx, p[0], p[1])
		require.NoError(t, err, "%q", p)
		assert.Equal(t, id, got.ID, "%q", p)
	}

	// Delete one: all others remain.
	require.NoError(t, store.Delete(ctx, "sA"))
	for i, p := range pairs[1:] {
		got, err := store.GetByUser(ctx, p[0], p[1])
		require.NoError(t, err)
		assert.Equal(t, "s"+string(rune('A'+i+1)), got.ID)
	}
	// DeleteByUser removes only that user's sessions.
	require.NoError(t, store.DeleteByUser(ctx, "b:c"))
	_, err := store.GetByUser(ctx, "a", "b:c")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	_, err = store.GetByUser(ctx, "a:b", "c")
	assert.NoError(t, err)
}
