package engine

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// faultHook lets a test observe or fail individual single commands.
type faultHook struct {
	fn func(cmd redis.Cmder) error
}

func (h *faultHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *faultHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *faultHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if err := h.fn(cmd); err != nil {
			cmd.SetErr(err)
			return err
		}
		return next(ctx, cmd)
	}
}

func cmdMentions(cmd redis.Cmder, s string) bool {
	for _, a := range cmd.Args() {
		if v, ok := a.(string); ok && v == s {
			return true
		}
	}
	return false
}

func isEval(cmd redis.Cmder) bool {
	n := cmd.Name()
	return n == "eval" || n == "evalsha"
}

var errInjected = errors.New("injected redis failure")

func sessAt(id, tenant, user string, created time.Time) *SessionData {
	s := redisSess(id, tenant, user, time.Hour)
	s.CreatedAt = created
	return s
}

// putScoped stores s through Put (scoped pointer and indexes); putLegacyOnly
// stores it as an old replica would (legacy pointer, no scoped pointer).
func putScoped(t *testing.T, store *RedisSessionStore, s *SessionData) {
	t.Helper()
	require.NoError(t, store.Put(context.Background(), s))
}

func scopedPointer(t *testing.T, store *RedisSessionStore, tenant, user string) string {
	t.Helper()
	v, err := store.client.Get(context.Background(), store.userKey(tenant, user)).Result()
	if err == redis.Nil {
		return ""
	}
	require.NoError(t, err)
	return v
}

func TestRedisGetByUser_LegacyNewerWinsAndRepointsScoped(t *testing.T) {
	store, _ := newTestRedisStore(t)
	now := time.Now()
	putScoped(t, store, sessAt("scoped", "t1", "u1", now.Add(-time.Hour)))
	seedLegacySession(t, store, sessAt("legacy", "t1", "u1", now), time.Hour)

	got, err := store.GetByUser(context.Background(), "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "legacy", got.ID)
	assert.Equal(t, "legacy", scopedPointer(t, store, "t1", "u1"), "scoped pointer repaired to the newer session")
}

func TestRedisGetByUser_ScopedNewerWins(t *testing.T) {
	store, _ := newTestRedisStore(t)
	now := time.Now()
	putScoped(t, store, sessAt("scoped", "t1", "u1", now))
	seedLegacySession(t, store, sessAt("legacy", "t1", "u1", now.Add(-time.Hour)), time.Hour)

	got, err := store.GetByUser(context.Background(), "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "scoped", got.ID)
	assert.Equal(t, "scoped", scopedPointer(t, store, "t1", "u1"))
}

func TestRedisGetByUser_EqualCreatedAtKeepsScoped(t *testing.T) {
	store, _ := newTestRedisStore(t)
	at := time.Now().Add(-time.Minute)
	putScoped(t, store, sessAt("scoped", "t1", "u1", at))
	seedLegacySession(t, store, sessAt("legacy", "t1", "u1", at), time.Hour)

	got, err := store.GetByUser(context.Background(), "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "scoped", got.ID, "a tie never repoints the scoped pointer")
	assert.Equal(t, "scoped", scopedPointer(t, store, "t1", "u1"))
}

func TestRedisGetByUser_DeadLegacyPointerKeepsScoped(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	putScoped(t, store, sessAt("scoped", "t1", "u1", time.Now().Add(-time.Hour)))

	// Legacy pointer to a record that does not exist.
	require.NoError(t, store.client.Set(ctx, store.legacyUserKey("u1"), "ghost", time.Hour).Err())
	got, err := store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "scoped", got.ID)

	// Legacy pointer to a record past its ExpiresAt that is still stored.
	expired := redisSess("expired", "t1", "u1", -time.Minute)
	seedLegacySession(t, store, expired, time.Hour)
	got, err = store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "scoped", got.ID)
	assert.Equal(t, "scoped", scopedPointer(t, store, "t1", "u1"))
	_ = mr
}

// A legacy session whose record is already past its lifetime must not be
// swapped in even though it is newer.
func TestRedisGetByUser_NewerButExpiredLegacyNotSwappedIn(t *testing.T) {
	store, _ := newTestRedisStore(t)
	putScoped(t, store, sessAt("scoped", "t1", "u1", time.Now().Add(-time.Hour)))
	expired := redisSess("expired", "t1", "u1", -time.Minute)
	expired.CreatedAt = time.Now()
	seedLegacySession(t, store, expired, time.Hour)

	got, err := store.GetByUser(context.Background(), "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "scoped", got.ID)
}

func TestRedisGetByUser_DanglingScopedPointerFallsBackToLegacy(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	putScoped(t, store, sessAt("scoped", "t1", "u1", time.Now().Add(-time.Hour)))
	mr.Del(store.sessionKey("scoped")) // record gone, pointer dangling
	seedLegacySession(t, store, sessAt("legacy", "t1", "u1", time.Now()), time.Hour)

	got, err := store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "legacy", got.ID)
	assert.Equal(t, "legacy", scopedPointer(t, store, "t1", "u1"), "dead pointer dropped, then backfilled")
}

func TestRedisGetByUser_BothPointersAbsent(t *testing.T) {
	store, _ := newTestRedisStore(t)
	got, err := store.GetByUser(context.Background(), "t1", "u1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	assert.Nil(t, got)
}

func TestRedisGetByUser_DanglingScopedPointerAloneIsNotFound(t *testing.T) {
	store, mr := newTestRedisStore(t)
	putScoped(t, store, sessAt("scoped", "t1", "u1", time.Now()))
	mr.Del(store.sessionKey("scoped"))
	_, err := store.GetByUser(context.Background(), "t1", "u1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	assert.False(t, mr.Exists(store.userKey("t1", "u1")), "the dead pointer is dropped")
}

// A scoped pointer that names another user's or tenant's session is never
// returned, and is dropped.
func TestRedisGetByUser_ScopedPointerMismatchRejected(t *testing.T) {
	store, mr := newTestRedisStore(t)
	ctx := context.Background()
	putScoped(t, store, sessAt("victim", "t2", "other", time.Now()))
	require.NoError(t, store.client.Set(ctx, store.userKey("t1", "u1"), "victim", time.Hour).Err())

	got, err := store.GetByUser(ctx, "t1", "u1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
	assert.Nil(t, got)
	assert.False(t, mr.Exists(store.userKey("t1", "u1")), "mismatched pointer dropped")
	assert.True(t, mr.Exists(store.sessionKey("victim")), "the other user's session is untouched")

	// Right user, wrong tenant.
	putScoped(t, store, sessAt("wrongtenant", "t2", "u1", time.Now()))
	require.NoError(t, store.client.Set(ctx, store.userKey("t1", "u1"), "wrongtenant", time.Hour).Err())
	_, err = store.GetByUser(ctx, "t1", "u1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

// The compare-and-set loses to a concurrent writer: the winner's pointer is
// kept (no clobber) and its session is returned.
func TestRedisGetByUser_CompareAndSetLosesRace(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()
	now := time.Now()
	putScoped(t, store, sessAt("scoped", "t1", "u1", now.Add(-2*time.Hour)))
	seedLegacySession(t, store, sessAt("legacy", "t1", "u1", now.Add(-time.Hour)), time.Hour)
	winner := sessAt("winner", "t1", "u1", now)
	data, err := jsonMarshal(winner)
	require.NoError(t, err)
	require.NoError(t, store.client.Set(ctx, store.sessionKey("winner"), data, time.Hour).Err())

	var raced atomic.Bool
	uk := store.userKey("t1", "u1")
	store.client.AddHook(&faultHook{fn: func(cmd redis.Cmder) error {
		if isEval(cmd) && cmdMentions(cmd, uk) && cmdMentions(cmd, "legacy") && raced.CompareAndSwap(false, true) {
			// Another replica repoints the pointer just before the CAS runs.
			require.NoError(t, store.client.Set(context.Background(), uk, "winner", time.Hour).Err())
		}
		return nil
	}})

	got, err := store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.True(t, raced.Load(), "the race must have been injected")
	assert.Equal(t, "winner", got.ID)
	assert.Equal(t, "winner", scopedPointer(t, store, "t1", "u1"), "the concurrent write is not clobbered")
}

// Redis errors at every step fail closed: an error and no session.
func TestRedisGetByUser_RedisErrorsFailClosed(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		setup func(t *testing.T, s *RedisSessionStore)
		fail  func(s *RedisSessionStore, calls *atomic.Int32) func(redis.Cmder) error
	}{
		{
			name:  "scoped pointer read",
			setup: func(t *testing.T, s *RedisSessionStore) {},
			fail: func(s *RedisSessionStore, _ *atomic.Int32) func(redis.Cmder) error {
				return func(c redis.Cmder) error {
					if c.Name() == "get" && cmdMentions(c, s.userKey("t1", "u1")) {
						return errInjected
					}
					return nil
				}
			},
		},
		{
			name:  "scoped session record read",
			setup: func(t *testing.T, s *RedisSessionStore) { putScoped(t, s, sessAt("a", "t1", "u1", now)) },
			fail: func(s *RedisSessionStore, _ *atomic.Int32) func(redis.Cmder) error {
				return func(c redis.Cmder) error {
					if c.Name() == "get" && cmdMentions(c, s.sessionKey("a")) {
						return errInjected
					}
					return nil
				}
			},
		},
		{
			name:  "legacy pointer read beside a live scoped session",
			setup: func(t *testing.T, s *RedisSessionStore) { putScoped(t, s, sessAt("a", "t1", "u1", now)) },
			fail: func(s *RedisSessionStore, _ *atomic.Int32) func(redis.Cmder) error {
				return func(c redis.Cmder) error {
					if c.Name() == "get" && cmdMentions(c, s.legacyUserKey("u1")) {
						return errInjected
					}
					return nil
				}
			},
		},
		{
			name:  "legacy pointer read with no scoped pointer",
			setup: func(t *testing.T, s *RedisSessionStore) {},
			fail: func(s *RedisSessionStore, _ *atomic.Int32) func(redis.Cmder) error {
				return func(c redis.Cmder) error {
					if c.Name() == "get" && cmdMentions(c, s.legacyUserKey("u1")) {
						return errInjected
					}
					return nil
				}
			},
		},
		{
			name: "scoped pointer re-read after the legacy lookup",
			setup: func(t *testing.T, s *RedisSessionStore) {
				seedLegacySession(t, s, sessAt("l", "t1", "u1", now), time.Hour)
			},
			fail: func(s *RedisSessionStore, calls *atomic.Int32) func(redis.Cmder) error {
				return func(c redis.Cmder) error {
					if c.Name() == "get" && cmdMentions(c, s.userKey("t1", "u1")) && calls.Add(1) == 2 {
						return errInjected
					}
					return nil
				}
			},
		},
		{
			name: "dropping a dead pointer",
			setup: func(t *testing.T, s *RedisSessionStore) {
				require.NoError(t, s.client.Set(context.Background(), s.userKey("t1", "u1"), "ghost", time.Hour).Err())
			},
			fail: func(s *RedisSessionStore, _ *atomic.Int32) func(redis.Cmder) error {
				return func(c redis.Cmder) error {
					if isEval(c) && cmdMentions(c, s.userKey("t1", "u1")) {
						return errInjected
					}
					return nil
				}
			},
		},
		{
			name: "dropping a mismatched pointer",
			setup: func(t *testing.T, s *RedisSessionStore) {
				putScoped(t, s, sessAt("v", "t2", "other", now))
				require.NoError(t, s.client.Set(context.Background(), s.userKey("t1", "u1"), "v", time.Hour).Err())
			},
			fail: func(s *RedisSessionStore, _ *atomic.Int32) func(redis.Cmder) error {
				return func(c redis.Cmder) error {
					if isEval(c) && cmdMentions(c, s.userKey("t1", "u1")) {
						return errInjected
					}
					return nil
				}
			},
		},
		{
			name: "compare-and-set",
			setup: func(t *testing.T, s *RedisSessionStore) {
				putScoped(t, s, sessAt("a", "t1", "u1", now.Add(-time.Hour)))
				seedLegacySession(t, s, sessAt("l", "t1", "u1", now), time.Hour)
			},
			fail: func(s *RedisSessionStore, _ *atomic.Int32) func(redis.Cmder) error {
				return func(c redis.Cmder) error {
					if isEval(c) && cmdMentions(c, s.userKey("t1", "u1")) {
						return errInjected
					}
					return nil
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := newTestRedisStore(t)
			tc.setup(t, store)
			var calls atomic.Int32
			store.client.AddHook(&faultHook{fn: tc.fail(store, &calls)})
			got, err := store.GetByUser(context.Background(), "t1", "u1")
			assert.ErrorIs(t, err, errInjected)
			assert.Nil(t, got)
		})
	}
}

func TestRedisGet_ErrorsAndCorruptRecord(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()
	require.NoError(t, store.client.Set(ctx, store.sessionKey("bad"), "{not json", time.Hour).Err())
	_, err := store.Get(ctx, "bad")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrSessionNotFound)

	store.client.AddHook(&faultHook{fn: func(c redis.Cmder) error {
		if c.Name() == "get" {
			return errInjected
		}
		return nil
	}})
	_, err = store.Get(ctx, "x")
	assert.ErrorIs(t, err, errInjected)
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// Redis errors in the write, delete and list paths are returned, never
// swallowed into a false success.
func TestRedisStore_RedisErrorsAreReturned(t *testing.T) {
	ctx := context.Background()
	failNames := func(names ...string) func(redis.Cmder) error {
		return func(c redis.Cmder) error {
			for _, n := range names {
				if c.Name() == n {
					return errInjected
				}
			}
			return nil
		}
	}
	seed := func(t *testing.T, s *RedisSessionStore) {
		putScoped(t, s, sessAt("a", "t1", "u1", time.Now()))
		putScoped(t, s, sessAt("b", "t1", "u2", time.Now()))
	}
	cases := []struct {
		name string
		fail func(redis.Cmder) error
		call func(s *RedisSessionStore) error
	}{
		{"put", failNames("evalsha", "eval"), func(s *RedisSessionStore) error {
			return s.Put(ctx, redisSess("n", "t1", "u9", time.Hour))
		}},
		{"update exists check", failNames("exists"), func(s *RedisSessionStore) error {
			return s.Update(ctx, redisSess("a", "t1", "u1", time.Hour))
		}},
		{"delete record read", failNames("get"), func(s *RedisSessionStore) error {
			return s.Delete(ctx, "t1", "u1", "a")
		}},
		{"deleteByUser candidates", failNames("zrange"), func(s *RedisSessionStore) error {
			return s.DeleteByUser(ctx, "u1")
		}},
		{"deleteByUser batch args", failNames("get"), func(s *RedisSessionStore) error {
			return s.DeleteByUser(ctx, "u1")
		}},
		{"deleteByUser batch script", failNames("evalsha", "eval"), func(s *RedisSessionStore) error {
			return s.DeleteByUser(ctx, "u1")
		}},
		{"list tenant set", failNames("zrange"), func(s *RedisSessionStore) error {
			_, err := s.List(ctx, "t1")
			return err
		}},
		{"list legacy set", failNames("smembers"), func(s *RedisSessionStore) error {
			_, err := s.List(ctx, "t1")
			return err
		}},
		{"list session read", failNames("get"), func(s *RedisSessionStore) error {
			_, err := s.List(ctx, "t1")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := newTestRedisStore(t)
			seed(t, store)
			store.client.AddHook(&faultHook{fn: tc.fail})
			assert.ErrorIs(t, tc.call(store), errInjected)
		})
	}
}

// A corrupt record is an error for the cleanup path too, not "not found".
func TestRedisStore_RawSessionCorruptRecord(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()
	require.NoError(t, store.client.Set(ctx, store.sessionKey("bad"), "{nope", time.Hour).Err())
	_, err := store.rawSession(ctx, "bad")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrSessionNotFound)
	assert.Error(t, store.Delete(ctx, "t1", "u1", "bad"))
}

// A failing index backfill does not fail the lookup of a valid legacy session.
func TestRedisGetByUser_BackfillFailureStillReturnsLegacySession(t *testing.T) {
	store, _ := newTestRedisStore(t)
	seedLegacySession(t, store, sessAt("l", "t1", "u1", time.Now()), time.Hour)
	store.client.AddHook(&pipelineFailHook{})
	got, err := store.GetByUser(context.Background(), "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "l", got.ID)
}

type pipelineFailHook struct{}

func (h *pipelineFailHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *pipelineFailHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return next
}
func (h *pipelineFailHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		return errInjected
	}
}

// When the scoped pointer appears for a different session while the legacy
// lookup runs, the lookup starts over and returns the pointer's session.
func TestRedisGetByUser_ScopedPointerAppearsDuringLegacyLookup(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()
	seedLegacySession(t, store, sessAt("l", "t1", "u1", time.Now().Add(-time.Hour)), time.Hour)
	newer := sessAt("n", "t1", "u1", time.Now())
	data, err := jsonMarshal(newer)
	require.NoError(t, err)
	require.NoError(t, store.client.Set(ctx, store.sessionKey("n"), data, time.Hour).Err())

	uk := store.userKey("t1", "u1")
	var fired atomic.Bool
	store.client.AddHook(&faultHook{fn: func(c redis.Cmder) error {
		// After the legacy pointer was read, another replica Puts "n".
		if c.Name() == "get" && cmdMentions(c, store.legacyUserKey("u1")) && fired.CompareAndSwap(false, true) {
			defer func() { _ = store.client.Set(ctx, uk, "n", time.Hour).Err() }()
		}
		return nil
	}})
	// The hook sets the pointer after the legacy GET but the backfill SETNX then
	// loses to it.
	got, err := store.GetByUser(ctx, "t1", "u1")
	require.NoError(t, err)
	assert.Equal(t, "n", got.ID)
}

func TestRedisStore_CleanupIsNoop(t *testing.T) {
	store, _ := newTestRedisStore(t)
	n, err := store.Cleanup(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n)
}

// A failed transaction is an error for Delete and Update, so a retry can finish
// the cleanup.
func TestRedisStore_TransactionErrorsAreReturned(t *testing.T) {
	store, _ := newTestRedisStore(t)
	ctx := context.Background()
	putScoped(t, store, sessAt("a", "t1", "u1", time.Now()))
	store.client.AddHook(&pipelineFailHook{})
	assert.ErrorIs(t, store.Delete(ctx, "t1", "u1", "a"), errInjected)
	assert.ErrorIs(t, store.Update(ctx, redisSess("a", "t1", "u1", time.Hour)), errInjected)
}
