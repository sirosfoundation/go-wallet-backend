package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

type failTombstoneUsers struct {
	storage.UserStore
	fail bool
}

func (u *failTombstoneUsers) PutDeletionTombstone(ctx context.Context, t *domain.DeletionTombstone) error {
	if u.fail {
		return errors.New("tombstone store down")
	}
	return u.UserStore.PutDeletionTombstone(ctx, t)
}

type tombstoneStore struct {
	storage.Store
	users *failTombstoneUsers
}

func (s *tombstoneStore) Users() storage.UserStore { return s.users }

func TestDeleteUser_WritesTombstoneThatOutlivesEveryToken(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	cfg := testConfig()
	cfg.JWT.RefreshDays = 400 // longer than any other token lifetime here
	svc := NewUserService(store, cfg, zap.NewNop())
	at := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return at })
	uid := seedWalletUser(t, store, domain.DefaultTenantID, "acme")

	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))

	tomb, err := store.Users().GetDeletionTombstone(ctx, uid.String())
	require.NoError(t, err)
	assert.True(t, tomb.DeletedAt.Equal(at))
	assert.ElementsMatch(t, []domain.TenantID{domain.DefaultTenantID, "acme"}, tomb.TenantIDs)
	wantExpiry := at.Add(400*24*time.Hour + 30*24*time.Hour)
	assert.True(t, tomb.ExpiresAt.Equal(wantExpiry), "refresh-token lifetime plus the default 30 day margin, got %s", tomb.ExpiresAt)
	assert.True(t, tomb.ExpiresAt.After(at.Add(time.Duration(cfg.JWT.RefreshDays)*24*time.Hour)),
		"the tombstone must outlive the longest refresh token")
}

func TestDeleteUser_TombstoneWriteFailureDeletesNothing(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore()
	fu := &failTombstoneUsers{UserStore: base.Users(), fail: true}
	store := &tombstoneStore{Store: base, users: fu}
	svc := NewUserService(store, testConfig(), zap.NewNop())
	revoked := false
	svc.AddUserRevoker(revokerFunc(func(string) { revoked = true }))
	uid := seedWalletUser(t, base, domain.DefaultTenantID, "acme")
	did := "did:example:" + uid.String()

	err := svc.DeleteUser(ctx, uid, uid.String())
	require.ErrorIs(t, err, ErrDeletionIncomplete)
	// The documented semantics: a failed tombstone write removes NOTHING, not
	// merely the user record. Holder data and wallet instances in every
	// tenant must still be there.
	for _, tid := range []domain.TenantID{domain.DefaultTenantID, "acme"} {
		creds, cerr := base.Credentials().GetAllByHolder(ctx, tid, did)
		require.NoError(t, cerr)
		assert.Len(t, creds, 1, "credential in tenant %s must survive a failed tombstone write", tid)
		pres, perr := base.Presentations().GetAllByHolder(ctx, tid, did)
		require.NoError(t, perr)
		assert.Len(t, pres, 1, "presentation in tenant %s must survive a failed tombstone write", tid)
	}
	insts, ierr := base.WalletInstances().GetAllByUser(ctx, uid)
	require.NoError(t, ierr)
	assert.Len(t, insts, 1, "the wallet instance must survive a failed tombstone write")
	_, gerr := base.Users().GetByID(ctx, uid)
	assert.NoError(t, gerr, "the user record must survive")
	assert.False(t, revoked, "no permanent revocation may have happened")
	_, terr := base.Users().GetDeletionTombstone(ctx, uid.String())
	assert.ErrorIs(t, terr, storage.ErrNotFound)

	// While the record exists the gate reads its cut-off: the caller is not
	// locked out of the retry by a failed deletion.
	gate := tokengate.New(base.Users())
	assert.NoError(t, gate.Check(ctx, uid.String(), time.Now()))

	fu.fail = false
	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
	_, gerr = base.Users().GetByID(ctx, uid)
	assert.ErrorIs(t, gerr, storage.ErrNotFound)
	creds, cerr := base.Credentials().GetAllByHolder(ctx, "acme", did)
	require.NoError(t, cerr)
	assert.Empty(t, creds, "the retry erases the holder data")
	insts, ierr = base.WalletInstances().GetAllByUser(ctx, uid)
	require.NoError(t, ierr)
	assert.Empty(t, insts, "the retry removes the wallet instance")
	assert.ErrorIs(t, gate.Check(ctx, uid.String(), time.Now().Add(-time.Hour)), tokengate.ErrAccountDeleted)
}

type revokerFunc func(string)

func (f revokerFunc) RevokeUser(id string) { f(id) }

func TestTombstoneStore_PutIsIdempotent(t *testing.T) {
	ctx := context.Background()
	users := memory.NewStore().Users()
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, users.PutDeletionTombstone(ctx, &domain.DeletionTombstone{
		UserID: "u", TenantIDs: []domain.TenantID{"a"}, DeletedAt: t0, ExpiresAt: t0.Add(time.Hour),
	}))
	require.NoError(t, users.PutDeletionTombstone(ctx, &domain.DeletionTombstone{
		UserID: "u", TenantIDs: []domain.TenantID{"a", "b"}, DeletedAt: t0.Add(time.Minute), ExpiresAt: t0.Add(2 * time.Hour),
	}))
	got, err := users.GetDeletionTombstone(ctx, "u")
	require.NoError(t, err)
	assert.True(t, got.DeletedAt.Equal(t0), "earliest DeletedAt kept")
	assert.True(t, got.ExpiresAt.Equal(t0.Add(2*time.Hour)), "expiry only moves later")
	assert.ElementsMatch(t, []domain.TenantID{"a", "b"}, got.TenantIDs)

	// An earlier expiry on a retry does not shorten it.
	require.NoError(t, users.PutDeletionTombstone(ctx, &domain.DeletionTombstone{UserID: "u", DeletedAt: t0, ExpiresAt: t0}))
	got, _ = users.GetDeletionTombstone(ctx, "u")
	assert.True(t, got.ExpiresAt.Equal(t0.Add(2*time.Hour)))

	assert.ErrorIs(t, users.PutDeletionTombstone(ctx, &domain.DeletionTombstone{}), storage.ErrInvalidInput)
}

func TestTombstoneStore_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	users := memory.NewStore().Users()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for id, exp := range map[string]time.Time{"past": now.Add(-time.Second), "boundary": now, "future": now.Add(time.Second)} {
		require.NoError(t, users.PutDeletionTombstone(ctx, &domain.DeletionTombstone{UserID: id, DeletedAt: now.Add(-time.Hour), ExpiresAt: exp}))
	}
	n, err := users.DeleteExpiredDeletionTombstones(ctx, now)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	_, err = users.GetDeletionTombstone(ctx, "future")
	assert.NoError(t, err)
	_, err = users.GetDeletionTombstone(ctx, "past")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestDeletionTombstoneSweeper_ExpiryWithInjectedClock(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	cfg := testConfig()
	svc := NewUserService(store, cfg, zap.NewNop())
	deletedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return deletedAt })
	uid := seedWalletUser(t, store, domain.DefaultTenantID)
	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
	tomb, err := store.Users().GetDeletionTombstone(ctx, uid.String())
	require.NoError(t, err)

	now := deletedAt
	sw := NewDeletionTombstoneSweeper(config.DeletionTombstoneConfig{}, store, zap.NewNop())
	sw.now = func() time.Time { return now }
	gate := tokengate.New(store.Users())

	// Right up to the expiry the tombstone stays and the token stays refused.
	now = tomb.ExpiresAt.Add(-time.Second)
	n, err := sw.RunOnce(ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.ErrorIs(t, gate.Check(ctx, uid.String(), deletedAt.Add(-time.Hour)), tokengate.ErrRevoked)

	// At the expiry it is swept. No token can be valid any more by then.
	now = tomb.ExpiresAt
	n, err = sw.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	_, err = store.Users().GetDeletionTombstone(ctx, uid.String())
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestDeletionTombstoneSweeper_StartStop(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	past := time.Now().Add(-time.Hour)
	require.NoError(t, store.Users().PutDeletionTombstone(ctx, &domain.DeletionTombstone{UserID: "gone", DeletedAt: past, ExpiresAt: past}))

	sw := NewDeletionTombstoneSweeper(config.DeletionTombstoneConfig{CleanupIntervalSeconds: 3600}, store, zap.NewNop())
	sw.Start()
	sw.Start() // idempotent
	require.Eventually(t, func() bool {
		_, err := store.Users().GetDeletionTombstone(ctx, "gone")
		return errors.Is(err, storage.ErrNotFound)
	}, 2*time.Second, 5*time.Millisecond, "the sweeper sweeps once on start")
	sw.Stop()
	sw.Stop() // idempotent

	// The service lifecycle starts and stops it.
	svcs := NewServices(store, testConfig(), zap.NewNop())
	require.NotNil(t, svcs.TombstoneSweeper)
	svcs.Start()
	svcs.Stop()
}

// The scenario the tombstone exists for: a token issued before the account was
// deleted must not create a new wallet instance or WIA for it afterwards, and
// not pass the gate either.
func TestDeletedAccount_PreDeletionTokenCannotCreateAnInstanceOrWIA(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestWIAServiceWithUsers(t)
	users := NewUserService(store, testConfig(), zap.NewNop())
	uid := seedWalletUser(t, store)
	issuedAt := time.Now().Add(-time.Minute)
	tokenCtx := tokengate.WithSubject(ctx, uid.String(), issuedAt)
	gate := tokengate.New(store.Users())

	require.NoError(t, gate.Check(ctx, uid.String(), issuedAt), "admitted while the account exists")
	require.NoError(t, users.DeleteUser(ctx, uid, uid.String()))

	assert.ErrorIs(t, gate.Check(ctx, uid.String(), issuedAt), tokengate.ErrRevoked)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	require.NoError(t, err)
	pop, _ := createTestPop(t, challenge)
	token, err := svc.GenerateWIA(tokenCtx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	assert.ErrorIs(t, err, tokengate.ErrRevoked)
	assert.Empty(t, token)
	instances, gerr := store.WalletInstances().GetAllByUser(ctx, uid)
	if gerr != nil {
		assert.ErrorIs(t, gerr, storage.ErrNotFound)
	}
	assert.Empty(t, instances, "no instance may be created for a deleted account")
}
