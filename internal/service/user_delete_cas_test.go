package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// beforeAdvanceStore runs beforeAdvance immediately before the user store
// executes DeleteUser's cut-off advance: the exact window a read-then-advance
// would leave open between its check and its write.
type beforeAdvanceStore struct {
	storage.Store
	beforeAdvance func()
}

type beforeAdvanceUsers struct {
	storage.UserStore
	s *beforeAdvanceStore
}

func (s *beforeAdvanceStore) Users() storage.UserStore {
	return &beforeAdvanceUsers{s.Store.Users(), s}
}

func (u *beforeAdvanceUsers) InvalidateAuthBeforeForToken(ctx context.Context, id domain.UserID, t, iat time.Time) error {
	if u.s.beforeAdvance != nil {
		u.s.beforeAdvance()
	}
	return u.UserStore.InvalidateAuthBeforeForToken(ctx, id, t, iat)
}

// A lifecycle revocation landing between the deletion's last look at the
// cut-off and its advance is refused by the compare-and-set: 401-class error,
// no permanent revocation, no user removal, and the independent cut-off is
// not overwritten.
func TestDeleteUser_CompareAndSetRefusesRevocationLandingBeforeTheAdvance(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewStore()
	hs := &beforeAdvanceStore{Store: inner}
	svc := NewUserService(hs, testConfig(), zap.NewNop())
	bl, ur := &countingRevoker{}, &countingUserRevoker{}
	svc.SetTokenBlacklist(bl)
	svc.AddUserRevoker(ur)
	cleaner := &scriptedCleaner{}
	svc.SetSessionCleaner(cleaner)
	uid := domain.NewUserID()
	require.NoError(t, inner.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}))

	independent := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	hs.beforeAdvance = func() {
		require.NoError(t, inner.Users().InvalidateAuthBefore(ctx, uid, independent))
	}

	err := svc.DeleteUser(tokengate.WithIssuedAt(ctx, time.Now().Add(-time.Minute)), uid, uid.String())
	require.ErrorIs(t, err, tokengate.ErrRevoked)
	assert.Zero(t, bl.calls, "no permanent revocation")
	assert.Zero(t, ur.calls)
	assert.Equal(t, 1, cleaner.calls, "the post-revocation cleaner pass never ran")
	_, gerr := inner.Users().GetByID(ctx, uid)
	assert.NoError(t, gerr, "the account is kept")
	cutoff, err := inner.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, err)
	assert.True(t, cutoff.Equal(independent), "the independent cut-off stands")
}

// Reverse of the above: no independent revocation, a token issued after a
// cut-off left by an earlier attempt passes the compare-and-set.
func TestDeleteUser_CompareAndSetPassesAFreshTokenAfterAnEarlierAttemptsCutoff(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), zap.NewNop())
	svc.SetSessionCleaner(&scriptedCleaner{})
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}))
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, uid, time.Now().Add(-time.Minute)))

	fresh := tokengate.WithIssuedAt(ctx, time.Now().Add(-time.Second))
	require.NoError(t, svc.DeleteUser(fresh, uid, uid.String()))
	_, gerr := store.Users().GetByID(ctx, uid)
	assert.ErrorIs(t, gerr, storage.ErrNotFound)
}
