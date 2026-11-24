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
)

// failNthGetByUser lets the first n-1 listings through, fails the nth, and
// lets later ones through again.
type failNthGetByUser struct {
	storage.WalletInstanceStore
	n, calls int
}

func (f *failNthGetByUser) GetByUser(ctx context.Context, tid domain.TenantID, uid domain.UserID) ([]*domain.WalletInstance, error) {
	f.calls++
	if f.calls == f.n {
		return nil, errors.New("db down")
	}
	return f.WalletInstanceStore.GetByUser(ctx, tid, uid)
}

// A revoke-all that persisted a revocation then errors out through an early
// cascade; the local record must carry the revocation time, or an older
// non-zero cut-off passes as sufficient and data is erased without a cut-off
// past the revocation.
func TestRevokeAll_PartialSweepAdvancesAnOlderCutoffBeforeErasing(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T) (*WalletLifecycleService, storage.Store, domain.UserID) {
		store := newFailStore().Store
		svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
		uid := seedWalletUser(t, store)
		require.NoError(t, store.Users().InvalidateAuthBefore(ctx, uid, time.Now()))
		time.Sleep(5 * time.Millisecond)
		return svc, store, uid
	}
	assertCutoffPastRevocation := func(t *testing.T, store storage.Store, uid domain.UserID) {
		inst, err := store.WalletInstances().GetByID(ctx, "inst-"+uid.String())
		require.NoError(t, err)
		require.Equal(t, domain.InstanceStatusRevoked, inst.Status)
		cutoff, err := store.Users().GetAuthCutoff(ctx, uid)
		require.NoError(t, err)
		assert.False(t, cutoff.Before(*inst.DeactivatedAt), "cut-off %v must not predate the revocation %v", cutoff, inst.DeactivatedAt)
	}

	t.Run("listing error on the second pass, erasure runs", func(t *testing.T) {
		svc, store, uid := setup(t)
		svc.store = storeWithInstances{Store: store, instances: &failNthGetByUser{WalletInstanceStore: store.WalletInstances(), n: 2}}
		_, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
		require.ErrorIs(t, err, ErrErasureIncomplete)
		u, gerr := store.Users().GetByID(ctx, uid)
		require.NoError(t, gerr)
		require.Empty(t, u.PrivateData, "everything was revoked, so the vault was erased")
		assertCutoffPastRevocation(t, store, uid)
	})

	t.Run("update error on a later instance", func(t *testing.T) {
		svc, store, uid := setup(t)
		require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "other-" + uid.String(), TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
		}))
		svc.store = storeWithInstances{Store: store, instances: &failAfterInstances{WalletInstanceStore: store.WalletInstances()}}
		_, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
		require.ErrorIs(t, err, ErrErasureIncomplete)
		first, gerr := store.WalletInstances().GetByUser(ctx, domain.DefaultTenantID, uid)
		require.NoError(t, gerr)
		cutoff, gerr := store.Users().GetAuthCutoff(ctx, uid)
		require.NoError(t, gerr)
		for _, in := range first {
			if in.Status == domain.InstanceStatusRevoked {
				assert.False(t, cutoff.Before(*in.DeactivatedAt), "cut-off must cover the persisted revocation")
			}
		}
	})
}

// A cascade handed a revoked record without a revocation time cannot show
// that a non-zero cut-off is new enough, so it must advance it.
func TestCascade_AdvancesACutoffWhenTheRevocationTimeIsUnknown(t *testing.T) {
	ctx := context.Background()
	store := newFailStore().Store
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	uid := seedWalletUser(t, store)
	old := time.Now().Add(-time.Hour)
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, uid, old))
	// A live instance keeps the erasure off, which would otherwise advance
	// the cut-off by itself.
	require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "live-" + uid.String(), TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
	}))
	inst := &domain.WalletInstance{ID: "x", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusRevoked}
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "inst-"+uid.String(), domain.DefaultTenantID, domain.InstanceStatusRevoked, "x"))
	require.NoError(t, svc.cascade(ctx, domain.DefaultTenantID, inst, providerActor))
	cutoff, err := store.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, err)
	assert.True(t, cutoff.After(old.Add(time.Minute)), "cut-off advanced")
}
