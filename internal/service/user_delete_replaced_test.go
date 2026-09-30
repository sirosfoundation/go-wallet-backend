package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// staleListStore hands DeleteUser a snapshot of the user's instances taken
// before an admin cleanup removed one and the same thumbprint was attested
// again for someone else.
type staleListStore struct {
	storage.Store
	stale []*domain.WalletInstance
	used  bool
}

type staleListInstances struct {
	storage.WalletInstanceStore
	s *staleListStore
}

func (s *staleListStore) WalletInstances() storage.WalletInstanceStore {
	return &staleListInstances{s.Store.WalletInstances(), s}
}

func (l *staleListInstances) GetAllByUser(ctx context.Context, userID domain.UserID) ([]*domain.WalletInstance, error) {
	if !l.s.used {
		l.s.used = true
		return l.s.stale, nil
	}
	return l.WalletInstanceStore.GetAllByUser(ctx, userID)
}

func TestDeleteUser_DoesNotDeleteAReplacementInstanceFromAStaleListing(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewStore()
	victim := domain.NewUserID()
	other := domain.NewUserID()
	require.NoError(t, inner.Users().Create(ctx, &domain.User{UUID: victim, DID: "did:key:" + victim.String()}))

	// The victim's record as listed, then replaced by the same thumbprint
	// attested in another tenant for another user.
	stale := &domain.WalletInstance{ID: "thumb", TenantID: "acme", UserID: &victim, Status: domain.InstanceStatusActive}
	require.NoError(t, inner.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "thumb", TenantID: "other-tenant", UserID: &other, Status: domain.InstanceStatusActive,
	}))

	svc := NewUserService(&staleListStore{Store: inner, stale: []*domain.WalletInstance{stale}}, testConfig(), zap.NewNop())
	// The first pass sees the mismatch, the second pass re-lists and finds
	// nothing of the victim's: the deletion completes, and the replacement
	// must be untouched throughout.
	err := svc.DeleteUser(ctx, victim, "did:key:"+victim.String())
	assert.NoError(t, err)

	got, gerr := inner.WalletInstances().GetByID(ctx, "thumb")
	require.NoError(t, gerr, "another user's replacement instance must survive")
	assert.Equal(t, domain.TenantID("other-tenant"), got.TenantID)
	assert.Equal(t, other, *got.UserID)
}

// A delete that matches nothing is an incomplete cleanup when the record is
// still the user's as far as the final listing can tell.
func TestDeleteWalletInstances_MismatchIsReportedAsIncomplete(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewStore()
	victim := domain.NewUserID()
	other := domain.NewUserID()
	require.NoError(t, inner.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "thumb", TenantID: "other-tenant", UserID: &other, Status: domain.InstanceStatusActive,
	}))
	stale := &domain.WalletInstance{ID: "thumb", TenantID: "acme", UserID: &victim, Status: domain.InstanceStatusActive}
	svc := NewUserService(&staleListStore{Store: inner, stale: []*domain.WalletInstance{stale}}, testConfig(), zap.NewNop())

	errs := svc.deleteWalletInstances(ctx, victim)
	require.Len(t, errs, 1)
	assert.ErrorIs(t, errs[0], storage.ErrNotFound)
	_, gerr := inner.WalletInstances().GetByID(ctx, "thumb")
	assert.NoError(t, gerr)
}
