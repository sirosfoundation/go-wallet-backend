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
)

// bindingInstances binds the named anonymous instance to a user just before
// UpdateStatus runs, simulating an attestation that lands between
// ChangeStatus's read of the instance and its status write.
type bindingInstances struct {
	storage.WalletInstanceStore
	userID domain.UserID
}

func (b *bindingInstances) UpdateStatusIfUnchanged(ctx context.Context, id string, tenantID domain.TenantID, exp domain.InstanceBinding, st domain.InstanceStatus, reason string) error {
	uid := b.userID
	if err := b.WalletInstanceStore.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: tenantID, UserID: &uid}); err != nil {
		return err
	}
	return b.WalletInstanceStore.UpdateStatusIfUnchanged(ctx, id, tenantID, exp, st, reason)
}

// An anonymous instance bound to a user concurrently with its revocation must
// still cut off that user's tokens and run the cascade: both work from the
// persisted owner, not from the pre-write copy that had no owner.
func TestWalletLifecycle_ChangeStatus_ConcurrentBindIsCutOffAndCascaded(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore()
	uid := seedWalletUser(t, base, domain.DefaultTenantID)
	// Drop the seeded live instance so revoking the bound one empties the wallet.
	require.NoError(t, base.WalletInstances().Delete(ctx, "inst-"+uid.String()))
	require.NoError(t, base.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "anon-inst", TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive,
	}))
	racing := &racingInstanceStore{Store: base, instances: &bindingInstances{WalletInstanceStore: base.WalletInstances(), userID: uid}}
	svc := NewWalletLifecycleService(racing, zap.NewNop(), nil)
	cleaner := &fakeSessionCleaner{}
	svc.SetSessionCleaner(cleaner)

	before := time.Now().Add(-time.Second)
	inst, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "anon-inst", domain.InstanceStatusRevoked, "lost")
	require.NoError(t, err)
	require.NotNil(t, inst.UserID, "the returned instance is the persisted one, with its owner")
	assert.Equal(t, uid, *inst.UserID)
	assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)

	cutoff, err := base.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, err)
	assert.True(t, cutoff.After(before), "the bound user's tokens must be cut off, got %s", cutoff)
	assert.Equal(t, []string{uid.String()}, cleaner.users, "the bound user's sessions must be dropped")
	creds, pres := countHolderData(t, base, domain.DefaultTenantID, uid)
	assert.Zero(t, creds+pres, "the cascade must erase the bound user's wallet data")
}
