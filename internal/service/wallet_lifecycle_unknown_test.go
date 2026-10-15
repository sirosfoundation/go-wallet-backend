package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

const unknownInstanceStatus = domain.InstanceStatus("corrupted")

// seedRawInstance inserts an instance with an arbitrary stored status (a
// corrupted or newer-release record) via Upsert.
func seedRawInstance(t *testing.T, store storage.Store, tenant domain.TenantID, id string, userID domain.UserID, credentialID string, st domain.InstanceStatus) {
	t.Helper()
	require.NoError(t, store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{
		ID: id, TenantID: tenant, UserID: &userID, CredentialID: credentialID, Status: st,
	}))
}

// An instance with an unrecognized status is neither live nor known to be
// dead. Revoking the other instance must not declare the wallet deactivated
// and erase its data on the strength of it.
func TestWalletLifecycle_UnknownStatusInstanceFailsClosed(t *testing.T) {
	ctx := context.Background()
	actor := LifecycleActor{Kind: "provider"}

	t.Run("same tenant: revoked + unknown erases nothing", func(t *testing.T) {
		svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive)
		seedRawInstance(t, store, domain.DefaultTenantID, "inst-b", userID, "", unknownInstanceStatus)

		_, err := svc.ChangeStatus(ctx, actor, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "lost")
		require.ErrorIs(t, err, ErrErasureIncomplete)
		user, err := store.Users().GetByID(ctx, userID)
		require.NoError(t, err)
		assert.NotNil(t, user.PrivateData, "the unresolved record keeps the wallet data")
		_, err = store.Challenges().GetByID(ctx, "chal-1")
		assert.NoError(t, err, "challenges are kept too")
	})

	t.Run("cross tenant: revoked + unknown erases nothing", func(t *testing.T) {
		svc, store, userID, holder := twoTenantFixture(t)
		// tenant B's live instance is replaced by one nobody can read.
		_, err := svc.ChangeStatus(ctx, actor, tenantB, "inst-"+string(tenantB), domain.InstanceStatusRevoked, "lost")
		require.NoError(t, err)
		seedRawInstance(t, store, tenantB, "inst-raw", userID, "", unknownInstanceStatus)

		_, err = svc.ChangeStatus(ctx, actor, tenantA, "inst-"+string(tenantA), domain.InstanceStatusRevoked, "lost")
		require.ErrorIs(t, err, ErrErasureIncomplete)
		assert.Equal(t, 2, holderDataCount(t, store, tenantA, holder))
		assert.Equal(t, 2, holderDataCount(t, store, tenantB, holder))
		user, err := store.Users().GetByID(ctx, userID)
		require.NoError(t, err)
		assert.NotNil(t, user.PrivateData)
	})

	t.Run("revoked + legacy suspended still erases", func(t *testing.T) {
		svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive)
		seedLegacySuspended(t, store, "inst-legacy", userID)

		_, err := svc.ChangeStatus(ctx, actor, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "lost")
		require.NoError(t, err)
		user, err := store.Users().GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Nil(t, user.PrivateData)
	})
}

func TestInstanceStatus_IsKnownNonLive(t *testing.T) {
	assert.True(t, domain.InstanceStatusRevoked.IsKnownNonLive())
	assert.True(t, domain.InstanceStatusLegacySuspended.IsKnownNonLive())
	assert.False(t, domain.InstanceStatusActive.IsKnownNonLive())
	assert.False(t, unknownInstanceStatus.IsKnownNonLive())
	assert.False(t, domain.InstanceStatus("").IsKnownNonLive())
}
