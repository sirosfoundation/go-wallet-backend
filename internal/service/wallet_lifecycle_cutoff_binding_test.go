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

// The user-wide token cut-off must only follow a confirmed instance
// transition. If the instance was deleted and attested again for another user
// between the read and the conditional write, nobody's tokens are cut off.
func TestLifecycle_CutoffIsNotAdvancedWhenTheBindingChanged(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*WalletLifecycleService, storage.Store, domain.UserID, domain.UserID, string) {
		base := memory.NewStore()
		alice := seedWalletUser(t, base)
		bob := seedWalletUser(t, base)
		id := "inst-" + alice.String()
		hooked := &beforeWriteInstances{WalletInstanceStore: base.WalletInstances(), match: id}
		hooked.hook = func() { replaceInstance(t, base.WalletInstances(), id, domain.DefaultTenantID, &bob) }
		return NewWalletLifecycleService(&racingInstanceStore{Store: base, instances: hooked}, zap.NewNop(), nil), base, alice, bob, id
	}
	requireNoCutoff := func(t *testing.T, base storage.Store, users ...domain.UserID) {
		for _, u := range users {
			c, err := base.Users().GetAuthCutoff(ctx, u)
			require.NoError(t, err)
			assert.True(t, c.IsZero(), "user %s must not be logged out by a transition that did not happen", u)
		}
	}

	t.Run("ChangeStatus", func(t *testing.T) {
		svc, base, alice, bob, id := setup(t)
		_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "lost")
		require.ErrorIs(t, err, storage.ErrNotFound)
		requireNoCutoff(t, base, alice, bob)
		got, err := base.WalletInstances().GetByID(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, domain.InstanceStatusActive, got.Status, "bob's replacement stays active")
	})
	t.Run("RevokeAllForUser", func(t *testing.T) {
		svc, base, alice, bob, id := setup(t)
		_, err := svc.RevokeAllForUser(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, alice, "lost")
		require.Error(t, err)
		requireNoCutoff(t, base, alice, bob)
		got, err := base.WalletInstances().GetByID(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, domain.InstanceStatusActive, got.Status)
	})
	t.Run("happy path cuts off only the revoked instance's user", func(t *testing.T) {
		base := memory.NewStore()
		alice := seedWalletUser(t, base)
		bob := seedWalletUser(t, base)
		svc := NewWalletLifecycleService(base, zap.NewNop(), nil)
		_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-"+alice.String(), domain.InstanceStatusRevoked, "lost")
		require.NoError(t, err)
		c, err := base.Users().GetAuthCutoff(ctx, alice)
		require.NoError(t, err)
		assert.False(t, c.IsZero(), "alice's tokens are cut off after the confirmed revocation")
		requireNoCutoff(t, base, bob)
	})
}
