package mongodb

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

func TestWalletInstanceStore_UpdateStatus_RejectsUnknownStatus(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-unknown-status",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	require.NoError(t, wis.Upsert(ctx, inst))

	// Regression test: an unrecognized status value must be rejected, not
	// silently written with no transition constraint. Without this check the
	// filter stays {_id: id} only, since the switch's default case previously
	// left it unconstrained.
	err := wis.UpdateStatus(ctx, "inst-unknown-status", domain.InstanceStatus("bogus"), "")
	require.Error(t, err)
	require.True(t, errors.Is(err, domain.ErrInvalidStatusTransition))

	got, err := wis.GetByID(ctx, "inst-unknown-status")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatusActive, got.Status, "status must be unchanged after a rejected update")
}

func TestWalletInstanceStore_UpdateStatus_ValidTransitions(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()

	inst := &domain.WalletInstance{
		ID:       "inst-valid-transitions",
		TenantID: "acme",
		Status:   domain.InstanceStatusActive,
	}
	require.NoError(t, wis.Upsert(ctx, inst))

	require.NoError(t, wis.UpdateStatus(ctx, "inst-valid-transitions", domain.InstanceStatusSuspended, "policy violation"))
	got, err := wis.GetByID(ctx, "inst-valid-transitions")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatusSuspended, got.Status)
	require.NotNil(t, got.DeactivatedAt)

	require.NoError(t, wis.UpdateStatus(ctx, "inst-valid-transitions", domain.InstanceStatusRevoked, "compromised"))
	got, err = wis.GetByID(ctx, "inst-valid-transitions")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatusRevoked, got.Status)

	// Revoked is terminal: attempting to reactivate must fail.
	err = wis.UpdateStatus(ctx, "inst-valid-transitions", domain.InstanceStatusActive, "")
	require.Error(t, err)
}
