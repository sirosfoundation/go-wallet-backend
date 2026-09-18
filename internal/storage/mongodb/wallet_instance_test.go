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

	// "active" is refused outright: an instance is active from insert, so
	// writing it could only ever mean reactivation.
	err := wis.UpdateStatus(ctx, "inst-valid-transitions", domain.InstanceStatusActive, "")
	require.Error(t, err)
	require.True(t, errors.Is(err, domain.ErrInvalidStatusTransition))

	require.NoError(t, wis.UpdateStatus(ctx, "inst-valid-transitions", domain.InstanceStatusRevoked, "compromised"))
	got, err := wis.GetByID(ctx, "inst-valid-transitions")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatusRevoked, got.Status)
	require.NotNil(t, got.DeactivatedAt)
	require.Equal(t, "compromised", got.DeactivationReason)

	// Revoked is terminal: attempting to reactivate must fail.
	err = wis.UpdateStatus(ctx, "inst-valid-transitions", domain.InstanceStatusActive, "")
	require.Error(t, err)
	require.True(t, errors.Is(err, domain.ErrInvalidStatusTransition))
}

// A record written by a release that still had the reversible "suspended"
// state must remain closable. The conditional filter matches anything not
// already revoked, so an operator can finish what they started; without that
// the document would be stuck in a state nothing can leave.
func TestWalletInstanceStore_UpdateStatus_LegacySuspendedIsRevocable(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()

	// Inserted directly in the legacy state, as an earlier release would have.
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID:       "inst-legacy-suspended",
		TenantID: "acme",
		Status:   domain.InstanceStatusLegacySuspended,
	}))

	require.NoError(t, wis.UpdateStatus(ctx, "inst-legacy-suspended", domain.InstanceStatusRevoked, "cleanup"))
	got, err := wis.GetByID(ctx, "inst-legacy-suspended")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatusRevoked, got.Status)
	require.NotNil(t, got.DeactivatedAt)

	// And it is terminal from there like any other revocation.
	err = wis.UpdateStatus(ctx, "inst-legacy-suspended", domain.InstanceStatusRevoked, "again")
	require.Error(t, err, "revoking an already-revoked instance matches nothing")
}
