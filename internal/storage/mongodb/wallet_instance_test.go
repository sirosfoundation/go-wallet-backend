package mongodb

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
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
	err := wis.UpdateStatus(ctx, "inst-unknown-status", "acme", domain.InstanceStatus("bogus"), "")
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
	err := wis.UpdateStatus(ctx, "inst-valid-transitions", "acme", domain.InstanceStatusActive, "")
	require.Error(t, err)
	require.True(t, errors.Is(err, domain.ErrInvalidStatusTransition))

	require.NoError(t, wis.UpdateStatus(ctx, "inst-valid-transitions", "acme", domain.InstanceStatusRevoked, "compromised"))
	got, err := wis.GetByID(ctx, "inst-valid-transitions")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatusRevoked, got.Status)
	require.NotNil(t, got.DeactivatedAt)
	require.Equal(t, "compromised", got.DeactivationReason)

	// Revoked is terminal: attempting to reactivate must fail.
	err = wis.UpdateStatus(ctx, "inst-valid-transitions", "acme", domain.InstanceStatusActive, "")
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

	require.NoError(t, wis.UpdateStatus(ctx, "inst-legacy-suspended", "acme", domain.InstanceStatusRevoked, "cleanup"))
	got, err := wis.GetByID(ctx, "inst-legacy-suspended")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatusRevoked, got.Status)
	require.NotNil(t, got.DeactivatedAt)

	// And it is terminal from there like any other revocation.
	err = wis.UpdateStatus(ctx, "inst-legacy-suspended", "acme", domain.InstanceStatusRevoked, "again")
	require.Error(t, err, "revoking an already-revoked instance matches nothing")
}

// The Mongo store must agree with the memory one about what is removable, so
// a racing revocation keeps its tombstone in both.
func TestWalletInstanceStore_DeleteIfRemovable(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	uid := domain.UserIDFromString("owner")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "del-live", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive,
	}))
	require.NoError(t, wis.DeleteIfRemovable(ctx, "del-live", "acme"))

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "del-tomb", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive,
	}))
	require.NoError(t, wis.UpdateStatus(ctx, "del-tomb", "acme", domain.InstanceStatusRevoked, "stolen"))
	err := wis.DeleteIfRemovable(ctx, "del-tomb", "acme")
	require.True(t, errors.Is(err, domain.ErrInvalidStatusTransition), "got %v", err)
	_, err = wis.GetByID(ctx, "del-tomb")
	require.NoError(t, err, "the tombstone must survive")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "del-stray", TenantID: "acme", Status: domain.InstanceStatusRevoked,
	}))
	require.NoError(t, wis.DeleteIfRemovable(ctx, "del-stray", "acme"), "a record with no user is removable")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "del-other", TenantID: "other", UserID: &uid, Status: domain.InstanceStatusActive,
	}))
	err = wis.DeleteIfRemovable(ctx, "del-other", "acme")
	require.True(t, errors.Is(err, storage.ErrNotFound), "got %v", err)
}

func TestWalletInstanceStore_OwnerCheckedWrites(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	owner := domain.UserIDFromString("owner-checked")
	other := domain.UserIDFromString("other-checked")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "owned-1", TenantID: "acme", UserID: &owner, Status: domain.InstanceStatusActive,
	}))
	require.ErrorIs(t, wis.DeleteForUser(ctx, "owned-1", "acme", other), storage.ErrNotFound)
	require.ErrorIs(t, wis.DeleteForUser(ctx, "owned-1", "elsewhere", owner), storage.ErrNotFound)
	_, err := wis.GetByID(ctx, "owned-1")
	require.NoError(t, err, "a mismatched delete must leave the record")

	require.ErrorIs(t, wis.UpdateStatusForUser(ctx, "owned-1", "acme", other, domain.InstanceStatusRevoked, "x"), storage.ErrNotFound)
	got, err := wis.GetByID(ctx, "owned-1")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatusActive, got.Status)

	require.NoError(t, wis.UpdateStatusForUser(ctx, "owned-1", "acme", owner, domain.InstanceStatusRevoked, "x"))
	require.NoError(t, wis.DeleteForUser(ctx, "owned-1", "acme", owner))
	require.ErrorIs(t, wis.DeleteForUser(ctx, "owned-1", "acme", owner), storage.ErrNotFound)
}
