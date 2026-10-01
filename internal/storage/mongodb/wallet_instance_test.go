package mongodb

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"

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

func TestWalletInstanceStore_UpdateStatus_UnknownStoredStatusCannotBeRevoked(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "inst-corrupt", TenantID: "acme", Status: domain.InstanceStatus("bogus"),
	}))
	err := wis.UpdateStatus(ctx, "inst-corrupt", "acme", domain.InstanceStatusRevoked, "x")
	require.ErrorIs(t, err, domain.ErrInvalidStatusTransition)
	got, err := wis.GetByID(ctx, "inst-corrupt")
	require.NoError(t, err)
	require.Equal(t, domain.InstanceStatus("bogus"), got.Status)
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
	require.NoError(t, wis.DeleteIfRemovable(ctx, "del-live", "acme", bindingOf(t, wis, "del-live")))

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "del-tomb", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive,
	}))
	require.NoError(t, wis.UpdateStatus(ctx, "del-tomb", "acme", domain.InstanceStatusRevoked, "stolen"))
	err := wis.DeleteIfRemovable(ctx, "del-tomb", "acme", bindingOf(t, wis, "del-tomb"))
	require.True(t, errors.Is(err, domain.ErrInvalidStatusTransition), "got %v", err)
	_, err = wis.GetByID(ctx, "del-tomb")
	require.NoError(t, err, "the tombstone must survive")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "del-stray", TenantID: "acme", Status: domain.InstanceStatusRevoked,
	}))
	require.NoError(t, wis.DeleteIfRemovable(ctx, "del-stray", "acme", bindingOf(t, wis, "del-stray")), "a record with no user is removable")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{
		ID: "del-other", TenantID: "other", UserID: &uid, Status: domain.InstanceStatusActive,
	}))
	err = wis.DeleteIfRemovable(ctx, "del-other", "acme", bindingOf(t, wis, "del-other"))
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

// bindingOf reads the binding of a stored record, as a caller that is about
// to make a conditional write would.
func bindingOf(t *testing.T, wis storage.WalletInstanceStore, id string) domain.InstanceBinding {
	t.Helper()
	inst, err := wis.GetByID(context.Background(), id)
	require.NoError(t, err)
	return inst.Binding()
}

// A record deleted and created again under the same id and tenant is a
// different record to a conditional write, whoever owns the replacement.
func TestWalletInstanceStore_Conditional_ReplacementIsNotTheRecordRead(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	alice := domain.UserIDFromString("cond-alice")
	bob := domain.UserIDFromString("cond-bob")

	writes := map[string]func(b domain.InstanceBinding, id string) error{
		"UpdateStatusIfUnchanged": func(b domain.InstanceBinding, id string) error {
			return wis.UpdateStatusIfUnchanged(ctx, id, "acme", b, domain.InstanceStatusRevoked, "x")
		},
		"DeleteIfUnchanged": func(b domain.InstanceBinding, id string) error {
			return wis.DeleteIfUnchanged(ctx, id, "acme", b)
		},
		"DeleteIfRemovable": func(b domain.InstanceBinding, id string) error {
			return wis.DeleteIfRemovable(ctx, id, "acme", b)
		},
	}
	cases := []struct {
		name         string
		first, again *domain.UserID
	}{
		{"other-user", &alice, &bob},
		{"same-user", &alice, &alice},
		{"unowned-to-owned", nil, &bob},
		{"owned-to-unowned", &alice, nil},
		{"unowned-to-unowned", nil, nil},
	}
	for wname, do := range writes {
		for _, c := range cases {
			id := "cond-" + wname + "-" + c.name
			t.Run(wname+"/"+c.name, func(t *testing.T) {
				_ = wis.Delete(ctx, id)
				require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", UserID: c.first, Status: domain.InstanceStatusActive}))
				read := bindingOf(t, wis, id)
				require.NotEmpty(t, read.Generation)
				require.NoError(t, wis.DeleteIfUnchanged(ctx, id, "acme", read))
				require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: "acme", UserID: c.again, Status: domain.InstanceStatusActive}))

				require.ErrorIs(t, do(read, id), storage.ErrBindingChanged)

				got, err := wis.GetByID(ctx, id)
				require.NoError(t, err, "the replacement must survive")
				require.Equal(t, domain.InstanceStatusActive, got.Status)
				require.Nil(t, got.DeactivatedAt)
				require.NotEqual(t, read.Generation, got.Generation)
				_ = wis.Delete(ctx, id)
			})
		}
	}
}

func TestWalletInstanceStore_Conditional_MatchAndOwnerBind(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	alice := domain.UserIDFromString("cond-bind-alice")
	_ = wis.Delete(ctx, "cond-anon")

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: "cond-anon", TenantID: "acme", Status: domain.InstanceStatusActive}))
	unowned := bindingOf(t, wis, "cond-anon")
	require.ErrorIs(t, wis.UpdateStatusIfUnchanged(ctx, "cond-anon", "other", unowned, domain.InstanceStatusRevoked, "x"), storage.ErrNotFound)

	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: "cond-anon", TenantID: "acme", UserID: &alice, Status: domain.InstanceStatusActive}))
	require.ErrorIs(t, wis.UpdateStatusIfUnchanged(ctx, "cond-anon", "acme", unowned, domain.InstanceStatusRevoked, "x"), storage.ErrBindingChanged)
	require.ErrorIs(t, wis.DeleteIfUnchanged(ctx, "cond-anon", "acme", unowned), storage.ErrBindingChanged)

	fresh := bindingOf(t, wis, "cond-anon")
	require.Equal(t, unowned.Generation, fresh.Generation, "binding an owner must not change the generation")
	require.NoError(t, wis.UpdateStatusIfUnchanged(ctx, "cond-anon", "acme", fresh, domain.InstanceStatusRevoked, "x"))
	require.ErrorIs(t, wis.UpdateStatusIfUnchanged(ctx, "cond-anon", "acme", fresh, domain.InstanceStatusRevoked, "x"), domain.ErrInvalidStatusTransition)
	// A revoked, owned record is a tombstone for the removable delete, with
	// the right binding; with a stale one it is still ErrBindingChanged.
	require.ErrorIs(t, wis.DeleteIfRemovable(ctx, "cond-anon", "acme", fresh), domain.ErrInvalidStatusTransition)
	require.ErrorIs(t, wis.DeleteIfRemovable(ctx, "cond-anon", "acme", unowned), storage.ErrBindingChanged)
	require.NoError(t, wis.DeleteIfUnchanged(ctx, "cond-anon", "acme", fresh))
	require.ErrorIs(t, wis.DeleteIfUnchanged(ctx, "cond-anon", "acme", fresh), storage.ErrNotFound)
}

// A document written before generations existed has no generation field and
// is matched by an expected binding with none.
func TestWalletInstanceStore_Conditional_LegacyRecordWithoutGeneration(t *testing.T) {
	store := skipIfNoMongo(t)
	ctx := context.Background()
	wis := store.WalletInstances()
	coll := wis.(*WalletInstanceStore).collection
	_ = wis.Delete(ctx, "cond-legacy")
	_, err := coll.InsertOne(ctx, bson.M{"_id": "cond-legacy", "tenant_id": "acme", "status": "active"})
	require.NoError(t, err)

	b := bindingOf(t, wis, "cond-legacy")
	require.Empty(t, b.Generation)
	require.ErrorIs(t, wis.UpdateStatusIfUnchanged(ctx, "cond-legacy", "acme", domain.InstanceBinding{Generation: "g"}, domain.InstanceStatusRevoked, "x"), storage.ErrBindingChanged)
	require.NoError(t, wis.UpdateStatusIfUnchanged(ctx, "cond-legacy", "acme", b, domain.InstanceStatusRevoked, "x"))
}
