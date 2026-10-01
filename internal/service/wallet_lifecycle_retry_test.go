package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

var providerActor = LifecycleActor{Kind: "provider"}

// The cut-off recorded after the status write can fail; the revocation is
// then persisted with a cut-off that predates it. Repeating the request must
// notice and advance the cut-off, or tokens minted in between stay valid
// forever.
func TestChangeStatus_RetryAdvancesACutoffThatPredatesTheRevocation(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore().failOnCalls("users.InvalidateAuthBefore", 1, 2)
	svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
	uid := seedWalletUser(t, fs.Store)
	// Calls 1 and 2 fail: the cut-off after the write, and the cascade's own repair of it.
	// A second live instance keeps the wallet alive, so no erasure advances
	// the cut-off behind the test's back.
	require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "inst-2", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
	}))
	id := "inst-" + uid.String()

	_, err := svc.ChangeStatus(ctx, providerActor, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "stolen")
	require.ErrorIs(t, err, ErrErasureIncomplete, "the second cut-off failed after the status was persisted")
	inst, gerr := fs.Store.WalletInstances().GetByID(ctx, id)
	require.NoError(t, gerr)
	require.Equal(t, domain.InstanceStatusRevoked, inst.Status)
	stale, gerr := fs.Store.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, gerr)
	require.True(t, stale.Before(*inst.DeactivatedAt), "the recorded cut-off predates the revocation")

	_, err = svc.ChangeStatus(ctx, providerActor, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "stolen")
	require.NoError(t, err)
	fresh, gerr := fs.Store.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, gerr)
	assert.False(t, fresh.Before(*inst.DeactivatedAt), "the retry advanced the cut-off past the revocation")
	assert.ErrorIs(t, tokengate.New(fs.Store.Users()).Check(ctx, uid.String(), inst.DeactivatedAt.Add(-1)), tokengate.ErrRevoked)

	// A further retry after a complete cascade leaves the cut-off alone.
	_, err = svc.ChangeStatus(ctx, providerActor, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "stolen")
	require.NoError(t, err)
	again, _ := fs.Store.Users().GetAuthCutoff(ctx, uid)
	assert.True(t, again.Equal(fresh), "a no-op retry must not invalidate tokens issued since")
}

func TestChangeStatus_RetryReportsAFailingCutoff(t *testing.T) {
	ctx := context.Background()
	newFixture := func(t *testing.T) (*WalletLifecycleService, *failStore, string) {
		fs := newFailStore().failOnCalls("users.InvalidateAuthBefore", 1, 2)
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs.Store)
		require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "inst-2", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
		}))
		id := "inst-" + uid.String()
		_, err := svc.ChangeStatus(ctx, providerActor, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "x")
		require.ErrorIs(t, err, ErrErasureIncomplete)
		return svc, fs, id
	}

	t.Run("re-cut fails", func(t *testing.T) {
		svc, fs, id := newFixture(t)
		fs.failNth = nil
		fs.fail["users.InvalidateAuthBefore"] = true
		_, err := svc.ChangeStatus(ctx, providerActor, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "x")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
	})
	t.Run("cut-off unreadable", func(t *testing.T) {
		svc, fs, id := newFixture(t)
		fs.fail["users.GetAuthCutoff"] = true
		_, err := svc.ChangeStatus(ctx, providerActor, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "x")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
	})
}

func TestRevokeAllForUser_FailuresAfterPersistedRevocationsAreIncomplete(t *testing.T) {
	ctx := context.Background()

	t.Run("nothing to revoke", func(t *testing.T) {
		svc := NewWalletLifecycleService(newFailStore(), zap.NewNop(), nil)
		n, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, domain.NewUserID(), "x")
		require.NoError(t, err)
		assert.Zero(t, n)
	})
	t.Run("the cut-off after the sweep fails", func(t *testing.T) {
		fs := newFailStore().failOnCall("users.InvalidateAuthBefore", 1)
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs.Store)
		n, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
		assert.Equal(t, 1, n, "the revocation itself was persisted")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
	})
	t.Run("a later listing fails", func(t *testing.T) {
		fs := newFailStore().failOnCall("instances.GetByUser", 2)
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs.Store)
		n, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
		assert.Equal(t, 1, n)
		assert.ErrorIs(t, err, ErrErasureIncomplete)
	})
	t.Run("the check for unswept instances fails", func(t *testing.T) {
		fs := newFailStore().failOnCall("instances.GetByUser", 4)
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs.Store)
		_, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
	})
}

// cascade runs for statuses persisted elsewhere too, so it establishes a
// cut-off when there is none, and must say so when it cannot.
func TestCascade_EnsuresACutoffAndReportsWhenItCannot(t *testing.T) {
	ctx := context.Background()
	revoked := func(t *testing.T, fs *failStore) (*WalletLifecycleService, *domain.WalletInstance, domain.UserID) {
		uid := seedWalletUser(t, fs.Store)
		id := "inst-" + uid.String()
		require.NoError(t, fs.Store.WalletInstances().UpdateStatus(ctx, id, domain.DefaultTenantID, domain.InstanceStatusRevoked, "elsewhere"))
		inst, err := fs.Store.WalletInstances().GetByID(ctx, id)
		require.NoError(t, err)
		return NewWalletLifecycleService(fs, zap.NewNop(), nil), inst, uid
	}

	t.Run("no cut-off yet: one is recorded", func(t *testing.T) {
		fs := newFailStore()
		svc, inst, uid := revoked(t, fs)
		require.NoError(t, svc.cascade(ctx, domain.DefaultTenantID, inst, providerActor))
		c, err := fs.Store.Users().GetAuthCutoff(ctx, uid)
		require.NoError(t, err)
		assert.False(t, c.IsZero())
	})
	t.Run("cut-off unreadable", func(t *testing.T) {
		fs := newFailStore("users.GetAuthCutoff")
		svc, inst, _ := revoked(t, fs)
		assert.ErrorIs(t, svc.cascade(ctx, domain.DefaultTenantID, inst, providerActor), ErrErasureIncomplete)
	})
	t.Run("cut-off cannot be recorded", func(t *testing.T) {
		fs := newFailStore("users.InvalidateAuthBefore")
		svc, inst, _ := revoked(t, fs)
		assert.ErrorIs(t, svc.cascade(ctx, domain.DefaultTenantID, inst, providerActor), ErrErasureIncomplete)
	})
}

// Erasure must not run on a guess about where the user's other instances are.
func TestEraseWalletData_FailsClosedWhenOtherTenantsCannotBeSeen(t *testing.T) {
	ctx := context.Background()

	t.Run("instances of the user cannot be listed", func(t *testing.T) {
		fs := newFailStore("instances.GetAllByUser")
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs.Store)
		errs := svc.eraseWalletData(ctx, domain.DefaultTenantID, uid)
		assert.NotEmpty(t, errs)
		u, err := fs.Store.Users().GetByID(ctx, uid)
		require.NoError(t, err)
		assert.NotEmpty(t, u.PrivateData, "the vault must survive when liveness elsewhere is unknown")
	})
	t.Run("another tenant's instances cannot be listed", func(t *testing.T) {
		// Call 1 is the default tenant, call 2 the membership tenant.
		fs := newFailStore().failOnCall("instances.GetByUser", 1)
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs.Store, domain.DefaultTenantID, "acme")
		errs := svc.eraseWalletData(ctx, "acme", uid)
		assert.NotEmpty(t, errs)
		u, err := fs.Store.Users().GetByID(ctx, uid)
		require.NoError(t, err)
		assert.NotEmpty(t, u.PrivateData, "a listing failure counts as live: the vault stays")
	})
}

// A revoke-all whose cut-off after the sweep failed leaves every instance
// revoked and a cut-off that predates the last revocation. Repeating it
// changes nothing, so it must still repair the cut-off before it reports
// success; cascade only fills a missing one.
func TestRevokeAllForUser_RetryRepairsAStaleCutoff(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore().failOnCalls("users.InvalidateAuthBefore", 1, 2)
	svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
	uid := seedWalletUser(t, fs.Store)
	// A live instance in another tenant keeps the vault, so no erasure
	// advances the cut-off behind the test's back.
	require.NoError(t, fs.Store.UserTenants().AddMembership(ctx, &domain.UserTenantMembership{UserID: uid, TenantID: "acme", Role: "user"}))
	require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "elsewhere", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive,
	}))

	n, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
	require.ErrorIs(t, err, ErrErasureIncomplete)
	require.Equal(t, 1, n)
	inst, gerr := fs.Store.WalletInstances().GetByID(ctx, "inst-"+uid.String())
	require.NoError(t, gerr)
	stale, _ := fs.Store.Users().GetAuthCutoff(ctx, uid)
	require.True(t, stale.Before(*inst.DeactivatedAt), "the first attempt left a cut-off older than the revocation")

	n, err = svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
	require.NoError(t, err)
	assert.Zero(t, n, "nothing left to revoke")
	fresh, _ := fs.Store.Users().GetAuthCutoff(ctx, uid)
	assert.False(t, fresh.Before(*inst.DeactivatedAt), "the retry advanced the cut-off past the revocation")

	again, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
	require.NoError(t, err)
	assert.Zero(t, again)
	same, _ := fs.Store.Users().GetAuthCutoff(ctx, uid)
	assert.True(t, same.Equal(fresh), "a further no-op retry leaves the cut-off alone")

	t.Run("a failing repair is reported", func(t *testing.T) {
		fs := newFailStore().failOnCalls("users.InvalidateAuthBefore", 1, 2)
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs.Store)
		require.NoError(t, fs.Store.UserTenants().AddMembership(ctx, &domain.UserTenantMembership{UserID: uid, TenantID: "acme", Role: "user"}))
		require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: "e2", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive}))
		_, err := svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
		require.ErrorIs(t, err, ErrErasureIncomplete)
		fs.failNth = nil
		fs.fail["users.InvalidateAuthBefore"] = true
		_, err = svc.RevokeAllForUser(ctx, providerActor, domain.DefaultTenantID, uid, "x")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
	})
}

func TestLatestRevoked(t *testing.T) {
	now := time.Now()
	older, newer := now.Add(-time.Hour), now
	a := &domain.WalletInstance{ID: "a", DeactivatedAt: &newer}
	b := &domain.WalletInstance{ID: "b", DeactivatedAt: &older}
	c := &domain.WalletInstance{ID: "c"}
	assert.Equal(t, "a", latestRevoked([]*domain.WalletInstance{b, a, c}).ID)
	assert.Equal(t, "b", latestRevoked([]*domain.WalletInstance{b, c}).ID, "an instance with a recorded revocation beats one without")
	assert.Equal(t, "c", latestRevoked([]*domain.WalletInstance{c}).ID, "none recorded: the last listed")
}
