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

// replaceInstance models the race every test here is about: the record is
// deleted and the same thumbprint attested again, by another user of the same
// tenant, between a caller's read and its write. It uses the store's own
// operations, so the replacement gets a generation of its own.
func replaceInstance(t *testing.T, wis storage.WalletInstanceStore, id string, tenant domain.TenantID, newOwner *domain.UserID) {
	t.Helper()
	ctx := context.Background()
	cur, err := wis.GetByID(ctx, id)
	require.NoError(t, err)
	require.NoError(t, wis.DeleteIfUnchanged(ctx, id, tenant, cur.Binding()))
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: tenant, UserID: newOwner, Status: domain.InstanceStatusActive}))
}

// beforeWriteInstances runs hook just before the first conditional status
// write whose id matches (every id when match is empty).
type beforeWriteInstances struct {
	storage.WalletInstanceStore
	match string
	skip  string
	hook  func()
	fired bool
}

func (b *beforeWriteInstances) UpdateStatusIfUnchanged(ctx context.Context, id string, tenantID domain.TenantID, exp domain.InstanceBinding, st domain.InstanceStatus, reason string) error {
	if !b.fired && (b.match == "" || id == b.match) && id != b.skip {
		b.fired = true
		b.hook()
	}
	return b.WalletInstanceStore.UpdateStatusIfUnchanged(ctx, id, tenantID, exp, st, reason)
}

func (b *beforeWriteInstances) DeleteIfRemovable(ctx context.Context, id string, tenantID domain.TenantID, exp domain.InstanceBinding) error {
	if !b.fired && (b.match == "" || id == b.match) {
		b.fired = true
		b.hook()
	}
	return b.WalletInstanceStore.DeleteIfRemovable(ctx, id, tenantID, exp)
}

// Thread 2: ChangeStatus must not revoke, or cascade against the owner of, a
// replacement that appeared between its read and its write.
func TestChangeStatus_ReplacementBetweenReadAndWriteIsNotRevoked(t *testing.T) {
	for name, firstOwner := range map[string]bool{"owned original": true, "unowned original": false} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			base := memory.NewStore()
			alice := seedWalletUser(t, base)
			bob := seedWalletUser(t, base, domain.DefaultTenantID)
			id := "shared-thumbprint"
			var first *domain.UserID
			if firstOwner {
				first = &alice
			}
			require.NoError(t, base.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: domain.DefaultTenantID, UserID: first, Status: domain.InstanceStatusActive}))

			hooked := &beforeWriteInstances{WalletInstanceStore: base.WalletInstances(), match: id}
			hooked.hook = func() { replaceInstance(t, base.WalletInstances(), id, domain.DefaultTenantID, &bob) }
			svc := NewWalletLifecycleService(&racingInstanceStore{Store: base, instances: hooked}, zap.NewNop(), nil)
			cleaner := &fakeSessionCleaner{}
			svc.SetSessionCleaner(cleaner)

			_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "lost")
			require.ErrorIs(t, err, storage.ErrNotFound)

			got, err := base.WalletInstances().GetByID(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, domain.InstanceStatusActive, got.Status, "the replacement must not be revoked")
			assert.Nil(t, got.DeactivatedAt)
			require.NotNil(t, got.UserID)
			assert.Equal(t, bob, *got.UserID)
			assert.NotContains(t, cleaner.users, bob.String(), "no cascade may run against the replacement's owner")
			creds, pres := countHolderData(t, base, domain.DefaultTenantID, bob)
			assert.NotZero(t, creds+pres, "bob's wallet data must not be erased")
		})
	}
}

// Thread 1: the admin delete must not remove a replacement that is live and
// passes the removability test.
func TestAdminStyleDeleteIfRemovable_ReplacementBetweenReadAndDeleteSurvives(t *testing.T) {
	ctx := context.Background()
	wis := memory.NewStore().WalletInstances()
	alice := domain.UserIDFromString("alice")
	bob := domain.UserIDFromString("bob")
	require.NoError(t, wis.Upsert(ctx, &domain.WalletInstance{ID: "t", TenantID: "acme", UserID: &alice, Status: domain.InstanceStatusActive}))
	read, err := wis.GetByID(ctx, "t")
	require.NoError(t, err)

	replaceInstance(t, wis, "t", "acme", &bob)

	err = wis.DeleteIfRemovable(ctx, "t", "acme", read.Binding())
	require.ErrorIs(t, err, storage.ErrBindingChanged)
	got, err := wis.GetByID(ctx, "t")
	require.NoError(t, err)
	assert.Equal(t, bob, *got.UserID)
}

// Thread 4: the compensating revocation of a raced first attestation must
// treat a replacement as a non-owned race and leave it alone.
func TestWIA_CompensatingRevocation_ReplacementIsNotRevoked(t *testing.T) {
	ctx := context.Background()
	alice := domain.UserIDFromString("user-compensate")
	bob := domain.UserIDFromString("user-replacement")
	base := memory.NewStore().WalletInstances()
	seedWIAInstance(t, base, "old-key", alice, domain.InstanceStatusActive)

	// old-key is revoked right after the new key is inserted (a deactivation
	// landing mid-attestation), so the compensating path runs; then the new
	// key's record is replaced by bob's just before that revocation is written.
	racing := &racingRevokeInstances{WalletInstanceStore: base, userID: alice}
	var newID string
	hooked := &beforeWriteInstances{WalletInstanceStore: racing, skip: "old-key"}
	hooked.hook = func() {
		all, err := base.GetByUser(ctx, domain.DefaultTenantID, alice)
		require.NoError(t, err)
		for _, in := range all {
			if in.ID != "old-key" {
				newID = in.ID
			}
		}
		require.NotEmpty(t, newID)
		replaceInstance(t, base, newID, domain.DefaultTenantID, &bob)
	}
	svc := newTestWIAServiceUsing(t, hooked)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	require.NoError(t, err)
	pop, _ := createTestPop(t, challenge)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &alice, &WIARequest{Pop: pop, Challenge: challenge})
	require.True(t, hooked.fired, "the compensating write must have been attempted")
	require.ErrorIs(t, err, ErrWIAInstanceNotOwned)

	got, err := base.GetByID(ctx, newID)
	require.NoError(t, err)
	assert.Equal(t, domain.InstanceStatusActive, got.Status, "the replacement must not be revoked by the old attestation's cleanup")
	require.NotNil(t, got.UserID)
	assert.Equal(t, bob, *got.UserID)
}

// RevokeAll works from a per-user listing; a record replaced after the
// listing, even by the same user, is not the one listed.
func TestRevokeAll_ReplacementAfterListingIsNotRevoked(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore()
	alice := seedWalletUser(t, base)
	bob := seedWalletUser(t, base, domain.DefaultTenantID)
	seeded := "inst-" + alice.String()

	hooked := &beforeWriteInstances{WalletInstanceStore: base.WalletInstances(), match: seeded}
	hooked.hook = func() { replaceInstance(t, base.WalletInstances(), seeded, domain.DefaultTenantID, &bob) }
	svc := NewWalletLifecycleService(&racingInstanceStore{Store: base, instances: hooked}, zap.NewNop(), nil)

	_, err := svc.RevokeAllForUser(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, alice, "x")
	require.Error(t, err, "the sweep did not complete: it must say so")
	got, gerr := base.WalletInstances().GetByID(ctx, seeded)
	require.NoError(t, gerr)
	assert.Equal(t, domain.InstanceStatusActive, got.Status)
	assert.Equal(t, bob, *got.UserID)
}
