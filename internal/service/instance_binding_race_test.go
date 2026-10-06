package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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

// hookGetInstances runs hook on the first GetByID of id, i.e. after the WIA
// request's user-exists check and before its instance write.
type hookGetInstances struct {
	storage.WalletInstanceStore
	id     string
	hook   func()
	once   sync.Once
	upsert func()
}

func (h *hookGetInstances) GetByID(ctx context.Context, id string) (*domain.WalletInstance, error) {
	if id == h.id && h.hook != nil {
		h.once.Do(h.hook)
	}
	return h.WalletInstanceStore.GetByID(ctx, id)
}

func (h *hookGetInstances) Upsert(ctx context.Context, in *domain.WalletInstance) error {
	if h.upsert != nil {
		h.upsert()
	}
	return h.WalletInstanceStore.Upsert(ctx, in)
}

func wireDeletionAndAttestation(t *testing.T, store storage.Store, instances storage.WalletInstanceStore) (*UserService, *WIAService) {
	t.Helper()
	lifecycle := NewWalletLifecycleService(store, zap.NewNop(), nil)
	userSvc := NewUserService(store, testConfig(), zap.NewNop())
	userSvc.SetUserLocker(lifecycle)
	wia := newTestWIAServiceUsingStores(t, instances, store.Users())
	wia.SetLifecycle(lifecycle)
	return userSvc, wia
}

// Thread 3, first interleaving: the account is deleted completely after the
// WIA request passed its user-exists check and before its instance write. The
// instance must not be bound to the deleted user.
func TestWIA_AccountDeletedAfterAdmissionLeavesNoOrphanInstance(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	uid := seedWalletUser(t, store)

	hooked := &hookGetInstances{WalletInstanceStore: store.WalletInstances()}
	userSvc, wia := wireDeletionAndAttestation(t, store, hooked)

	challenge, _, err := wia.CreateChallenge(ctx, domain.DefaultTenantID)
	require.NoError(t, err)
	pop, jkt := func() (string, string) {
		p, key := createTestPop(t, challenge)
		_, j := signTestPopWithKey(t, challenge, key)
		return p, j
	}()
	hooked.id = jkt
	hooked.hook = func() { require.NoError(t, userSvc.DeleteUser(ctx, uid, "did:example:"+uid.String())) }

	wiaToken, err := wia.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	require.Error(t, err, "a WIA must not be issued to a deleted account")
	assert.Empty(t, wiaToken)

	all, err := store.WalletInstances().GetAllByUser(ctx, uid)
	require.NoError(t, err)
	assert.Empty(t, all, "no instance may outlive the account")
	_, err = store.WalletInstances().GetByID(ctx, jkt)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// Thread 3, second interleaving: the request is already inside its critical
// section (holding the user's lock, about to write the instance) when the
// deletion reaches its final sweep. The deletion must wait for the request and
// then sweep the instance the request bound.
func TestDeleteUser_WaitsForAnAttestationInsideItsCriticalSection(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	uid := seedWalletUser(t, store)

	hooked := &hookGetInstances{WalletInstanceStore: store.WalletInstances()}
	userSvc, wia := wireDeletionAndAttestation(t, store, hooked)

	done := make(chan error, 1)
	hooked.upsert = func() {
		go func() { done <- userSvc.DeleteUser(ctx, uid, "did:example:"+uid.String()) }()
		select {
		case err := <-done:
			t.Errorf("DeleteUser finished (%v) while an attestation held the user's lock", err)
			done <- err
		case <-time.After(200 * time.Millisecond):
		}
	}

	challenge, _, err := wia.CreateChallenge(ctx, domain.DefaultTenantID)
	require.NoError(t, err)
	pop, _ := createTestPop(t, challenge)
	_, err = wia.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	// The request's last cut-off check may legitimately refuse the WIA once
	// the deletion has run; what matters is the end state.
	_ = err

	select {
	case derr := <-done:
		require.NoError(t, derr)
	case <-time.After(5 * time.Second):
		t.Fatal("DeleteUser never finished")
	}
	all, gerr := store.WalletInstances().GetAllByUser(ctx, uid)
	require.NoError(t, gerr)
	assert.Empty(t, all, "the instance bound during the deletion must be swept before the user record goes")
	_, uerr := store.Users().GetByID(ctx, uid)
	assert.True(t, errors.Is(uerr, storage.ErrNotFound), "the account must be gone, got %v", uerr)
}

// afterWriteInstances runs hook right after the first successful conditional
// status write for id: the record the write revoked is then replaced.
type afterWriteInstances struct {
	storage.WalletInstanceStore
	match string
	hook  func()
	fired bool
}

func (a *afterWriteInstances) UpdateStatusIfUnchanged(ctx context.Context, id string, tenantID domain.TenantID, exp domain.InstanceBinding, st domain.InstanceStatus, reason string) error {
	if err := a.WalletInstanceStore.UpdateStatusIfUnchanged(ctx, id, tenantID, exp, st, reason); err != nil {
		return err
	}
	if !a.fired && id == a.match {
		a.fired = true
		a.hook()
	}
	return nil
}

// After the conditional status write the revoked record can be gone and its
// id taken by a replacement of another user (account deletion removed it, a
// concurrent attestation inserted the same thumbprint). That is a lost binding:
// no cut-off and no cascade may run, neither against the replacement's owner
// nor against the stale pre-write owner.
func TestChangeStatus_ReplacementAfterTheWriteRunsNoCascade(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore()
	alice := seedWalletUser(t, base, domain.DefaultTenantID)
	bob := seedWalletUser(t, base, domain.DefaultTenantID)
	id := "shared-thumbprint"
	require.NoError(t, base.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: id, TenantID: domain.DefaultTenantID, UserID: &alice, Status: domain.InstanceStatusActive}))
	aliceCutoff, err := base.Users().GetAuthCutoff(ctx, alice)
	require.NoError(t, err)

	hooked := &afterWriteInstances{WalletInstanceStore: base.WalletInstances(), match: id}
	hooked.hook = func() { replaceInstance(t, base.WalletInstances(), id, domain.DefaultTenantID, &bob) }
	svc := NewWalletLifecycleService(&racingInstanceStore{Store: base, instances: hooked}, zap.NewNop(), nil)
	cleaner := &fakeSessionCleaner{}
	svc.SetSessionCleaner(cleaner)

	_, err = svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "lost")
	require.ErrorIs(t, err, ErrErasureIncomplete, "the lost binding is reported, not swallowed")

	got, err := base.WalletInstances().GetByID(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, domain.InstanceStatusActive, got.Status, "the replacement must not be touched")
	require.NotNil(t, got.UserID)
	assert.Equal(t, bob, *got.UserID)
	assert.Empty(t, cleaner.users, "no session cleanup for anybody")
	creds, pres := countHolderData(t, base, domain.DefaultTenantID, bob)
	assert.NotZero(t, creds+pres, "bob's wallet data must not be erased")
	acreds, apres := countHolderData(t, base, domain.DefaultTenantID, alice)
	assert.NotZero(t, acreds+apres, "no cascade ran against the stale pre-write owner either")
	for _, u := range []domain.UserID{alice, bob} {
		c, err := base.Users().GetAuthCutoff(ctx, u)
		require.NoError(t, err)
		if u == alice {
			assert.True(t, c.Equal(aliceCutoff), "no token cut-off for the stale owner")
		} else {
			assert.True(t, c.IsZero(), "no token cut-off for the replacement's owner")
		}
	}
}
