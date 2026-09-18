package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

type fakeSessionCleaner struct {
	users []string
	err   error // returned by DeleteByUser when set
}

func (f *fakeSessionCleaner) DeleteByUser(_ context.Context, userID string) error {
	if f.err != nil {
		return f.err
	}
	f.users = append(f.users, userID)
	return nil
}

// failAfterInstances lets the first UpdateStatus through and fails every
// later one, so a revoke-all can be made to fail part-way through (the
// memory store returns instances in no particular order).
type failAfterInstances struct {
	storage.WalletInstanceStore
	allowed string
}

func (f *failAfterInstances) UpdateStatus(ctx context.Context, id string, st domain.InstanceStatus, reason string) error {
	if f.allowed == "" {
		f.allowed = id
	}
	if id != f.allowed {
		return errors.New("db down")
	}
	return f.WalletInstanceStore.UpdateStatus(ctx, id, st, reason)
}

// storeWithInstances swaps the wallet-instance store of a storage.Store.
type storeWithInstances struct {
	storage.Store
	instances storage.WalletInstanceStore
}

func (s storeWithInstances) WalletInstances() storage.WalletInstanceStore { return s.instances }

// lifecycleFixture seeds a user with private data, a pending challenge and
// the given instances, all in the default tenant.
func lifecycleFixture(t *testing.T, statuses ...domain.InstanceStatus) (*WalletLifecycleService, storage.Store, domain.UserID, *fakeSessionCleaner) {
	t.Helper()
	store := memory.NewStore()
	ctx := context.Background()
	userID := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{
		UUID:            userID,
		DID:             "did:example:" + userID.String(),
		PrivateData:     []byte("encrypted-vault"),
		PrivateDataETag: "etag-1",
		Keys:            []byte("legacy-key-blob"),
	}))
	require.NoError(t, store.Challenges().Create(ctx, &domain.WebauthnChallenge{
		ID: "chal-1", UserID: userID.String(), Challenge: "c", Action: "login", ExpiresAt: time.Now().Add(time.Minute),
	}))
	for i, st := range statuses {
		require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "inst-" + string(rune('a'+i)), TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusActive,
		}))
		if st != domain.InstanceStatusActive {
			require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "inst-"+string(rune('a'+i)), st, "seed"))
		}
	}
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	sc := &fakeSessionCleaner{}
	svc.SetSessionCleaner(sc)
	return svc, store, userID, sc
}

func userActor(id domain.UserID) LifecycleActor { return LifecycleActor{Kind: "user", UserID: &id} }

// Revoking one instance of several drops the user's sessions but erases
// nothing: the wallet is only deactivated when no live instance is left
// anywhere. There is no reversible state to test here - revocation is the
// only status change a wallet instance has, and it cannot be undone.
func TestWalletLifecycle_RevokingOneOfSeveralBlocksWithoutErasing(t *testing.T) {
	svc, store, userID, sc := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusActive)
	ctx := context.Background()

	inst, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "lost phone")
	require.NoError(t, err)
	assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
	assert.Equal(t, []string{userID.String()}, sc.users, "live sessions are dropped")

	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, []byte("encrypted-vault"), user.PrivateData, "another instance is still live; nothing is erased")

	// And there is no way back.
	_, err = svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusActive, "found it")
	require.Error(t, err, "revocation cannot be undone")
}

func TestWalletLifecycle_RevokingLastInstanceErasesWalletData(t *testing.T) {
	svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusActive)
	ctx := context.Background()

	// One live instance remains: no erasure yet.
	_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "compromised")
	require.NoError(t, err)
	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.NotNil(t, user.PrivateData, "another instance is still live; data must stay")

	// Revoking the last one deactivates the wallet.
	_, err = svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-b", domain.InstanceStatusRevoked, "compromised")
	require.NoError(t, err)
	user, err = store.Users().GetByID(ctx, userID)
	require.NoError(t, err, "the user record itself is kept")
	assert.Nil(t, user.PrivateData)
	assert.Empty(t, user.PrivateDataETag)
	assert.Nil(t, user.Keys, "the legacy key blob is key material too")
	_, err = store.Challenges().GetByID(ctx, "chal-1")
	assert.True(t, errors.Is(err, storage.ErrNotFound), "pending challenges are deleted")
}

// Users registered without a DID have their credentials stored under the
// user id (the handlers' getHolderDID fallback); erasure must look there.
func TestWalletLifecycle_ErasureUsesUserIDForHolderWithoutDID(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	userID := domain.NewUserID()
	holder := userID.String()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: userID, PrivateData: []byte("vault")}))
	require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "inst-nodid", TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusActive,
	}))
	require.NoError(t, store.Credentials().Create(ctx, &domain.VerifiableCredential{
		TenantID: domain.DefaultTenantID, HolderDID: holder, CredentialIdentifier: "cred-1", Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
	}))
	require.NoError(t, store.Presentations().Create(ctx, &domain.VerifiablePresentation{
		TenantID: domain.DefaultTenantID, HolderDID: holder, PresentationIdentifier: "pres-1", Presentation: "jwt",
	}))

	n, err := svc.RevokeAllForUser(ctx, userActor(userID), domain.DefaultTenantID, userID, "deactivate")
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	creds, err := store.Credentials().GetAllByHolder(ctx, domain.DefaultTenantID, holder)
	if err != nil {
		require.True(t, errors.Is(err, storage.ErrNotFound), err)
	}
	assert.Empty(t, creds, "credentials stored under the user-id fallback are erased")
	pres, err := store.Presentations().GetAllByHolder(ctx, domain.DefaultTenantID, holder)
	if err != nil {
		require.True(t, errors.Is(err, storage.ErrNotFound), err)
	}
	assert.Empty(t, pres, "presentations stored under the user-id fallback are erased")
}

func TestWalletLifecycle_RevokeAllForUser(t *testing.T) {
	svc, store, userID, sc := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusActive, domain.InstanceStatusRevoked)
	ctx := context.Background()

	n, err := svc.RevokeAllForUser(ctx, userActor(userID), domain.DefaultTenantID, userID, "deactivate wallet")
	require.NoError(t, err)
	assert.Equal(t, 2, n, "already-revoked instances are not counted")

	instances, err := svc.ListForUser(ctx, domain.DefaultTenantID, userID)
	require.NoError(t, err)
	for _, inst := range instances {
		assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
	}
	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.Nil(t, user.PrivateData)
	assert.NotEmpty(t, sc.users)
}

func TestWalletLifecycle_OwnershipAndTransitions(t *testing.T) {
	svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive)
	ctx := context.Background()
	other := domain.NewUserID()

	_, err := svc.ChangeStatus(ctx, userActor(other), domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "")
	assert.True(t, errors.Is(err, ErrWalletInstanceNotOwned), "another user's instance cannot be changed")

	_, err = svc.ChangeStatus(ctx, userActor(userID), "other-tenant", "inst-a", domain.InstanceStatusRevoked, "")
	assert.True(t, errors.Is(err, storage.ErrNotFound), "wrong tenant reads as not found")

	_, err = svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "missing", domain.InstanceStatusRevoked, "")
	assert.True(t, errors.Is(err, storage.ErrNotFound))

	_, err = svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "")
	require.NoError(t, err)
	_, err = svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusActive, "")
	assert.True(t, errors.Is(err, domain.ErrInvalidStatusTransition), "revocation is terminal")

	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.Nil(t, user.PrivateData, "the single instance was revoked, so the wallet is deactivated")
}

// SID-AUTH-06: revoking an instance also cuts off bearer tokens that were
// issued before it, since dropping sessions does not invalidate them.
func TestWalletLifecycle_StatusChangeCutsOffIssuedTokens(t *testing.T) {
	svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusActive)
	ctx := context.Background()
	before := time.Now()

	_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "lost phone")
	require.NoError(t, err)
	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.False(t, user.AuthInvalidBefore.IsZero(), "revocation records a token cut-off")
	assert.False(t, user.AuthInvalidBefore.Before(before))
	assert.Equal(t, []byte("encrypted-vault"), user.PrivateData, "another instance is live, so nothing is erased")
}

// A revocation whose cascade failed answers ErrErasureIncomplete; repeating
// the same request (same target status) must re-run the cascade, not answer
// success while the old sessions are still live. Revocation is idempotent
// for exactly this reason: the retry finds the instance already revoked and
// still has to finish the work the first attempt left undone.
func TestWalletLifecycle_FailedCascadeRetryRerunsCascade(t *testing.T) {
	svc, _, userID, sc := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusActive)
	ctx := context.Background()
	sc.err = errors.New("session store down")

	inst, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "lost phone")
	require.True(t, errors.Is(err, ErrErasureIncomplete), "got %v", err)
	require.NotNil(t, inst)
	assert.Equal(t, domain.InstanceStatusRevoked, inst.Status, "the status change itself is persisted")
	assert.Empty(t, sc.users)

	sc.err = nil
	_, err = svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "lost phone")
	require.NoError(t, err)
	assert.Equal(t, []string{userID.String()}, sc.users, "the retry dropped the sessions")
}

// When revoke-all fails part-way, the instances already revoked must still
// get their cascade (tokens cut off, sessions dropped) instead of staying live
// until the retry; the not-yet-revoked instance keeps the erasure off.
func TestWalletLifecycle_RevokeAllPartialFailureStillCascades(t *testing.T) {
	svc, store, userID, sc := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusActive)
	ctx := context.Background()
	svc.store = storeWithInstances{Store: store, instances: &failAfterInstances{WalletInstanceStore: store.WalletInstances()}}

	n, err := svc.RevokeAllForUser(ctx, userActor(userID), domain.DefaultTenantID, userID, "deactivate")
	require.Error(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []string{userID.String()}, sc.users, "sessions dropped for the revocation that was persisted")
	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.False(t, user.AuthInvalidBefore.IsZero(), "issued tokens cut off")
	assert.Equal(t, []byte("encrypted-vault"), user.PrivateData, "one instance is still active, so nothing is erased")
}

// TestWalletLifecycle_CutOffIsUserWideNotInstanceScoped pins the documented
// scope of the cut-off: revoking one device of a two-device user cuts off
// that user's tokens and drops that user's sessions, so the other device is
// signed out too and has to authenticate again.
//
// This is wider than the change that caused it. It stays that way because a
// bearer token and a session record carry the user and the tenant and no
// wallet instance (see cutOffTokens), so there is nothing to narrow the
// cut-off with: a device whose token was not cut off would keep it until it
// expired, and nothing after login checks instance status. The test exists so
// the day an instance identity does survive login, this assertion is the one
// that has to be rewritten on purpose.
func TestWalletLifecycle_CutOffIsUserWideNotInstanceScoped(t *testing.T) {
	svc, store, userID, sc := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusActive)
	ctx := context.Background()

	_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "lost phone")
	require.NoError(t, err)

	cutoff, err := store.Users().GetAuthCutoff(ctx, userID)
	require.NoError(t, err)
	assert.False(t, cutoff.IsZero(), "the user's tokens are cut off, not just the revoked instance's")
	assert.Equal(t, []string{userID.String()}, sc.users, "and every session of the user is dropped, not just that device's")

	other, err := store.WalletInstances().GetByID(ctx, "inst-b")
	require.NoError(t, err)
	assert.Equal(t, domain.InstanceStatusActive, other.Status,
		"the other instance keeps its status: it can log in again, it just cannot keep its session")
}

// seedLegacySuspended inserts an instance already in the pre-removal
// "suspended" state, the way a record written by an earlier release sits in
// the database. It goes in through Upsert because the stores refuse to write
// that status any more - which is the point: it can be read, not created.
func seedLegacySuspended(t *testing.T, store storage.Store, id string, userID domain.UserID) {
	t.Helper()
	require.NoError(t, store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{
		ID: id, TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusLegacySuspended,
	}))
}

// TestWalletLifecycle_LegacySuspendedIsNotLive covers records written before
// suspension was removed. A suspended instance must be closable by an
// operator, must not count as a live instance of the wallet, and must not
// keep the wallet's data alive - otherwise removing the state would have
// silently upgraded every suspended device back to a working one.
func TestWalletLifecycle_LegacySuspendedIsNotLive(t *testing.T) {
	ctx := context.Background()

	t.Run("a suspended record can still be revoked", func(t *testing.T) {
		svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive)
		seedLegacySuspended(t, store, "inst-legacy", userID)

		inst, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-legacy", domain.InstanceStatusRevoked, "cleanup")
		require.NoError(t, err)
		assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
	})

	t.Run("a suspended record does not keep the wallet alive", func(t *testing.T) {
		svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive)
		seedLegacySuspended(t, store, "inst-legacy", userID)

		// Revoking the only live instance deactivates the wallet: the
		// suspended one cannot log in or attest, so nothing is left to use
		// the data.
		_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "compromised")
		require.NoError(t, err)
		user, err := store.Users().GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Nil(t, user.PrivateData, "no live instance remains, so the wallet data is erased")
	})

	t.Run("revoke-all sweeps a suspended record", func(t *testing.T) {
		svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive)
		seedLegacySuspended(t, store, "inst-legacy", userID)

		n, err := svc.RevokeAllForUser(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, userID, "cleanup")
		require.NoError(t, err)
		assert.Equal(t, 2, n, "both the active and the suspended instance are revoked")
		for _, id := range []string{"inst-a", "inst-legacy"} {
			got, err := store.WalletInstances().GetByID(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, domain.InstanceStatusRevoked, got.Status, id)
		}
	})
}

// A user actor may only sweep their own wallet.
func TestWalletLifecycle_RevokeAllRefusesAnotherUsersWallet(t *testing.T) {
	svc, _, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive)
	other := domain.NewUserID()

	n, err := svc.RevokeAllForUser(context.Background(), userActor(other), domain.DefaultTenantID, userID, "")
	assert.ErrorIs(t, err, ErrWalletInstanceNotOwned)
	assert.Zero(t, n)
}

// The cut-off is recorded before the status write, so a login already past
// its own lifecycle check can mint a token in between: it sees a live
// instance, and its fresh iat clears that first cut-off. Advancing the
// cut-off again after the write is what refuses such a token.
func TestWalletLifecycle_CutOffIsAdvancedAfterTheStatusWrite(t *testing.T) {
	svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusActive)
	ctx := context.Background()

	_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "stolen")
	require.NoError(t, err)

	// The status write is the moment the sliver closes: a login that got its
	// lifecycle check in before it saw a live instance. So the cut-off has
	// to sit at or after that write, not before it. With only the pre-write
	// cut-off this is false, and a token minted in between survives.
	revoked, err := store.WalletInstances().GetByID(ctx, "inst-a")
	require.NoError(t, err)
	cutoff, err := store.Users().GetAuthCutoff(ctx, userID)
	require.NoError(t, err)
	assert.False(t, cutoff.Before(revoked.UpdatedAt),
		"cut-off %s predates the status write at %s, so a token minted in between would still pass",
		cutoff, revoked.UpdatedAt)
}

// The account-deletion retry has to be able to find the tenant again. A
// membership removed while one of its instances is still there would hide
// that instance from the next attempt, which would then find nothing
// outstanding and delete the account over the top of the orphan.
func TestDeleteUser_KeepsMembershipWhenAnInstanceSurvives(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewStore()
	svc := NewUserService(failInstanceDeleteStore{Store: inner}, testConfig(), zap.NewNop())

	userID := domain.NewUserID()
	did := "did:example:" + userID.String()
	require.NoError(t, inner.Users().Create(ctx, &domain.User{UUID: userID, DID: did}))
	require.NoError(t, inner.UserTenants().AddMembership(ctx, &domain.UserTenantMembership{
		UserID: userID, TenantID: "acme", Role: "user",
	}))
	require.NoError(t, inner.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "inst-acme", TenantID: "acme", UserID: &userID, Status: domain.InstanceStatusActive,
	}))

	require.ErrorIs(t, svc.DeleteUser(ctx, userID, did), ErrDeletionIncomplete)

	tenants, err := inner.UserTenants().GetUserTenants(ctx, userID)
	require.NoError(t, err)
	assert.Contains(t, tenants, domain.TenantID("acme"),
		"the membership must survive so the retry can still find this tenant")
}
