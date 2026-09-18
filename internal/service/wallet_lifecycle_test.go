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

func TestWalletLifecycle_SuspendBlocksWithoutErasing(t *testing.T) {
	svc, store, userID, sc := lifecycleFixture(t, domain.InstanceStatusActive)
	ctx := context.Background()

	inst, err := svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatusSuspended, "lost phone")
	require.NoError(t, err)
	assert.Equal(t, domain.InstanceStatusSuspended, inst.Status)
	assert.Equal(t, []string{userID.String()}, sc.users, "live sessions are dropped")

	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, []byte("encrypted-vault"), user.PrivateData, "suspension is reversible: nothing is erased")

	// Reactivation by the owner is a valid transition.
	inst, err = svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatusActive, "found it")
	require.NoError(t, err)
	assert.Equal(t, domain.InstanceStatusActive, inst.Status)
}

func TestWalletLifecycle_RevokingLastInstanceErasesWalletData(t *testing.T) {
	svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive, domain.InstanceStatusSuspended)
	ctx := context.Background()

	// One live (suspended, reactivatable) instance remains: no erasure yet.
	_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-a", domain.InstanceStatusRevoked, "compromised")
	require.NoError(t, err)
	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.NotNil(t, user.PrivateData, "a suspended instance could still be reactivated; data must stay")

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

// SID-AUTH-06: any change away from active also cuts off bearer tokens that
// were issued before it, since dropping sessions does not invalidate them.
func TestWalletLifecycle_StatusChangeCutsOffIssuedTokens(t *testing.T) {
	svc, store, userID, _ := lifecycleFixture(t, domain.InstanceStatusActive)
	ctx := context.Background()
	before := time.Now()

	_, err := svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatusSuspended, "lost phone")
	require.NoError(t, err)
	user, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.False(t, user.AuthInvalidBefore.IsZero(), "suspension records a token cut-off")
	assert.False(t, user.AuthInvalidBefore.Before(before))
	assert.Equal(t, []byte("encrypted-vault"), user.PrivateData, "suspension still erases nothing")
}

// A suspension whose cascade failed answers ErrErasureIncomplete; repeating
// the same request (same target status) must re-run the cascade, not answer
// success while the old sessions are still live.
func TestWalletLifecycle_SuspendedRetryRerunsCascade(t *testing.T) {
	svc, _, userID, sc := lifecycleFixture(t, domain.InstanceStatusActive)
	ctx := context.Background()
	sc.err = errors.New("session store down")

	inst, err := svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatusSuspended, "lost phone")
	require.True(t, errors.Is(err, ErrErasureIncomplete), "got %v", err)
	require.NotNil(t, inst)
	assert.Equal(t, domain.InstanceStatusSuspended, inst.Status, "the status change itself is persisted")
	assert.Empty(t, sc.users)

	sc.err = nil
	_, err = svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatusSuspended, "lost phone")
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
// scope of the cut-off: suspending one device of a two-device user cuts off
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

	_, err := svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatusSuspended, "lost phone")
	require.NoError(t, err)

	cutoff, err := store.Users().GetAuthCutoff(ctx, userID)
	require.NoError(t, err)
	assert.False(t, cutoff.IsZero(), "the user's tokens are cut off, not just the suspended instance's")
	assert.Equal(t, []string{userID.String()}, sc.users, "and every session of the user is dropped, not just that device's")

	other, err := store.WalletInstances().GetByID(ctx, "inst-b")
	require.NoError(t, err)
	assert.Equal(t, domain.InstanceStatusActive, other.Status,
		"the other instance keeps its status: it can log in again, it just cannot keep its session")
}
