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

type fakeSessionCleaner struct{ users []string }

func (f *fakeSessionCleaner) DeleteByUser(_ context.Context, userID string) error {
	f.users = append(f.users, userID)
	return nil
}

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
	_, err = store.Challenges().GetByID(ctx, "chal-1")
	assert.True(t, errors.Is(err, storage.ErrNotFound), "pending challenges are deleted")
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
