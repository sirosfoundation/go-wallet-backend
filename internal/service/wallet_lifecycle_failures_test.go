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

var errBoom = errors.New("boom")

// failStore wraps the memory store and makes the named operations fail, so
// the lifecycle service's error branches (which must log and continue, or
// stop, as documented) can be exercised.
type failStore struct {
	storage.Store
	fail map[string]bool
}

func newFailStore(ops ...string) *failStore {
	f := &failStore{Store: memory.NewStore(), fail: map[string]bool{}}
	for _, op := range ops {
		f.fail[op] = true
	}
	return f
}

func (f *failStore) err(op string) error {
	if f.fail[op] {
		return errBoom
	}
	return nil
}

func (f *failStore) WalletInstances() storage.WalletInstanceStore {
	return &failInstances{f.Store.WalletInstances(), f}
}
func (f *failStore) Users() storage.UserStore { return &failUsers{f.Store.Users(), f} }
func (f *failStore) UserTenants() storage.UserTenantStore {
	return &failUserTenants{f.Store.UserTenants(), f}
}
func (f *failStore) Credentials() storage.CredentialStore {
	return &failCredentials{f.Store.Credentials(), f}
}
func (f *failStore) Presentations() storage.PresentationStore {
	return &failPresentations{f.Store.Presentations(), f}
}
func (f *failStore) Challenges() storage.ChallengeStore {
	return &failChallenges{f.Store.Challenges(), f}
}

type failInstances struct {
	storage.WalletInstanceStore
	f *failStore
}

func (s *failInstances) GetByUser(ctx context.Context, t domain.TenantID, u domain.UserID) ([]*domain.WalletInstance, error) {
	if err := s.f.err("instances.GetByUser"); err != nil {
		return nil, err
	}
	return s.WalletInstanceStore.GetByUser(ctx, t, u)
}

func (s *failInstances) UpdateStatus(ctx context.Context, id string, st domain.InstanceStatus, reason string) error {
	if err := s.f.err("instances.UpdateStatus"); err != nil {
		return err
	}
	return s.WalletInstanceStore.UpdateStatus(ctx, id, st, reason)
}

type failUsers struct {
	storage.UserStore
	f *failStore
}

func (s *failUsers) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	if err := s.f.err("users.GetByID"); err != nil {
		return nil, err
	}
	return s.UserStore.GetByID(ctx, id)
}

func (s *failUsers) Update(ctx context.Context, u *domain.User) error {
	if err := s.f.err("users.Update"); err != nil {
		return err
	}
	return s.UserStore.Update(ctx, u)
}

type failUserTenants struct {
	storage.UserTenantStore
	f *failStore
}

func (s *failUserTenants) GetUserTenants(ctx context.Context, id domain.UserID) ([]domain.TenantID, error) {
	if err := s.f.err("usertenants.GetUserTenants"); err != nil {
		return nil, err
	}
	return s.UserTenantStore.GetUserTenants(ctx, id)
}

type failCredentials struct {
	storage.CredentialStore
	f *failStore
}

func (s *failCredentials) GetAllByHolder(ctx context.Context, t domain.TenantID, did string) ([]*domain.VerifiableCredential, error) {
	if err := s.f.err("credentials.GetAllByHolder"); err != nil {
		return nil, err
	}
	return s.CredentialStore.GetAllByHolder(ctx, t, did)
}

func (s *failCredentials) Delete(ctx context.Context, t domain.TenantID, did, id string) error {
	if err := s.f.err("credentials.Delete"); err != nil {
		return err
	}
	return s.CredentialStore.Delete(ctx, t, did, id)
}

type failPresentations struct {
	storage.PresentationStore
	f *failStore
}

func (s *failPresentations) GetAllByHolder(ctx context.Context, t domain.TenantID, did string) ([]*domain.VerifiablePresentation, error) {
	if err := s.f.err("presentations.GetAllByHolder"); err != nil {
		return nil, err
	}
	return s.PresentationStore.GetAllByHolder(ctx, t, did)
}

func (s *failPresentations) Delete(ctx context.Context, t domain.TenantID, did, id string) error {
	if err := s.f.err("presentations.Delete"); err != nil {
		return err
	}
	return s.PresentationStore.Delete(ctx, t, did, id)
}

type failChallenges struct {
	storage.ChallengeStore
	f *failStore
}

func (s *failChallenges) DeleteByUserID(ctx context.Context, id string) error {
	if err := s.f.err("challenges.DeleteByUserID"); err != nil {
		return err
	}
	return s.ChallengeStore.DeleteByUserID(ctx, id)
}

type erroringSessionCleaner struct{}

func (erroringSessionCleaner) DeleteByUser(context.Context, string) error { return errBoom }

// seedWalletUser creates a user with a DID, private data, a challenge, one
// active instance, and credentials/presentations in the given tenants.
func seedWalletUser(t *testing.T, store storage.Store, tenants ...domain.TenantID) domain.UserID {
	t.Helper()
	ctx := context.Background()
	userID := domain.NewUserID()
	did := "did:example:" + userID.String()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: userID, DID: did, PrivateData: []byte("vault"), PrivateDataETag: "e1"}))
	require.NoError(t, store.Challenges().Create(ctx, &domain.WebauthnChallenge{
		ID: "chal-" + userID.String(), UserID: userID.String(), Challenge: "c", Action: "login", ExpiresAt: time.Now().Add(time.Minute),
	}))
	require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "inst-" + userID.String(), TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusActive,
	}))
	for _, tid := range tenants {
		if tid != domain.DefaultTenantID {
			require.NoError(t, store.UserTenants().AddMembership(ctx, &domain.UserTenantMembership{UserID: userID, TenantID: tid, Role: "user"}))
		}
		require.NoError(t, store.Credentials().Create(ctx, &domain.VerifiableCredential{
			TenantID: tid, HolderDID: did, CredentialIdentifier: "cred-" + string(tid), Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
		}))
		require.NoError(t, store.Presentations().Create(ctx, &domain.VerifiablePresentation{
			TenantID: tid, HolderDID: did, PresentationIdentifier: "pres-" + string(tid), Presentation: "jwt",
		}))
	}
	return userID
}

func countHolderData(t *testing.T, store storage.Store, tid domain.TenantID, userID domain.UserID) (int, int) {
	t.Helper()
	ctx := context.Background()
	did := "did:example:" + userID.String()
	creds, err := store.Credentials().GetAllByHolder(ctx, tid, did)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
	pres, err := store.Presentations().GetAllByHolder(ctx, tid, did)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		t.Fatal(err)
	}
	return len(creds), len(pres)
}

func TestWalletLifecycle_ListForUser_EmptyAndError(t *testing.T) {
	ctx := context.Background()
	svc := NewWalletLifecycleService(memory.NewStore(), zap.NewNop(), nil)
	list, err := svc.ListForUser(ctx, domain.DefaultTenantID, domain.NewUserID())
	require.NoError(t, err)
	assert.NotNil(t, list, "a user without instances gets an empty list, not null")
	assert.Empty(t, list)

	failing := NewWalletLifecycleService(newFailStore("instances.GetByUser"), zap.NewNop(), nil)
	_, err = failing.ListForUser(ctx, domain.DefaultTenantID, domain.NewUserID())
	assert.ErrorIs(t, err, errBoom)
}

func TestWalletLifecycle_ChangeStatus_NoOpAndInvalid(t *testing.T) {
	svc, _, userID, sc := lifecycleFixture(t, domain.InstanceStatusActive)
	ctx := context.Background()

	inst, err := svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatusActive, "")
	require.NoError(t, err, "same status is a no-op")
	assert.Equal(t, domain.InstanceStatusActive, inst.Status)
	assert.Empty(t, sc.users, "a no-op does not drop sessions")

	_, err = svc.ChangeStatus(ctx, userActor(userID), domain.DefaultTenantID, "inst-a", domain.InstanceStatus("bogus"), "")
	assert.ErrorIs(t, err, domain.ErrInvalidStatusTransition)

	_, err = svc.ChangeStatus(ctx, userActor(userID), "other-tenant", "inst-a", domain.InstanceStatusSuspended, "")
	assert.ErrorIs(t, err, storage.ErrNotFound, "an instance of another tenant is not found")

	failing := NewWalletLifecycleService(newFailStore("instances.UpdateStatus"), zap.NewNop(), nil)
	uid := seedWalletUser(t, failing.store)
	_, err = failing.ChangeStatus(ctx, userActor(uid), domain.DefaultTenantID, "inst-"+uid.String(), domain.InstanceStatusSuspended, "")
	assert.ErrorIs(t, err, errBoom)
}

func TestWalletLifecycle_Cascade_UnownedInstanceAndErrorsDoNotErase(t *testing.T) {
	ctx := context.Background()
	provider := LifecycleActor{Kind: "provider"}

	t.Run("instance without a user: nothing to cascade", func(t *testing.T) {
		svc := NewWalletLifecycleService(memory.NewStore(), zap.NewNop(), nil)
		require.NoError(t, svc.store.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: "anon", TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive}))
		inst, err := svc.ChangeStatus(ctx, provider, domain.DefaultTenantID, "anon", domain.InstanceStatusRevoked, "")
		require.NoError(t, err)
		assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
	})

	t.Run("session drop failure is logged, erasure still runs", func(t *testing.T) {
		store := memory.NewStore()
		svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
		svc.SetSessionCleaner(erroringSessionCleaner{})
		uid := seedWalletUser(t, store, domain.DefaultTenantID)
		_, err := svc.ChangeStatus(ctx, provider, domain.DefaultTenantID, "inst-"+uid.String(), domain.InstanceStatusRevoked, "")
		require.NoError(t, err)
		user, _ := store.Users().GetByID(ctx, uid)
		assert.Nil(t, user.PrivateData)
	})

	t.Run("cannot list remaining instances: wallet data is kept", func(t *testing.T) {
		fs := newFailStore()
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs, domain.DefaultTenantID)
		fs.fail["instances.GetByUser"] = true
		_, err := svc.ChangeStatus(ctx, provider, domain.DefaultTenantID, "inst-"+uid.String(), domain.InstanceStatusRevoked, "")
		require.NoError(t, err)
		user, _ := fs.Store.Users().GetByID(ctx, uid)
		assert.NotNil(t, user.PrivateData, "no erasure when we cannot prove nothing live remains")
	})
}

func TestWalletLifecycle_Erasure_CoversEveryTenantMembership(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	uid := seedWalletUser(t, store, domain.DefaultTenantID, "acme")
	c, p := countHolderData(t, store, "acme", uid)
	require.Equal(t, 1, c)
	require.Equal(t, 1, p)

	n, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "leaving")
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	for _, tid := range []domain.TenantID{domain.DefaultTenantID, "acme"} {
		c, p := countHolderData(t, store, tid, uid)
		assert.Zero(t, c, "credentials erased in %s", tid)
		assert.Zero(t, p, "presentations erased in %s", tid)
	}
	_, err = store.Challenges().GetByID(ctx, "chal-"+uid.String())
	assert.Error(t, err, "pending challenges are gone")
}

func TestWalletLifecycle_Erasure_StoreFailuresAreLoggedNotFatal(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{
		"users.Update", "usertenants.GetUserTenants", "credentials.GetAllByHolder", "credentials.Delete",
		"presentations.GetAllByHolder", "presentations.Delete", "challenges.DeleteByUserID",
	} {
		t.Run(op, func(t *testing.T) {
			fs := newFailStore()
			svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
			uid := seedWalletUser(t, fs, domain.DefaultTenantID, "acme")
			fs.fail[op] = true
			n, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "test")
			require.NoError(t, err, "erasure problems never fail the revocation")
			assert.Equal(t, 1, n)
			inst, _ := fs.Store.WalletInstances().GetByID(ctx, "inst-"+uid.String())
			assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
			if op == "usertenants.GetUserTenants" {
				c, _ := countHolderData(t, fs.Store, domain.DefaultTenantID, uid)
				assert.Zero(t, c, "the default tenant is still erased")
				c, _ = countHolderData(t, fs.Store, "acme", uid)
				assert.Equal(t, 1, c, "the other tenant survives - which is why this is logged as an error")
			}
		})
	}

	t.Run("users.GetByID", func(t *testing.T) {
		fs := newFailStore()
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs, domain.DefaultTenantID)
		fs.fail["users.GetByID"] = true
		_, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "test")
		require.NoError(t, err)
		_, err = fs.Store.Challenges().GetByID(ctx, "chal-"+uid.String())
		assert.NoError(t, err, "erasure stops when the user cannot be loaded")
	})
}

func TestWalletLifecycle_RevokeAll_StoreErrors(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore()
	svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
	uid := seedWalletUser(t, fs, domain.DefaultTenantID)

	fs.fail["instances.UpdateStatus"] = true
	n, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "test")
	assert.ErrorIs(t, err, errBoom)
	assert.Zero(t, n)

	fs.fail["instances.GetByUser"] = true
	_, err = svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "test")
	assert.ErrorIs(t, err, errBoom)
}
