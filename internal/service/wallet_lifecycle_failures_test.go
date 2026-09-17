package service

import (
	"context"
	"errors"
	"fmt"
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

	captureBeforeClear bool
	captured           *domain.User
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

func (s *failUsers) EraseWalletData(ctx context.Context, id domain.UserID, fence time.Time, exemptJTI string) error {
	if err := s.f.err("users.EraseWalletData"); err != nil {
		return err
	}
	if s.f.captureBeforeClear {
		// A request that loaded the user after the first cut-off but before
		// the clear: it carries the current cut-off and the intact vault.
		u, err := s.UserStore.GetByID(ctx, id)
		if err != nil {
			return err
		}
		c := *u
		s.f.captured = &c
	}
	return s.UserStore.EraseWalletData(ctx, id, fence, exemptJTI)
}

func (s *failUsers) InvalidateAuthBefore(ctx context.Context, id domain.UserID, t time.Time, exemptJTI string) error {
	if err := s.f.err("users.InvalidateAuthBefore"); err != nil {
		return err
	}
	return s.UserStore.InvalidateAuthBefore(ctx, id, t, exemptJTI)
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

func TestWalletLifecycle_Cascade_UnownedInstanceAndErrors(t *testing.T) {
	ctx := context.Background()
	provider := LifecycleActor{Kind: "provider"}

	t.Run("instance without a user: nothing to cascade", func(t *testing.T) {
		svc := NewWalletLifecycleService(memory.NewStore(), zap.NewNop(), nil)
		require.NoError(t, svc.store.WalletInstances().Upsert(ctx, &domain.WalletInstance{ID: "anon", TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive}))
		inst, err := svc.ChangeStatus(ctx, provider, domain.DefaultTenantID, "anon", domain.InstanceStatusRevoked, "")
		require.NoError(t, err)
		assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
	})

	t.Run("session drop failure: erasure still runs, reported as incomplete", func(t *testing.T) {
		store := memory.NewStore()
		svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
		svc.SetSessionCleaner(erroringSessionCleaner{})
		uid := seedWalletUser(t, store, domain.DefaultTenantID)
		inst, err := svc.ChangeStatus(ctx, provider, domain.DefaultTenantID, "inst-"+uid.String(), domain.InstanceStatusRevoked, "")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
		assert.ErrorIs(t, err, errBoom, "the underlying failure is wrapped")
		require.NotNil(t, inst, "the persisted state is returned alongside the error")
		assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
		user, _ := store.Users().GetByID(ctx, uid)
		assert.Nil(t, user.PrivateData)
	})

	t.Run("cannot list remaining instances: wallet data is kept, reported as incomplete", func(t *testing.T) {
		fs := newFailStore()
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs, domain.DefaultTenantID)
		fs.fail["instances.GetByUser"] = true
		_, err := svc.ChangeStatus(ctx, provider, domain.DefaultTenantID, "inst-"+uid.String(), domain.InstanceStatusRevoked, "")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
		user, _ := fs.Store.Users().GetByID(ctx, uid)
		assert.NotNil(t, user.PrivateData, "no erasure when we cannot prove nothing live remains")
	})
}

// Wallet instances are per tenant: deactivating the wallet in one tenant
// erases the holder data of that tenant only. The user-level vault is erased
// only once no live instance remains anywhere.
func TestWalletLifecycle_Erasure_IsScopedToTheTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("live instance in another tenant keeps the vault", func(t *testing.T) {
		store := memory.NewStore()
		svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
		uid := seedWalletUser(t, store, domain.DefaultTenantID, "acme")
		require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "acme-inst", TenantID: "acme", UserID: &uid, Status: domain.InstanceStatusActive,
		}))

		n, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "leaving")
		require.NoError(t, err)
		assert.Equal(t, 1, n)

		c, p := countHolderData(t, store, domain.DefaultTenantID, uid)
		assert.Zero(t, c, "default-tenant credentials erased")
		assert.Zero(t, p, "default-tenant presentations erased")
		c, p = countHolderData(t, store, "acme", uid)
		assert.Equal(t, 1, c, "acme credentials untouched")
		assert.Equal(t, 1, p, "acme presentations untouched")
		user, _ := store.Users().GetByID(ctx, uid)
		assert.NotNil(t, user.PrivateData, "the vault serves the live acme instance")
		_, err = store.Challenges().GetByID(ctx, "chal-"+uid.String())
		assert.NoError(t, err, "challenges are user-level too")
	})

	t.Run("no live instance anywhere erases the vault and every tenant's holder data", func(t *testing.T) {
		store := memory.NewStore()
		svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
		uid := seedWalletUser(t, store, domain.DefaultTenantID, "acme") // acme membership + data, no acme instance

		_, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "leaving")
		require.NoError(t, err)

		user, _ := store.Users().GetByID(ctx, uid)
		assert.Nil(t, user.PrivateData)
		_, err = store.Challenges().GetByID(ctx, "chal-"+uid.String())
		assert.Error(t, err, "pending challenges are gone")
		c, p := countHolderData(t, store, "acme", uid)
		assert.Zero(t, c+p, "a fully deactivated wallet has its VCs/VPs erased in every tenant (#195)")
	})
}

func TestWalletLifecycle_Erasure_StoreFailuresAreReportedAndRetryable(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{
		"users.EraseWalletData", "usertenants.GetUserTenants", "credentials.GetAllByHolder", "credentials.Delete",
		"presentations.GetAllByHolder", "presentations.Delete", "challenges.DeleteByUserID",
	} {
		t.Run(op, func(t *testing.T) {
			fs := newFailStore()
			svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
			uid := seedWalletUser(t, fs, domain.DefaultTenantID)
			fs.fail[op] = true
			n, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "test")
			assert.ErrorIs(t, err, ErrErasureIncomplete, "erasure problems are reported, not swallowed")
			assert.Equal(t, 1, n, "the revocation itself took effect")
			inst, _ := fs.Store.WalletInstances().GetByID(ctx, "inst-"+uid.String())
			assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
			if op == "usertenants.GetUserTenants" {
				user, _ := fs.Store.Users().GetByID(ctx, uid)
				assert.NotNil(t, user.PrivateData, "vault kept: cannot prove no live instance elsewhere")
				c, _ := countHolderData(t, fs.Store, domain.DefaultTenantID, uid)
				assert.Zero(t, c, "this tenant's holder data is still erased")
			}

			// Retry with everything already revoked re-runs the cascade.
			fs.fail[op] = false
			n, err = svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "test")
			require.NoError(t, err)
			assert.Zero(t, n)
			user, _ := fs.Store.Users().GetByID(ctx, uid)
			assert.Nil(t, user.PrivateData)
			c, p := countHolderData(t, fs.Store, domain.DefaultTenantID, uid)
			assert.Zero(t, c+p)
			_, err = fs.Store.Challenges().GetByID(ctx, "chal-"+uid.String())
			assert.Error(t, err)
		})
	}

	t.Run("users.GetByID", func(t *testing.T) {
		fs := newFailStore()
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs, domain.DefaultTenantID)
		fs.fail["users.GetByID"] = true
		_, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "test")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
		_, err = fs.Store.Challenges().GetByID(ctx, "chal-"+uid.String())
		assert.NoError(t, err, "erasure stops when the user cannot be loaded")
	})

	t.Run("retry via ChangeStatus on the revoked instance", func(t *testing.T) {
		fs := newFailStore("credentials.Delete")
		svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
		uid := seedWalletUser(t, fs, domain.DefaultTenantID)
		id := "inst-" + uid.String()
		inst, err := svc.ChangeStatus(ctx, userActor(uid), domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "stolen")
		assert.ErrorIs(t, err, ErrErasureIncomplete)
		assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)

		fs.fail["credentials.Delete"] = false
		inst, err = svc.ChangeStatus(ctx, userActor(uid), domain.DefaultTenantID, id, domain.InstanceStatusRevoked, "stolen")
		require.NoError(t, err)
		assert.Equal(t, domain.InstanceStatusRevoked, inst.Status)
		c, _ := countHolderData(t, fs.Store, domain.DefaultTenantID, uid)
		assert.Zero(t, c)
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

// A user record loaded between the token cut-off and the erasure must not be
// able to write the erased vault back: the cascade advances the write fence
// again after clearing.
func TestWalletLifecycle_CopyLoadedDuringErasureIsFenced(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore()
	fs.captureBeforeClear = true
	svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
	uid := seedWalletUser(t, fs, domain.DefaultTenantID)

	_, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "stolen")
	require.NoError(t, err)
	require.NotNil(t, fs.captured, "the copy was taken inside the window")
	require.NotNil(t, fs.captured.PrivateData, "and it still holds the vault")

	assert.ErrorIs(t, fs.Store.Users().Update(ctx, fs.captured), storage.ErrStaleWrite)
	u, _ := fs.Store.Users().GetByID(ctx, uid)
	assert.Nil(t, u.PrivateData, "the erasure stands")
}

// The token cut-off is recorded before the status is persisted: if it cannot
// be, nothing changes (fail closed), instead of a blocked instance whose
// pre-cut-off tokens keep working.
func TestWalletLifecycle_CutoffFailureLeavesStatusUnchanged(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore("users.InvalidateAuthBefore")
	svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
	uid := seedWalletUser(t, fs, domain.DefaultTenantID)
	id := "inst-" + uid.String()

	_, err := svc.ChangeStatus(ctx, userActor(uid), domain.DefaultTenantID, id, domain.InstanceStatusSuspended, "x")
	assert.ErrorIs(t, err, errBoom)
	inst, _ := fs.Store.WalletInstances().GetByID(ctx, id)
	assert.Equal(t, domain.InstanceStatusActive, inst.Status, "status untouched when the cut-off cannot be recorded")

	n, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "x")
	assert.ErrorIs(t, err, errBoom)
	assert.Zero(t, n)
	inst, _ = fs.Store.WalletInstances().GetByID(ctx, id)
	assert.Equal(t, domain.InstanceStatusActive, inst.Status)
}

// The acting session's exemption exists to retry the erasure, so it ends with
// the erasure: once the vault is gone the wallet needs a new enrollment and
// that session must not be able to write wallet data back. It survives only
// while the erasure itself has not happened.
func TestWalletLifecycle_ExemptionEndsWithTheErasure(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore("users.EraseWalletData")
	svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
	uid := seedWalletUser(t, fs, domain.DefaultTenantID)
	actor := userActor(uid)
	actor.TokenJTI = "acting"

	_, err := svc.RevokeAllForUser(ctx, actor, domain.DefaultTenantID, uid, "stolen")
	assert.ErrorIs(t, err, ErrErasureIncomplete)
	user, _ := fs.Store.Users().GetByID(ctx, uid)
	assert.NotNil(t, user.PrivateData, "the vault is still there")
	assert.Equal(t, "acting", user.AuthCutoffExemptJTI, "so the session keeps working to retry")

	fs.fail["users.EraseWalletData"] = false
	_, err = svc.RevokeAllForUser(ctx, actor, domain.DefaultTenantID, uid, "stolen")
	require.NoError(t, err)
	user, _ = fs.Store.Users().GetByID(ctx, uid)
	assert.Nil(t, user.PrivateData)
	_, exempt, _ := fs.Store.Users().GetAuthCutoff(ctx, uid)
	assert.Empty(t, exempt, "the vault is gone: no token survives")
}

// attestingInstances inserts a brand-new active instance the first time an
// instance is revoked, simulating a first attestation racing revoke-all.
type attestingInstances struct {
	storage.WalletInstanceStore
	userID domain.UserID
	fired  bool
}

func (a *attestingInstances) UpdateStatus(ctx context.Context, id string, st domain.InstanceStatus, reason string) error {
	if err := a.WalletInstanceStore.UpdateStatus(ctx, id, st, reason); err != nil {
		return err
	}
	if !a.fired && st == domain.InstanceStatusRevoked {
		a.fired = true
		uid := a.userID
		return a.WalletInstanceStore.Upsert(ctx, &domain.WalletInstance{
			ID: "raced-instance", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
		})
	}
	return nil
}

type racingInstanceStore struct {
	storage.Store
	instances storage.WalletInstanceStore
}

func (r *racingInstanceStore) WalletInstances() storage.WalletInstanceStore { return r.instances }

// An instance created while revoke-all is sweeping must not survive as the
// only live one: the sweep re-lists until nothing is left to revoke, so the
// wallet really is deactivated and the data erased.
func TestWalletLifecycle_RevokeAllCatchesInstanceCreatedDuringTheSweep(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore()
	uid := seedWalletUser(t, base, domain.DefaultTenantID)
	racing := &racingInstanceStore{Store: base, instances: &attestingInstances{WalletInstanceStore: base.WalletInstances(), userID: uid}}
	svc := NewWalletLifecycleService(racing, zap.NewNop(), nil)

	n, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "stolen")
	require.NoError(t, err)
	assert.Equal(t, 2, n, "the seeded instance and the one attested mid-sweep")

	instances, err := base.WalletInstances().GetByUser(ctx, domain.DefaultTenantID, uid)
	require.NoError(t, err)
	require.Len(t, instances, 2)
	for _, inst := range instances {
		assert.Equal(t, domain.InstanceStatusRevoked, inst.Status, "instance %s", inst.ID)
	}
	user, _ := base.Users().GetByID(ctx, uid)
	assert.Nil(t, user.PrivateData, "the wallet is deactivated, so the vault is erased")
}

// A status persisted outside ChangeStatus (the standalone admin path, an
// older deployment) leaves no cut-off; the idempotent retry establishes one
// without advancing a cut-off that already exists.
func TestWalletLifecycle_CascadeEstablishesMissingCutoff(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	uid := seedWalletUser(t, store, domain.DefaultTenantID)
	id := "inst-" + uid.String()
	// Persisted directly, as another process would have.
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, id, domain.InstanceStatusSuspended, "elsewhere"))
	cutoff, _, err := store.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, err)
	require.True(t, cutoff.IsZero(), "no cut-off was recorded by that path")

	actor := userActor(uid)
	actor.TokenJTI = "acting"
	_, err = svc.ChangeStatus(ctx, actor, domain.DefaultTenantID, id, domain.InstanceStatusSuspended, "retry")
	require.NoError(t, err)
	cutoff, exempt, err := store.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, err)
	require.False(t, cutoff.IsZero(), "the retry establishes the cut-off")
	assert.Equal(t, "acting", exempt)

	// A second retry must not advance it (that would cut off tokens issued
	// since, for no reason).
	_, err = svc.ChangeStatus(ctx, actor, domain.DefaultTenantID, id, domain.InstanceStatusSuspended, "retry again")
	require.NoError(t, err)
	again, _, _ := store.Users().GetAuthCutoff(ctx, uid)
	assert.True(t, again.Equal(cutoff), "an established cut-off stays put")
}

// A cascade step failing around a successful erasure does not keep the
// exemption alive: the vault is gone, so the wallet is deactivated and the
// acting session must not be able to write new wallet data with its
// pre-cut-off token.
func TestWalletLifecycle_ExemptionDroppedEvenIfAnotherStepFailed(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	svc.SetSessionCleaner(erroringSessionCleaner{})
	uid := seedWalletUser(t, store, domain.DefaultTenantID)
	actor := userActor(uid)
	actor.TokenJTI = "acting"

	_, err := svc.RevokeAllForUser(ctx, actor, domain.DefaultTenantID, uid, "stolen")
	assert.ErrorIs(t, err, ErrErasureIncomplete, "the session drop failed")
	user, _ := store.Users().GetByID(ctx, uid)
	assert.Nil(t, user.PrivateData, "the erasure itself went through")
	assert.Empty(t, user.AuthCutoffExemptJTI, "so no token survives, retry or not")
}

// alwaysAttestingInstances inserts a fresh active instance after every
// revocation, so the revoke-all sweep never reaches a fixed point and runs out
// of passes instead.
type alwaysAttestingInstances struct {
	storage.WalletInstanceStore
	userID domain.UserID
	n      int
}

func (a *alwaysAttestingInstances) UpdateStatus(ctx context.Context, id string, st domain.InstanceStatus, reason string) error {
	if err := a.WalletInstanceStore.UpdateStatus(ctx, id, st, reason); err != nil {
		return err
	}
	if st != domain.InstanceStatusRevoked {
		return nil
	}
	a.n++
	uid := a.userID
	return a.WalletInstanceStore.Upsert(ctx, &domain.WalletInstance{
		ID:       fmt.Sprintf("raced-%d", a.n),
		TenantID: domain.DefaultTenantID,
		UserID:   &uid,
		Status:   domain.InstanceStatusActive,
	})
}

// A client attesting fast enough to outrun the bounded sweep must not get a
// success back for a wallet that still has an active instance: the request is
// reported as incomplete so repeating it resumes the sweep, and the wallet
// data is not erased while something live remains.
func TestWalletLifecycle_RevokeAllReportsIncompleteWhenTheSweepRunsOutOfPasses(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore()
	uid := seedWalletUser(t, base, domain.DefaultTenantID)
	racing := &racingInstanceStore{
		Store:     base,
		instances: &alwaysAttestingInstances{WalletInstanceStore: base.WalletInstances(), userID: uid},
	}
	svc := NewWalletLifecycleService(racing, zap.NewNop(), nil)

	n, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "stolen")
	assert.ErrorIs(t, err, ErrErasureIncomplete, "the sweep hit its bound with an instance still live")
	assert.Equal(t, revokeAllMaxPasses, n, "one revocation per pass")

	instances, err := base.WalletInstances().GetByUser(ctx, domain.DefaultTenantID, uid)
	require.NoError(t, err)
	live := 0
	for _, inst := range instances {
		if inst.Status != domain.InstanceStatusRevoked {
			live++
		}
	}
	assert.Equal(t, 1, live, "the instance attested during the last pass is still active")

	user, err := base.Users().GetByID(ctx, uid)
	require.NoError(t, err)
	assert.NotNil(t, user.PrivateData, "an instance the user could still use remains, so nothing is erased")
}

// The sweep cuts tokens off before its first status write and again once
// every instance is revoked: a token minted while it was still running
// carries an iat after the first cut-off and would otherwise survive.
func TestWalletLifecycle_RevokeAllAdvancesTheCutoffAfterTheSweep(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	uid := seedWalletUser(t, store, domain.DefaultTenantID)

	before, _ := store.Users().GetByID(ctx, uid)
	require.Zero(t, before.AuthFence)

	_, err := svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "stolen")
	require.NoError(t, err)

	after, _ := store.Users().GetByID(ctx, uid)
	assert.GreaterOrEqual(t, after.AuthFence, int64(2),
		"one cut-off before the first revocation and one after the sweep (plus the erasure), each advancing the fence")

	// Nothing left to revoke: the retry path does not keep advancing it.
	fence := after.AuthFence
	_, err = svc.RevokeAllForUser(ctx, userActor(uid), domain.DefaultTenantID, uid, "again")
	require.NoError(t, err)
	again, _ := store.Users().GetByID(ctx, uid)
	assert.Equal(t, fence+1, again.AuthFence, "only the idempotent erasure writes again")
}
