package service

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// revokeSilently revokes all of the user's instances in the store only, as a
// cascade that never ran (or an operator) would leave them.
func revokeSilently(t *testing.T, store storage.Store, userID domain.UserID) {
	t.Helper()
	ctx := context.Background()
	insts, err := store.WalletInstances().GetAllByUser(ctx, userID)
	require.NoError(t, err)
	for _, inst := range insts {
		require.NoError(t, store.WalletInstances().UpdateStatus(ctx, inst.ID, inst.TenantID, domain.InstanceStatusRevoked, "seed"))
	}
}

func inTheFuture() time.Time { return time.Now().Add(time.Hour) }

func userData(t *testing.T, store storage.Store, userID domain.UserID) *domain.User {
	t.Helper()
	u, err := store.Users().GetByID(context.Background(), userID)
	require.NoError(t, err)
	return u
}

func TestReconcileUser_FinishesAnErasureThatNeverRan(t *testing.T) {
	svc, store, userID, holder := twoTenantFixture(t)
	ctx := context.Background()
	sc := &fakeSessionCleaner{}
	svc.SetSessionCleaner(sc)
	require.NoError(t, store.Challenges().Create(ctx, &domain.WebauthnChallenge{
		ID: "c1", UserID: userID.String(), Challenge: "c", Action: "login", ExpiresAt: time.Now().Add(time.Minute),
	}))
	revokeSilently(t, store, userID)

	out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileErased, out)

	assert.Zero(t, holderDataCount(t, store, tenantA, holder))
	assert.Zero(t, holderDataCount(t, store, tenantB, holder))
	u := userData(t, store, userID)
	assert.Nil(t, u.PrivateData)
	assert.Nil(t, u.Keys)
	assert.Equal(t, []string{userID.String()}, sc.users, "sessions are dropped")
	_, err = store.Challenges().GetByID(ctx, "c1")
	assert.ErrorIs(t, err, storage.ErrNotFound)
	cutoff, err := store.Users().GetAuthCutoff(ctx, userID)
	require.NoError(t, err)
	assert.False(t, cutoff.IsZero(), "the cut-off is advanced")

	// Idempotent: a second pass finds nothing to do.
	out, err = svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileClean, out)
}

func TestReconcileUser_FinishesACascadeThatFailedAndWasNeverRetried(t *testing.T) {
	f := newFailStore("users.EraseWalletData")
	svc := NewWalletLifecycleService(f, zap.NewNop(), nil)
	ctx := context.Background()
	userID := seedWalletUser(t, f, domain.DefaultTenantID)

	_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-"+userID.String(), domain.InstanceStatusRevoked, "lost")
	require.ErrorIs(t, err, ErrErasureIncomplete)
	require.NotNil(t, userData(t, f, userID).PrivateData, "the key-material erase failed")

	f.fail["users.EraseWalletData"] = false
	out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileErased, out)
	assert.Nil(t, userData(t, f, userID).PrivateData)
}

func TestReconcileUser_LeavesAUserWithALiveInstanceInAnotherTenantAlone(t *testing.T) {
	svc, store, userID, holder := twoTenantFixture(t)
	ctx := context.Background()
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "inst-"+string(tenantA), tenantA, domain.InstanceStatusRevoked, "seed"))

	out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileLive, out)
	assert.Equal(t, 2, holderDataCount(t, store, tenantA, holder))
	assert.Equal(t, 2, holderDataCount(t, store, tenantB, holder))
	assert.NotNil(t, userData(t, store, userID).PrivateData)
	cutoff, err := store.Users().GetAuthCutoff(ctx, userID)
	require.NoError(t, err)
	assert.True(t, cutoff.IsZero(), "a live wallet is not logged out")
}

func TestReconcileUser_UnrecognizedStatusFailsClosed(t *testing.T) {
	svc, store, userID, holder := twoTenantFixture(t)
	ctx := context.Background()
	// Revoke both fixture instances so the unrecognized status is the only
	// reason reconciliation can refuse.
	revokeSilently(t, store, userID)
	seedRawInstance(t, store, tenantB, "inst-raw", userID, "", unknownInstanceStatus)

	out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileLive, out)
	assert.Equal(t, 2, holderDataCount(t, store, tenantB, holder))
}

// A wallet that is only suspended (legacy, reversible) was never revoked.
func TestReconcileUser_SuspendedOnlyIsNotADeactivatedWallet(t *testing.T) {
	svc, store, userID, _ := lifecycleFixture(t)
	seedLegacySuspended(t, store, "inst-s", userID)
	out, err := svc.ReconcileUser(context.Background(), userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileClean, out)
	assert.NotNil(t, userData(t, store, userID).PrivateData)
}

func TestReconcileUser_RespectsTheGracePeriod(t *testing.T) {
	svc, store, userID, holder := twoTenantFixture(t)
	ctx := context.Background()
	revokeSilently(t, store, userID)

	out, err := svc.ReconcileUser(ctx, userID, time.Now().Add(-15*time.Minute))
	require.NoError(t, err)
	assert.Equal(t, ReconcileGrace, out)
	assert.Equal(t, 2, holderDataCount(t, store, tenantA, holder), "nothing is erased inside the grace period")
	assert.NotNil(t, userData(t, store, userID).PrivateData)

	out, err = svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileErased, out)
}

// The grace period runs from the latest revocation, not the earliest.
func TestReconcileUser_GraceFollowsTheLatestRevocation(t *testing.T) {
	svc, store, userID, _ := twoTenantFixture(t)
	ctx := context.Background()
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "inst-"+string(tenantA), tenantA, domain.InstanceStatusRevoked, "seed"))
	time.Sleep(20 * time.Millisecond)
	cut := time.Now()
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "inst-"+string(tenantB), tenantB, domain.InstanceStatusRevoked, "seed"))

	out, err := svc.ReconcileUser(ctx, userID, cut)
	require.NoError(t, err)
	assert.Equal(t, ReconcileGrace, out, "the first revocation is old enough, the second is not")
}

// A revocation with no recorded time is the most recent as far as the grace
// period goes: it is not aged by another instance's older revocation.
func TestReconcileUser_UnrecordedRevocationTimeStaysInGrace(t *testing.T) {
	svc, store, userID, holder := twoTenantFixture(t)
	ctx := context.Background()
	revokeSilently(t, store, userID)
	seedRawInstance(t, store, tenantA, "inst-untimed", userID, "", domain.InstanceStatusRevoked)

	out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileGrace, out)
	assert.Equal(t, 2, holderDataCount(t, store, tenantA, holder))
}

// A user with nothing left to erase is not cascaded again (no session drop, no
// cut-off churn on every pass).
func TestReconcileUser_ErasedUserIsLeftAlone(t *testing.T) {
	svc, store, userID, _ := twoTenantFixture(t)
	ctx := context.Background()
	revokeSilently(t, store, userID)
	_, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	sc := &fakeSessionCleaner{}
	svc.SetSessionCleaner(sc)
	before, err := store.Users().GetAuthCutoff(ctx, userID)
	require.NoError(t, err)

	out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileClean, out)
	assert.Empty(t, sc.users)
	after, err := store.Users().GetAuthCutoff(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

// Holder data alone (a write that landed after the last sweep) is enough, and
// a user's vault alone is too.
func TestReconcileUser_DetectsEachKindOfLeftoverData(t *testing.T) {
	ctx := context.Background()
	for name, leave := range map[string]func(t *testing.T, store storage.Store, userID domain.UserID, holder string){
		"private data": func(t *testing.T, store storage.Store, userID domain.UserID, _ string) {
			require.NoError(t, store.Users().Update(ctx, func() *domain.User {
				u := userData(t, store, userID)
				u.PrivateData = []byte("late")
				return u
			}()))
		},
		"key material": func(t *testing.T, store storage.Store, userID domain.UserID, _ string) {
			u := userData(t, store, userID)
			u.Keys = []byte("late")
			require.NoError(t, store.Users().Update(ctx, u))
		},
		"credential": func(t *testing.T, store storage.Store, _ domain.UserID, holder string) {
			require.NoError(t, store.Credentials().Create(ctx, &domain.VerifiableCredential{
				TenantID: tenantB, HolderDID: holder, CredentialIdentifier: "late", Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
			}))
		},
		"presentation": func(t *testing.T, store storage.Store, _ domain.UserID, holder string) {
			require.NoError(t, store.Presentations().Create(ctx, &domain.VerifiablePresentation{
				TenantID: tenantA, HolderDID: holder, PresentationIdentifier: "late", Presentation: "jwt",
			}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			svc, store, userID, holder := twoTenantFixture(t)
			revokeSilently(t, store, userID)
			out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
			require.NoError(t, err)
			require.Equal(t, ReconcileErased, out)
			leave(t, store, userID, holder)

			out, err = svc.ReconcileUser(ctx, userID, inTheFuture())
			require.NoError(t, err)
			assert.Equal(t, ReconcileErased, out)
			out, err = svc.ReconcileUser(ctx, userID, inTheFuture())
			require.NoError(t, err)
			assert.Equal(t, ReconcileClean, out)
		})
	}
}

// Fail closed: if the cut-off cannot be advanced, or the data cannot be
// probed, nothing is erased and the error says so.
func TestReconcileUser_FailsClosed(t *testing.T) {
	for _, op := range []string{"users.InvalidateAuthBefore", "credentials.GetAllByHolder", "usertenants.GetUserTenants", "users.GetByID"} {
		t.Run(op, func(t *testing.T) {
			f := newFailStore()
			svc := NewWalletLifecycleService(f, zap.NewNop(), nil)
			userID := seedWalletUser(t, f, domain.DefaultTenantID)
			revokeSilently(t, f, userID)
			// Probe the vault-less case too, so the holder listing is reached.
			if op == "credentials.GetAllByHolder" {
				u := userData(t, f, userID)
				u.PrivateData = nil
				require.NoError(t, f.Users().Update(context.Background(), u))
			}
			f.fail[op] = true

			_, err := svc.ReconcileUser(context.Background(), userID, inTheFuture())
			require.Error(t, err)
			f.fail[op] = false
			n, _ := countHolderData(t, f, domain.DefaultTenantID, userID)
			assert.Equal(t, 1, n, "no holder data erased")
			if op != "credentials.GetAllByHolder" {
				assert.NotNil(t, userData(t, f, userID).PrivateData)
			}
		})
	}
}

// A first attestation holds the user lock from its instance write to the end of
// its recheck; the reconciler must wait for it and then see the live instance.
func TestReconcileUser_WaitsForAnAttestationHoldingTheUserLock(t *testing.T) {
	svc, store, userID, holder := twoTenantFixture(t)
	ctx := context.Background()
	revokeSilently(t, store, userID)

	unlock := svc.LockUser(userID)
	done := make(chan ReconcileOutcome, 1)
	go func() {
		out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
		assert.NoError(t, err)
		done <- out
	}()
	select {
	case <-done:
		t.Fatal("the reconciler ran while the user lock was held")
	case <-time.After(50 * time.Millisecond):
	}
	require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "inst-new", TenantID: "tenant-c", UserID: &userID, Status: domain.InstanceStatusActive,
	}))
	unlock()

	select {
	case out := <-done:
		assert.Equal(t, ReconcileLive, out)
	case <-time.After(5 * time.Second):
		t.Fatal("reconciler did not finish")
	}
	assert.Equal(t, 2, holderDataCount(t, store, tenantA, holder))
}

// Two reconcilers on one service (same lock): exactly one erases.
func TestReconcileUser_ConcurrentCallsOnOneReplicaEraseOnce(t *testing.T) {
	svc, store, userID, _ := twoTenantFixture(t)
	revokeSilently(t, store, userID)
	var erased, clean atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := svc.ReconcileUser(context.Background(), userID, inTheFuture())
			assert.NoError(t, err)
			switch out {
			case ReconcileErased:
				erased.Add(1)
			case ReconcileClean:
				clean.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), erased.Load())
	assert.Equal(t, int32(7), clean.Load())
}

// Two replicas (separate services, so no shared in-process lock) reconciling the
// same users at once both succeed and leave the same end state.
func TestErasureReconciler_TwoReplicasRacingBothSucceed(t *testing.T) {
	store := memory.NewStore()
	ctx := context.Background()
	var users []domain.UserID
	for i := 0; i < 6; i++ {
		u := seedWalletUser(t, store, domain.DefaultTenantID, tenantA)
		revokeSilently(t, store, u)
		users = append(users, u)
	}
	mk := func() *ErasureReconciler {
		r := NewErasureReconciler(config.ErasureReconcilerConfig{GracePeriodSeconds: 1, BatchSize: 100}, NewWalletLifecycleService(store, zap.NewNop(), nil), store, zap.NewNop())
		r.cursor = domain.UserID{}
		r.now = inTheFuture
		return r
	}
	a, b := mk(), mk()
	var wg sync.WaitGroup
	var failed atomic.Int32
	for _, r := range []*ErasureReconciler{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, err := r.RunOnce(ctx)
			assert.NoError(t, err)
			failed.Add(int32(st.Failed))
		}()
	}
	wg.Wait()
	assert.Zero(t, failed.Load())
	for _, u := range users {
		assert.Nil(t, userData(t, store, u).PrivateData)
		for _, tid := range []domain.TenantID{domain.DefaultTenantID, tenantA} {
			c, p := countHolderData(t, store, tid, u)
			assert.Zero(t, c+p)
		}
		insts, err := store.WalletInstances().GetAllByUser(ctx, u)
		require.NoError(t, err)
		require.Len(t, insts, 1, "no instance is created or removed")
		assert.Equal(t, domain.InstanceStatusRevoked, insts[0].Status)
	}
}

func reconcilerFor(store storage.Store, batch int) *ErasureReconciler {
	r := NewErasureReconciler(config.ErasureReconcilerConfig{GracePeriodSeconds: 1, BatchSize: batch}, NewWalletLifecycleService(store, zap.NewNop(), nil), store, zap.NewNop())
	r.cursor = domain.UserID{}
	r.now = inTheFuture
	return r
}

func TestErasureReconciler_RespectsTheBatchBoundAndWalksAllUsers(t *testing.T) {
	store := memory.NewStore()
	ctx := context.Background()
	var users []domain.UserID
	for i := 0; i < 5; i++ {
		u := seedWalletUser(t, store, domain.DefaultTenantID)
		revokeSilently(t, store, u)
		users = append(users, u)
	}
	r := reconcilerFor(store, 2)

	erasedUsers := func() int {
		n := 0
		for _, u := range users {
			if userData(t, store, u).PrivateData == nil {
				n++
			}
		}
		return n
	}
	st, err := r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 2, Erased: 2}, st)
	assert.Equal(t, 2, erasedUsers(), "only the batch is touched")

	st, err = r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 2, Erased: 2}, st)
	st, err = r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 1, Erased: 1}, st)
	assert.Equal(t, 5, erasedUsers())

	// The list is exhausted, so the next run starts over (and finds nothing to do).
	st, err = r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 2, Clean: 2}, st)
}

// failErasingUser fails EraseWalletData for one user.
type failErasingUser struct {
	storage.Store
	bad  domain.UserID
	fail atomic.Bool
}

func (s *failErasingUser) Users() storage.UserStore { return &failErasingUserStore{s.Store.Users(), s} }

type failErasingUserStore struct {
	storage.UserStore
	s *failErasingUser
}

func (u *failErasingUserStore) EraseWalletData(ctx context.Context, id domain.UserID, fence time.Time) error {
	if u.s.fail.Load() && id == u.s.bad {
		return errBoom
	}
	return u.UserStore.EraseWalletData(ctx, id, fence)
}

func TestErasureReconciler_OneFailureDoesNotStopTheRestAndIsRetried(t *testing.T) {
	mem := memory.NewStore()
	ctx := context.Background()
	var users []domain.UserID
	for i := 0; i < 3; i++ {
		u := seedWalletUser(t, mem, domain.DefaultTenantID)
		revokeSilently(t, mem, u)
		users = append(users, u)
	}
	store := &failErasingUser{Store: mem, bad: users[1]}
	store.fail.Store(true)
	r := reconcilerFor(store, 10)

	st, err := r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, st.Scanned)
	assert.Equal(t, 1, st.Failed)
	assert.Equal(t, 2, st.Erased)
	assert.NotNil(t, userData(t, mem, users[1]).PrivateData, "the failed user keeps its data for the retry")
	assert.Nil(t, userData(t, mem, users[0]).PrivateData)
	assert.Nil(t, userData(t, mem, users[2]).PrivateData)

	// Resumes: the next pass finishes the failed user and leaves the others.
	store.fail.Store(false)
	st, err = r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 3, Erased: 1, Clean: 2}, st)
	assert.Nil(t, userData(t, mem, users[1]).PrivateData)
}

func TestErasureReconciler_ListFailureIsAnError(t *testing.T) {
	store := &failListStore{Store: memory.NewStore()}
	r := reconcilerFor(store, 10)
	_, err := r.RunOnce(context.Background())
	require.ErrorIs(t, err, errBoom)
}

type failListStore struct{ storage.Store }

func (s *failListStore) WalletInstances() storage.WalletInstanceStore {
	return &failListInstances{s.Store.WalletInstances()}
}

type failListInstances struct{ storage.WalletInstanceStore }

func (failListInstances) ListUsersWithRevokedInstances(context.Context, domain.UserID, int) ([]domain.UserID, error) {
	return nil, errBoom
}

// The reconciler honors the clock and the grace period it is configured with.
func TestErasureReconciler_GraceUsesTheConfiguredPeriod(t *testing.T) {
	store := memory.NewStore()
	u := seedWalletUser(t, store, domain.DefaultTenantID)
	revokeSilently(t, store, u)
	r := NewErasureReconciler(config.ErasureReconcilerConfig{GracePeriodSeconds: 600, BatchSize: 10}, NewWalletLifecycleService(store, zap.NewNop(), nil), store, zap.NewNop())
	r.cursor = domain.UserID{}

	r.now = func() time.Time { return time.Now().Add(9 * time.Minute) }
	st, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 1, Grace: 1}, st)

	r.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	st, err = r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 1, Erased: 1}, st)
}

func TestErasureReconciler_StartRunsAndStopStops(t *testing.T) {
	store := memory.NewStore()
	u := seedWalletUser(t, store, domain.DefaultTenantID)
	revokeSilently(t, store, u)
	r := reconcilerFor(store, 10)
	r.interval = 20 * time.Millisecond
	r.Start()
	r.Start() // idempotent
	require.Eventually(t, func() bool { return userData(t, store, u).PrivateData == nil }, 5*time.Second, 5*time.Millisecond)
	r.Stop()
	r.Stop() // idempotent

	// Stopped means stopped: a new revocation is left until restart.
	u2 := seedWalletUser(t, store, domain.DefaultTenantID)
	revokeSilently(t, store, u2)
	time.Sleep(100 * time.Millisecond)
	assert.NotNil(t, userData(t, store, u2).PrivateData)
	r.Start()
	require.Eventually(t, func() bool { return userData(t, store, u2).PrivateData == nil }, 5*time.Second, 5*time.Millisecond)
	r.Stop()
}

func TestErasureReconciler_StartStopRace(t *testing.T) {
	store := memory.NewStore()
	r := reconcilerFor(store, 10)
	r.interval = 5 * time.Millisecond
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); r.Start() }()
		go func() { defer wg.Done(); r.Stop() }()
	}
	wg.Wait()
	r.Stop()
	r.mu.Lock()
	assert.Nil(t, r.cancel)
	r.mu.Unlock()
}

// Stop waits for a run in progress and no run starts after it returns.
func TestErasureReconciler_StopWaitsForARunInProgress(t *testing.T) {
	mem := memory.NewStore()
	u := seedWalletUser(t, mem, domain.DefaultTenantID)
	revokeSilently(t, mem, u)
	gate := &gatedListStore{Store: mem, entered: make(chan struct{}, 8), release: make(chan struct{})}
	r := reconcilerFor(gate, 10)
	r.interval = 200 * time.Millisecond
	r.Start()
	<-gate.entered

	stopped := make(chan struct{})
	go func() { r.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned while a run was in progress")
	case <-time.After(50 * time.Millisecond):
	}
	close(gate.release)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}
}

type gatedListStore struct {
	storage.Store
	entered chan struct{}
	release chan struct{}
}

func (s *gatedListStore) WalletInstances() storage.WalletInstanceStore {
	return &gatedListInstances{s.Store.WalletInstances(), s}
}

type gatedListInstances struct {
	storage.WalletInstanceStore
	s *gatedListStore
}

func (g *gatedListInstances) ListUsersWithRevokedInstances(ctx context.Context, after domain.UserID, limit int) ([]domain.UserID, error) {
	g.s.entered <- struct{}{}
	<-g.s.release
	return g.WalletInstanceStore.ListUsersWithRevokedInstances(ctx, after, limit)
}

func TestErasureReconcilerStatsCountEveryOutcome(t *testing.T) {
	var st ReconcileStats
	for _, o := range []ReconcileOutcome{ReconcileClean, ReconcileLive, ReconcileGrace, ReconcileErased, outcomeFailed} {
		st.add(o)
	}
	assert.Equal(t, ReconcileStats{Scanned: 5, Clean: 1, Live: 1, Grace: 1, Erased: 1, Failed: 1}, st)
}

func TestJitteredStaysWithinATenth(t *testing.T) {
	for i := 0; i < 1000; i++ {
		d := jittered(time.Minute)
		assert.GreaterOrEqual(t, d, 54*time.Second)
		assert.LessOrEqual(t, d, 66*time.Second)
	}
	assert.Equal(t, time.Duration(5), jittered(5))
}

// A cancelled run (shutdown) stops between users instead of working through the batch.
func TestErasureReconciler_CancelledRunStopsBetweenUsers(t *testing.T) {
	store := memory.NewStore()
	u := seedWalletUser(t, store, domain.DefaultTenantID)
	revokeSilently(t, store, u)
	r := reconcilerFor(store, 10)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st, err := r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Zero(t, st.Scanned)
	assert.NotNil(t, userData(t, store, u).PrivateData)
}

// cancelingCleaner cancels the run's context on its first call, as a timeout
// or shutdown arriving mid-page would; with failWith set it also fails.
type cancelingCleaner struct {
	cancel   context.CancelFunc
	failWith error
	once     sync.Once
}

func (c *cancelingCleaner) DeleteByUser(context.Context, string) error {
	c.once.Do(c.cancel)
	return c.failWith
}

func seedRevokedUsers(t *testing.T, store storage.Store, n int) []domain.UserID {
	t.Helper()
	var ids []domain.UserID
	for i := 0; i < n; i++ {
		u := seedWalletUser(t, store, domain.DefaultTenantID)
		revokeSilently(t, store, u)
		ids = append(ids, u)
	}
	return ids
}

func countErased(t *testing.T, store storage.Store, ids []domain.UserID) int {
	t.Helper()
	n := 0
	for _, id := range ids {
		if userData(t, store, id).PrivateData == nil {
			n++
		}
	}
	return n
}

// A run cut short after the first user leaves the rest of the page for the
// next run, which starts right after the last user examined.
func TestErasureReconciler_CutShortRunDoesNotSkipUnexaminedUsers(t *testing.T) {
	store := memory.NewStore()
	ids := seedRevokedUsers(t, store, 3)
	r := reconcilerFor(store, 10)
	ctx, cancel := context.WithCancel(context.Background())
	r.lifecycle.SetSessionCleaner(&cancelingCleaner{cancel: cancel})

	st, err := r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, st.Scanned)
	assert.Equal(t, 1, countErased(t, store, ids))

	st, err = r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, st.Scanned, "resumes after the user examined, not from the start")
	assert.Equal(t, 2, st.Erased)
	assert.Equal(t, 3, countErased(t, store, ids))
}

// A user whose cascade is cut short by cancellation is not counted as failed
// and is examined again first by the next run.
func TestErasureReconciler_UserInterruptedMidCascadeIsRetriedFirst(t *testing.T) {
	store := memory.NewStore()
	ids := seedRevokedUsers(t, store, 3)
	r := reconcilerFor(store, 10)
	ctx, cancel := context.WithCancel(context.Background())
	r.lifecycle.SetSessionCleaner(&cancelingCleaner{cancel: cancel, failWith: context.Canceled})

	st, err := r.RunOnce(ctx)
	require.NoError(t, err)
	assert.Zero(t, st.Failed, "an interrupted user is not a failure")

	r.lifecycle.SetSessionCleaner(&fakeSessionCleaner{})
	st, err = r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, st.Scanned, "the interrupted user is examined again, first")
	assert.Equal(t, 3, countErased(t, store, ids))
}

// When the user count is an exact multiple of the batch, the run after the
// last full page wraps and examines users in the same run.
func TestErasureReconciler_ExactSizeFinalPageWrapsWithoutAWastedRun(t *testing.T) {
	store := memory.NewStore()
	seedRevokedUsers(t, store, 4)
	r := reconcilerFor(store, 2)
	for i := 0; i < 2; i++ {
		st, err := r.RunOnce(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 2, st.Scanned)
	}
	st, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, st.Scanned, "the empty tail wraps within the run")
}

// A run cancelled while another operation holds the user's lock returns
// promptly instead of waiting for it, and examines that user next time.
func TestErasureReconciler_CancelledWhileUserLockedDoesNotHang(t *testing.T) {
	store := memory.NewStore()
	ids := seedRevokedUsers(t, store, 1)
	r := reconcilerFor(store, 5)
	unlock := r.lifecycle.LockUser(ids[0])
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { _, err := r.RunOnce(ctx); done <- err }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		unlock()
		t.Fatal("RunOnce blocked on the user lock past its deadline")
	}
	unlock()

	st, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, st.Erased)
}

func TestUserLocks_ContextAbandonsWaitAndKeepsExclusion(t *testing.T) {
	var l userLocks
	id := domain.NewUserID()
	release := l.lock(id)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := l.lockCtx(ctx, id)
	assert.ErrorIs(t, err, context.Canceled)
	release()
	again, err := l.lockCtx(context.Background(), id)
	require.NoError(t, err)
	again()
	assert.Empty(t, l.m, "idle entries are dropped")
}

// lateEnrollStore enrolls a live instance in another tenant the first time
// the cascade lists a tenant's instances, as another replica could between
// the reconciler's candidate check and the cascade's liveness check.
type lateEnrollStore struct {
	storage.Store
	enroll func()
	once   sync.Once
}

func (s *lateEnrollStore) WalletInstances() storage.WalletInstanceStore {
	return &lateEnrollInstances{s.Store.WalletInstances(), s}
}

type lateEnrollInstances struct {
	storage.WalletInstanceStore
	s *lateEnrollStore
}

func (l *lateEnrollInstances) GetByUser(ctx context.Context, tid domain.TenantID, id domain.UserID) ([]*domain.WalletInstance, error) {
	l.s.once.Do(l.s.enroll)
	return l.WalletInstanceStore.GetByUser(ctx, tid, id)
}

func TestReconcileUser_LiveInstanceAppearingDuringCascadeIsNotReportedErased(t *testing.T) {
	_, mem, userID, holder := twoTenantFixture(t)
	ctx := context.Background()
	revokeSilently(t, mem, userID)
	store := &lateEnrollStore{Store: mem}
	store.enroll = func() {
		require.NoError(t, mem.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "inst-late", TenantID: tenantB, UserID: &userID, Status: domain.InstanceStatusActive,
		}))
	}
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)

	out, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileLive, out)
	assert.Equal(t, 2, holderDataCount(t, mem, tenantA, holder), "nothing is erased for a live wallet")
	assert.NotNil(t, userData(t, mem, userID).PrivateData)
}

// HTTP credential writes use domain.HolderDID(userID), but the stored user.DID
// can be empty or differ; with no vault or keys left, the probe and both cascade
// sweeps must still find data stored under the canonical DID.
func TestReconcileUser_FindsHolderDataUnderTheCanonicalDID(t *testing.T) {
	ctx := context.Background()
	for name, storedDID := range map[string]string{
		"empty stored DID":     "",
		"different stored DID": "did:example:something-else",
	} {
		t.Run(name, func(t *testing.T) {
			store := memory.NewStore()
			svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
			userID := domain.NewUserID()
			canonical := domain.HolderDID(userID.String())
			require.NotEqual(t, canonical, storedDID)
			require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: userID, DID: storedDID}))
			require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
				ID: "inst-canon", TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusActive,
			}))
			require.NoError(t, store.Credentials().Create(ctx, &domain.VerifiableCredential{
				TenantID: domain.DefaultTenantID, HolderDID: canonical, CredentialIdentifier: "c", Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
			}))
			require.NoError(t, store.Presentations().Create(ctx, &domain.VerifiablePresentation{
				TenantID: domain.DefaultTenantID, HolderDID: canonical, PresentationIdentifier: "p", Presentation: "jwt",
			}))
			revokeSilently(t, store, userID)

			out, left, err := svc.ReconcileUserDryRun(ctx, userID, inTheFuture())
			require.NoError(t, err)
			require.Equal(t, ReconcileWouldErase, out, "the probe must see canonical-DID data")
			assert.ElementsMatch(t, []string{leftoverCredentials, leftoverPresentations}, left)

			out, err = svc.ReconcileUser(ctx, userID, inTheFuture())
			require.NoError(t, err)
			assert.Equal(t, ReconcileErased, out)
			assert.Zero(t, holderDataCount(t, store, domain.DefaultTenantID, canonical))

			out, err = svc.ReconcileUser(ctx, userID, inTheFuture())
			require.NoError(t, err)
			assert.Equal(t, ReconcileClean, out)
		})
	}
}

// The revoke cascade (not only the reconciler) sweeps the canonical DID.
func TestWalletLifecycle_ErasureSweepsTheCanonicalDIDWhenStoredDIDDiffers(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	userID := domain.NewUserID()
	canonical := domain.HolderDID(userID.String())
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: userID, DID: "did:example:other", PrivateData: []byte("v")}))
	require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "inst-c2", TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusActive,
	}))
	require.NoError(t, store.Credentials().Create(ctx, &domain.VerifiableCredential{
		TenantID: domain.DefaultTenantID, HolderDID: canonical, CredentialIdentifier: "c", Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
	}))
	_, err := svc.RevokeAllForUser(ctx, userActor(userID), domain.DefaultTenantID, userID, "deactivate")
	require.NoError(t, err)
	assert.Zero(t, holderDataCount(t, store, domain.DefaultTenantID, canonical))
}

// A membership removed while holder data remains (admin RemoveUserFromTenant)
// leaves a tenant with records but neither a membership nor an instance. The
// probe, the reconcile and the cascade must still visit it.
func tenantWithOnlyHolderData(t *testing.T, store storage.Store, holder string) (domain.UserID, domain.TenantID) {
	t.Helper()
	ctx := context.Background()
	userID := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: userID, DID: holder}))
	require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "inst-orphan-" + userID.String(), TenantID: tenantA, UserID: &userID, Status: domain.InstanceStatusActive,
	}))
	require.NoError(t, store.Credentials().Create(ctx, &domain.VerifiableCredential{
		TenantID: tenantB, HolderDID: holder, CredentialIdentifier: "c", Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
	}))
	require.NoError(t, store.Presentations().Create(ctx, &domain.VerifiablePresentation{
		TenantID: tenantB, HolderDID: holder, PresentationIdentifier: "p", Presentation: "jwt",
	}))
	return userID, tenantB
}

func TestReconcileUser_VisitsATenantHoldingOnlyHolderData(t *testing.T) {
	ctx := context.Background()
	for name, mk := range map[string]func(uid domain.UserID) string{
		"stored DID":    func(uid domain.UserID) string { return "did:example:" + uid.String() },
		"canonical DID": func(uid domain.UserID) string { return domain.HolderDID(uid.String()) },
	} {
		t.Run(name, func(t *testing.T) {
			store := memory.NewStore()
			svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
			uid := domain.NewUserID()
			holder := mk(uid)
			require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid, DID: holder}))
			require.NoError(t, store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
				ID: "inst-o", TenantID: tenantA, UserID: &uid, Status: domain.InstanceStatusActive,
			}))
			require.NoError(t, store.Credentials().Create(ctx, &domain.VerifiableCredential{
				TenantID: tenantB, HolderDID: holder, CredentialIdentifier: "c", Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
			}))
			require.NoError(t, store.Presentations().Create(ctx, &domain.VerifiablePresentation{
				TenantID: tenantB, HolderDID: holder, PresentationIdentifier: "p", Presentation: "jwt",
			}))
			revokeSilently(t, store, uid)

			out, left, err := svc.ReconcileUserDryRun(ctx, uid, inTheFuture())
			require.NoError(t, err)
			require.Equal(t, ReconcileWouldErase, out, "tenant B holds data and must not read as clean")
			assert.ElementsMatch(t, []string{leftoverCredentials, leftoverPresentations}, left)

			out, err = svc.ReconcileUser(ctx, uid, inTheFuture())
			require.NoError(t, err)
			assert.Equal(t, ReconcileErased, out)
			assert.Zero(t, holderDataCount(t, store, tenantB, holder))
		})
	}
}

func TestWalletLifecycle_CascadeSweepsATenantHoldingOnlyHolderData(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	holder := "did:example:orphan"
	uid, tb := tenantWithOnlyHolderData(t, store, holder)
	_, err := svc.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, tenantA, "inst-orphan-"+uid.String(), domain.InstanceStatusRevoked, "lost")
	require.NoError(t, err)
	assert.Zero(t, holderDataCount(t, store, tb, holder))
}

// A failing tenant discovery must not read as clean.
func TestReconcileUser_TenantDiscoveryFailureIsAnErrorNotClean(t *testing.T) {
	ctx := context.Background()
	f := newFailStore("credentials.TenantsByHolders")
	svc := NewWalletLifecycleService(f, zap.NewNop(), nil)
	uid, _ := tenantWithOnlyHolderData(t, f, "did:example:fail")
	revokeSilently(t, f, uid)
	out, err := svc.ReconcileUser(ctx, uid, inTheFuture())
	require.Error(t, err)
	assert.NotEqual(t, ReconcileClean, out)
	assert.NotEqual(t, ReconcileErased, out)
}

// hangingUserInstances blocks one user's instance listing until its context
// ends, as a hung store call or a huge wallet would.
type hangingUserStore struct {
	storage.Store
	bad domain.UserID
}

func (s *hangingUserStore) WalletInstances() storage.WalletInstanceStore {
	return &hangingUserInstances{s.Store.WalletInstances(), s}
}

type hangingUserInstances struct {
	storage.WalletInstanceStore
	s *hangingUserStore
}

func (i *hangingUserInstances) GetAllByUser(ctx context.Context, id domain.UserID) ([]*domain.WalletInstance, error) {
	if id == i.s.bad {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return i.WalletInstanceStore.GetAllByUser(ctx, id)
}

// A user that always exhausts its budget must not stall the cursor: the users
// after it are still reconciled, it is counted failed (never clean) and moved
// past, and shutdown still retries in place.
func TestErasureReconciler_SlowUserDoesNotBlockLaterUsers(t *testing.T) {
	mem := memory.NewStore()
	ctx := context.Background()
	var users []domain.UserID
	for i := 0; i < 4; i++ {
		u := seedWalletUser(t, mem, domain.DefaultTenantID)
		revokeSilently(t, mem, u)
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].String() < users[j].String() })
	store := &hangingUserStore{Store: mem, bad: users[0]} // first in cursor order
	r := reconcilerFor(store, 10)
	r.userTimeout = 50 * time.Millisecond

	for pass := 0; pass < 2; pass++ {
		runCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // far longer than the per-user budget
		st, err := r.RunOnce(runCtx)
		cancel()
		require.NoError(t, err)
		assert.Equal(t, 1, st.Failed, "the slow user is a failure, not clean")
		assert.Zero(t, st.Live+st.Grace, "pass %d", pass)
		if pass == 0 {
			assert.Equal(t, 3, st.Erased, "later users are reconciled in the same pass")
		} else {
			assert.Equal(t, 3, st.Clean, "the slow user is retried on the next pass and the others are already clean")
		}
	}
	for _, u := range users[1:] {
		assert.Nil(t, userData(t, mem, u).PrivateData)
	}
	assert.NotNil(t, userData(t, mem, users[0]).PrivateData, "the slow user's data is untouched")

	// Shutdown (the run context ending) is not a budget expiry: the user is retried in place.
	runCtx, cancel := context.WithCancel(ctx)
	r.cursor = domain.UserID{}
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	r.userTimeout = time.Minute
	st, err := r.RunOnce(runCtx)
	require.NoError(t, err)
	assert.Zero(t, st.Failed)
	assert.Equal(t, domain.UserID{}, r.cursor, "an interrupted user is not moved past")
}
