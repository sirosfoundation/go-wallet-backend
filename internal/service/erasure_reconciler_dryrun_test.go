package service

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// storeSnapshot captures everything a reconciliation could write for a user.
type storeSnapshot struct {
	User       domain.User
	Cutoff     time.Time
	Instances  []domain.WalletInstance
	Holder     map[domain.TenantID][2]int
	Challenges int
}

func snapshotUser(t *testing.T, store storage.Store, userID domain.UserID, holder string, tenants ...domain.TenantID) storeSnapshot {
	t.Helper()
	ctx := context.Background()
	s := storeSnapshot{User: *userData(t, store, userID), Holder: map[domain.TenantID][2]int{}}
	var err error
	s.Cutoff, err = store.Users().GetAuthCutoff(ctx, userID)
	require.NoError(t, err)
	insts, err := store.WalletInstances().GetAllByUser(ctx, userID)
	require.NoError(t, err)
	for _, i := range insts {
		s.Instances = append(s.Instances, *i)
	}
	sort.Slice(s.Instances, func(i, j int) bool { return s.Instances[i].ID < s.Instances[j].ID })
	for _, tid := range tenants {
		c, _ := store.Credentials().GetAllByHolder(ctx, tid, holder)
		p, _ := store.Presentations().GetAllByHolder(ctx, tid, holder)
		s.Holder[tid] = [2]int{len(c), len(p)}
	}
	_, err = store.Challenges().GetByID(ctx, "c1")
	if err == nil {
		s.Challenges = 1
	}
	return s
}

func dryRunFixture(t *testing.T) (*WalletLifecycleService, *memory.Store, domain.UserID, string, *fakeSessionCleaner) {
	svc, store, userID, holder := twoTenantFixture(t)
	sc := &fakeSessionCleaner{}
	svc.SetSessionCleaner(sc)
	require.NoError(t, store.Challenges().Create(context.Background(), &domain.WebauthnChallenge{
		ID: "c1", UserID: userID.String(), Challenge: "c", Action: "login", ExpiresAt: time.Now().Add(time.Minute),
	}))
	revokeSilently(t, store, userID)
	return svc, store, userID, holder, sc
}

func TestReconcileUserDryRun_ReportsAndChangesNothing(t *testing.T) {
	svc, store, userID, holder, sc := dryRunFixture(t)
	ctx := context.Background()
	u := userData(t, store, userID)
	u.Keys = []byte("legacy")
	require.NoError(t, store.Users().Update(ctx, u))
	before := snapshotUser(t, store, userID, holder, tenantA, tenantB)

	out, cats, err := svc.ReconcileUserDryRun(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileWouldErase, out)
	assert.Equal(t, []string{"private_data", "key_material", "credentials", "presentations"}, cats)

	assert.Equal(t, before, snapshotUser(t, store, userID, holder, tenantA, tenantB), "dry run writes nothing, cut-off included")
	assert.Empty(t, sc.users, "no session is dropped")

	// The real run erases the same user.
	out, err = svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileErased, out)
	assert.Zero(t, holderDataCount(t, store, tenantA, holder))
	assert.Nil(t, userData(t, store, userID).PrivateData)
}

func TestReconcileUserDryRun_ReportsOnlyTheCategoriesFound(t *testing.T) {
	svc, store, userID, _, _ := dryRunFixture(t)
	ctx := context.Background()
	_, err := svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	require.NoError(t, store.Presentations().Create(ctx, &domain.VerifiablePresentation{
		TenantID: tenantA, HolderDID: userData(t, store, userID).DID, PresentationIdentifier: "late", Presentation: "jwt",
	}))
	out, cats, err := svc.ReconcileUserDryRun(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileWouldErase, out)
	assert.Equal(t, []string{"presentations"}, cats)
}

func TestReconcileUserDryRun_DoesNotCountGraceLiveOrClean(t *testing.T) {
	ctx := context.Background()
	svc, _, userID, _, _ := dryRunFixture(t)
	out, cats, err := svc.ReconcileUserDryRun(ctx, userID, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Equal(t, ReconcileGrace, out)
	assert.Empty(t, cats)

	svc, store, userID, _ := twoTenantFixture(t)
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "inst-"+string(tenantA), tenantA, domain.InstanceStatusRevoked, "seed"))
	out, _, err = svc.ReconcileUserDryRun(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileLive, out)

	svc, store, userID, _, _ = dryRunFixture(t)
	_, err = svc.ReconcileUser(ctx, userID, inTheFuture())
	require.NoError(t, err)
	out, _, err = svc.ReconcileUserDryRun(ctx, userID, inTheFuture())
	require.NoError(t, err)
	assert.Equal(t, ReconcileClean, out)
}

func TestErasureReconciler_DryRunCountsLogsAndLeavesTheStoreAlone(t *testing.T) {
	svc, store, userID, holder, _ := dryRunFixture(t)
	before := snapshotUser(t, store, userID, holder, tenantA, tenantB)
	core, logs := observer.New(zap.InfoLevel)
	r := NewErasureReconciler(config.ErasureReconcilerConfig{DryRun: true, GracePeriodSeconds: 1, BatchSize: 10}, svc, store, zap.New(core))
	r.cursor = domain.UserID{}
	r.now = inTheFuture

	would := testutil.ToFloat64(reconcilerUsersTotal.WithLabelValues("would_erase"))
	erased := testutil.ToFloat64(reconcilerUsersTotal.WithLabelValues("erased"))
	st, err := r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 1, WouldErase: 1}, st)
	assert.Equal(t, would+1, testutil.ToFloat64(reconcilerUsersTotal.WithLabelValues("would_erase")))
	assert.Equal(t, erased, testutil.ToFloat64(reconcilerUsersTotal.WithLabelValues("erased")), "erased counts real runs only")
	assert.Equal(t, before, snapshotUser(t, store, userID, holder, tenantA, tenantB))

	entries := logs.FilterMessage("Erasure reconciler dry run: would erase").All()
	require.Len(t, entries, 1)
	f := entries[0].ContextMap()
	assert.Equal(t, userID.String(), f["user_id"])
	assert.Equal(t, []any{"private_data", "credentials", "presentations"}, f["leftover"])
	for _, v := range f {
		assert.NotContains(t, v, "vault", "no contents are logged")
	}

	// Switching dry run off erases it, and counts it as erased.
	r.dryRun = false
	st, err = r.RunOnce(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ReconcileStats{Scanned: 1, Erased: 1}, st)
	assert.Nil(t, userData(t, store, userID).PrivateData)
}

func TestErasureReconciler_DryRunStartupWarningAndGauge(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	mk := func(dry bool) *ErasureReconciler {
		store := memory.NewStore()
		r := NewErasureReconciler(config.ErasureReconcilerConfig{DryRun: dry}, NewWalletLifecycleService(store, zap.NewNop(), nil), store, zap.New(core))
		r.interval = time.Hour
		return r
	}
	r := mk(true)
	r.Start()
	assert.Equal(t, 1.0, testutil.ToFloat64(reconcilerDryRun))
	warn := logs.FilterLevelExact(zap.WarnLevel).All()
	require.Len(t, warn, 1)
	assert.Contains(t, warn[0].Message, "DRY-RUN")
	r.Stop()
	assert.Equal(t, 0.0, testutil.ToFloat64(reconcilerDryRun))

	real := mk(false)
	real.Start()
	assert.Equal(t, 0.0, testutil.ToFloat64(reconcilerDryRun))
	real.Stop()
}
