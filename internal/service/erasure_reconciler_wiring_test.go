package service

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestServices_ReconcilerIsWiredAndStoppable(t *testing.T) {
	cfg := testConfig()
	cfg.Lifecycle.Reconciler = config.ErasureReconcilerConfig{Enabled: true, IntervalSeconds: 60, GracePeriodSeconds: 60, BatchSize: 5}
	svcs := NewServices(memory.NewStore(), cfg, zap.NewNop())
	require.NotNil(t, svcs.Reconciler)
	svcs.Start()
	svcs.Stop()

	cfg.Lifecycle.Reconciler.Enabled = false
	assert.Nil(t, NewServices(memory.NewStore(), cfg, zap.NewNop()).Reconciler)
}

// The reconciler's cascade needs the session cleaner, which is wired after
// Start, so Start must leave the reconciler stopped until StartReconciler.
func TestServices_ReconcilerStartsOnlyAfterCleanerWiring(t *testing.T) {
	cfg := testConfig()
	cfg.Lifecycle.Reconciler = config.ErasureReconcilerConfig{Enabled: true, IntervalSeconds: 60, GracePeriodSeconds: 60, BatchSize: 5}
	svcs := NewServices(memory.NewStore(), cfg, zap.NewNop())
	defer svcs.Stop()

	svcs.Start()
	svcs.Reconciler.mu.Lock()
	started := svcs.Reconciler.cancel != nil
	svcs.Reconciler.mu.Unlock()
	assert.False(t, started, "Start must not run the reconciler before the session cleaner is wired")

	svcs.WalletLifecycle.SetSessionCleaner(&fakeSessionCleaner{})
	svcs.StartReconciler()
	svcs.Reconciler.mu.Lock()
	started = svcs.Reconciler.cancel != nil
	svcs.Reconciler.mu.Unlock()
	assert.True(t, started)
}

// Wiring the cleaner while a cascade reads it is race-free.
func TestWalletLifecycle_SetSessionCleanerIsRaceFree(t *testing.T) {
	svc, store, userID, _ := twoTenantFixture(t)
	revokeSilently(t, store, userID)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		svc.SetSessionCleaner(&fakeSessionCleaner{})
	}()
	go func() {
		defer wg.Done()
		_, _ = svc.ReconcileUser(context.Background(), userID, inTheFuture())
	}()
	wg.Wait()
}
