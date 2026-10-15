package service

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// outcomeFailed counts a user whose reconciliation returned an error.
const outcomeFailed ReconcileOutcome = "failed"

// ReconcileStats counts what one reconciler run did, by outcome.
type ReconcileStats struct {
	Scanned, Clean, Live, Grace, Erased, WouldErase, Failed int
}

func (s *ReconcileStats) add(o ReconcileOutcome) {
	s.Scanned++
	switch o {
	case ReconcileClean:
		s.Clean++
	case ReconcileLive:
		s.Live++
	case ReconcileGrace:
		s.Grace++
	case ReconcileErased:
		s.Erased++
	case ReconcileWouldErase:
		s.WouldErase++
	default:
		s.Failed++
	}
	reconcilerUsersTotal.WithLabelValues(string(o)).Inc()
}

// ErasureReconciler periodically finishes the erasure of deactivated wallets
// (WalletLifecycleService.ReconcileUser). Replicas need no coordination: the
// cascade is idempotent and the liveness check runs under the user's lock
// immediately before erasing.
type ErasureReconciler struct {
	lifecycle *WalletLifecycleService
	store     storage.Store
	interval  time.Duration
	grace     time.Duration
	batch     int
	dryRun    bool
	logger    *zap.Logger
	// now is the clock; tests replace it.
	now func() time.Time

	// runMu serializes runs and guards cursor, the last user examined. A run
	// resumes after it and wraps to the start at the end of the user list; a
	// run cut short never moves it past a user it did not examine.
	runMu  sync.Mutex
	cursor domain.UserID

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewErasureReconciler creates a reconciler over the store's wallet instances.
func NewErasureReconciler(cfg config.ErasureReconcilerConfig, lifecycle *WalletLifecycleService, store storage.Store, logger *zap.Logger) *ErasureReconciler {
	cfg.SetDefaults()
	return &ErasureReconciler{
		lifecycle: lifecycle,
		store:     store,
		interval:  time.Duration(cfg.IntervalSeconds) * time.Second,
		grace:     time.Duration(cfg.GracePeriodSeconds) * time.Second,
		batch:     cfg.BatchSize,
		dryRun:    cfg.DryRun,
		logger:    logger.Named("erasure-reconciler"),
		now:       time.Now,
		// A random start spreads replicas, and restarts, over the user list.
		cursor: domain.UserIDFromString(uuid.NewString()),
	}
}

// Start begins reconciling in the background after a short random delay,
// then every interval (jittered). A running reconciler is left alone; a Start
// racing a Stop waits for it and starts a fresh run.
func (r *ErasureReconciler) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.wg.Add(1)
	go r.run(ctx)
	if r.dryRun {
		reconcilerDryRun.Set(1)
		r.logger.Warn("Erasure reconciler is in DRY-RUN mode: it only reports what it would erase and erases nothing; set lifecycle.reconciler.dry_run=false to erase",
			zap.Duration("interval", r.interval), zap.Duration("grace_period", r.grace), zap.Int("batch_size", r.batch))
		return
	}
	reconcilerDryRun.Set(0)
	r.logger.Info("Erasure reconciler started",
		zap.Duration("interval", r.interval), zap.Duration("grace_period", r.grace), zap.Int("batch_size", r.batch))
}

// Stop stops the reconciler and waits for a run in progress to end. As in
// DeletionTombstoneSweeper, the lock is held through the wait.
func (r *ErasureReconciler) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel == nil {
		return
	}
	r.cancel()
	r.cancel = nil
	r.wg.Wait()
	reconcilerDryRun.Set(0)
}

// jittered returns d plus or minus up to a tenth of it.
func jittered(d time.Duration) time.Duration {
	span := int64(d / 10)
	if span <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(2*span+1)-span)
}

func (r *ErasureReconciler) run(ctx context.Context) {
	defer r.wg.Done()
	timer := time.NewTimer(time.Duration(rand.Int64N(int64(r.interval/10) + 1)))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.reconcile(ctx)
			timer.Reset(jittered(r.interval))
		}
	}
}

func (r *ErasureReconciler) reconcile(ctx context.Context) {
	// A run never outlives its interval, so runs do not pile up.
	ctx, cancel := context.WithTimeout(ctx, r.interval)
	defer cancel()
	stats, err := r.RunOnce(ctx)
	if err != nil {
		r.logger.Error("Erasure reconciler run failed", zap.Error(err))
		return
	}
	if stats.Erased > 0 || stats.WouldErase > 0 || stats.Failed > 0 {
		r.logger.Info("Erasure reconciler run finished", zap.Bool("dry_run", r.dryRun),
			zap.Int("scanned", stats.Scanned), zap.Int("erased", stats.Erased), zap.Int("would_erase", stats.WouldErase), zap.Int("failed", stats.Failed),
			zap.Int("live", stats.Live), zap.Int("in_grace", stats.Grace), zap.Int("clean", stats.Clean))
	}
}

// RunOnce examines up to batch users with a revoked instance, from where the
// previous run stopped, and finishes the erasure of those that need it. A
// failure for one user is counted and does not stop the others; it is retried
// on a later pass over the list. An error is returned only when the user list
// cannot be read.
func (r *ErasureReconciler) RunOnce(ctx context.Context) (ReconcileStats, error) {
	r.runMu.Lock()
	defer r.runMu.Unlock()

	var stats ReconcileStats
	ids, err := r.store.WalletInstances().ListUsersWithRevokedInstances(ctx, r.cursor, r.batch)
	if err != nil {
		return stats, err
	}
	revokedBefore := r.now().Add(-r.grace)
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		var outcome ReconcileOutcome
		var err error
		if r.dryRun {
			var leftover []string
			outcome, leftover, err = r.lifecycle.ReconcileUserDryRun(ctx, id, revokedBefore)
			if outcome == ReconcileWouldErase {
				r.logger.Info("Erasure reconciler dry run: would erase", zap.String("user_id", id.String()), zap.Strings("leftover", leftover))
			}
		} else {
			outcome, err = r.lifecycle.ReconcileUser(ctx, id, revokedBefore)
		}
		if err != nil {
			if ctx.Err() != nil {
				break // interrupted mid-user: examine it again next run
			}
			// The cascade already logged its own failure; a probe failure is logged here.
			r.logger.Warn("Erasure reconciliation failed", zap.String("user_id", id.String()), zap.Error(err))
			outcome = outcomeFailed
		}
		stats.add(outcome)
		r.cursor = id
	}
	if len(ids) < r.batch && ctx.Err() == nil {
		r.cursor = domain.UserID{} // end of the list: start over next run
	}
	return stats, nil
}
