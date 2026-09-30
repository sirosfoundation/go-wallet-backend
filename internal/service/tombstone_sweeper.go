package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// DeletionTombstoneSweeper periodically removes expired account-deletion
// tombstones (domain.DeletionTombstone). MongoDB expires them with a TTL index
// as well; this sweeper is what expires them on a backend without one (the
// in-memory store) and the backstop where the TTL monitor lags.
type DeletionTombstoneSweeper struct {
	interval time.Duration
	store    storage.Store
	logger   *zap.Logger
	// now is the clock; tests replace it.
	now func() time.Time

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDeletionTombstoneSweeper creates a sweeper over the store's tombstones.
func NewDeletionTombstoneSweeper(cfg config.DeletionTombstoneConfig, store storage.Store, logger *zap.Logger) *DeletionTombstoneSweeper {
	cfg.SetDefaults()
	return &DeletionTombstoneSweeper{
		interval: time.Duration(cfg.CleanupIntervalSeconds) * time.Second,
		store:    store,
		logger:   logger.Named("tombstone-sweeper"),
		now:      time.Now,
	}
}

// Start begins sweeping in the background: once immediately, then every
// interval. Calling Start on a running sweeper does nothing.
func (w *DeletionTombstoneSweeper) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.wg.Add(1)
	go w.run(ctx)
	w.logger.Info("Deletion tombstone sweeper started", zap.Duration("interval", w.interval))
}

// Stop stops the sweeper and waits for a sweep in progress to end.
func (w *DeletionTombstoneSweeper) Stop() {
	w.mu.Lock()
	cancel := w.cancel
	w.cancel = nil
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	w.wg.Wait()
}

func (w *DeletionTombstoneSweeper) run(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	w.sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

func (w *DeletionTombstoneSweeper) sweep(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	n, err := w.RunOnce(ctx)
	if err != nil {
		w.logger.Error("Failed to sweep expired deletion tombstones", zap.Error(err))
		return
	}
	if n > 0 {
		w.logger.Info("Removed expired deletion tombstones", zap.Int("count", n))
	}
}

// RunOnce removes the tombstones that have expired by the sweeper's clock and
// returns how many it removed.
func (w *DeletionTombstoneSweeper) RunOnce(ctx context.Context) (int, error) {
	users := w.store.Users()
	if users == nil {
		return 0, nil // a backend with no user store has no tombstones
	}
	return users.DeleteExpiredDeletionTombstones(ctx, w.now())
}
