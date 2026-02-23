package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// ChallengeCleanupWorker periodically cleans up expired WebAuthn challenges
// to prevent storage leaks from abandoned registrations/logins.
type ChallengeCleanupWorker struct {
	config config.ChallengeCleanupConfig
	store  storage.Store
	logger *zap.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewChallengeCleanupWorker creates a new challenge cleanup worker
func NewChallengeCleanupWorker(cfg config.ChallengeCleanupConfig, store storage.Store, logger *zap.Logger) *ChallengeCleanupWorker {
	cfg.SetDefaults()
	return &ChallengeCleanupWorker{
		config: cfg,
		store:  store,
		logger: logger.Named("challenge-cleanup"),
	}
}

// Start begins the cleanup worker in the background
func (w *ChallengeCleanupWorker) Start() {
	if !w.config.Enabled {
		w.logger.Info("Challenge cleanup worker disabled")
		return
	}

	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.wg.Add(1)

	go w.run()

	w.logger.Info("Challenge cleanup worker started",
		zap.Int("interval_seconds", w.config.IntervalSeconds),
	)
}

// Stop gracefully stops the cleanup worker
func (w *ChallengeCleanupWorker) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
	w.logger.Info("Challenge cleanup worker stopped")
}

// run is the main worker loop
func (w *ChallengeCleanupWorker) run() {
	defer w.wg.Done()

	ticker := time.NewTicker(time.Duration(w.config.IntervalSeconds) * time.Second)
	defer ticker.Stop()

	// Run once immediately on startup
	w.cleanup()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.cleanup()
		}
	}
}

// cleanup performs a single cleanup pass
func (w *ChallengeCleanupWorker) cleanup() {
	ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
	defer cancel()

	err := w.store.Challenges().DeleteExpired(ctx)
	if err != nil {
		w.logger.Error("Failed to cleanup expired challenges",
			zap.Error(err),
		)
		return
	}

	w.logger.Debug("Completed challenge cleanup pass")
}

// RunOnce runs a single cleanup pass (useful for testing)
func (w *ChallengeCleanupWorker) RunOnce(ctx context.Context) error {
	return w.store.Challenges().DeleteExpired(ctx)
}
