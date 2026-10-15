package server

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// SharedBlacklist is the token blacklist of a process that has no storage
// backend of its own (a standalone engine or registry), backed by the shared
// revocation collections.
type SharedBlacklist struct {
	*service.TokenBlacklist
	store backend.Backend
}

// Close releases the database connection.
func (b *SharedBlacklist) Close() error { return b.store.Close() }

// NewSharedBlacklist connects to the shared revocation store for a process
// without a storage backend, so it rejects the revocations made by the
// backend replicas. It returns nil when revocations are not shared
// (blacklist disabled, or backend memory, or unset with non-MongoDB storage):
// a process-local blacklist in such a process would never see a revocation.
// A configured but unreachable store is an error, never a silent fallback.
func NewSharedBlacklist(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*SharedBlacklist, error) {
	warnProcessLocalState(cfg, logger, false)
	bl := cfg.Security.TokenBlacklist
	if !bl.Enabled || bl.Backend == config.TokenBlacklistBackendMemory ||
		(bl.Backend == "" && cfg.Storage.Type != "mongodb") {
		return nil, nil
	}
	store, err := backend.New(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("revocation store: %w", err)
	}
	rs, err := service.NewRevocationStore(ctx, bl, store, logger)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("revocation store: %w", err)
	}
	return &SharedBlacklist{TokenBlacklist: service.NewTokenBlacklistWithStore(bl, logger, rs), store: store}, nil
}
