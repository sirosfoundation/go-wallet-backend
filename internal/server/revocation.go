package server

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/mongodb"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// SharedBlacklist is the token blacklist of a process that has no storage
// backend of its own (a standalone engine or registry), backed by the shared
// revocation collections.
type SharedBlacklist struct {
	*service.TokenBlacklist
	client *mongo.Client
}

// Close releases the database connection.
func (b *SharedBlacklist) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.Disconnect(ctx)
}

// NewSharedBlacklist connects to the shared revocation store for a process
// without a storage backend, so it rejects the revocations made by the
// backend replicas. Only the revocation collections are touched. It returns
// nil when revocations are not shared (blacklist disabled, or backend memory,
// or unset with non-MongoDB storage): a process-local blacklist in such a
// process would never see a revocation. A configured but unreachable store
// is an error, never a silent fallback; setup is bounded by
// service.RevocationInitTimeout.
func NewSharedBlacklist(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*SharedBlacklist, error) {
	warnProcessLocalState(cfg, logger, false)
	if !cfg.UsesSharedRevocationStore() {
		return nil, nil
	}
	if cfg.Storage.Type != "mongodb" {
		return nil, fmt.Errorf("revocation store: security.token_blacklist.backend=storage requires storage.type=mongodb")
	}
	ctx, cancel := context.WithTimeout(ctx, service.RevocationInitTimeout)
	defer cancel()
	client, err := mongodb.Connect(ctx, &cfg.Storage.MongoDB)
	if err != nil {
		return nil, fmt.Errorf("revocation store: %w", err)
	}
	rs, err := service.NewMongoRevocationStore(ctx, client.Database(cfg.Storage.MongoDB.Database))
	if err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("revocation store: %w", err)
	}
	logger.Info("Token revocation: MongoDB store (shared by replicas, survives restarts)")
	return &SharedBlacklist{
		TokenBlacklist: service.NewTokenBlacklistWithStore(cfg.Security.TokenBlacklist, logger, rs),
		client:         client,
	}, nil
}
