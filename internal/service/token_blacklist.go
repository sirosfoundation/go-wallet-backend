package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// TokenBlacklist manages revoked JWT tokens
// Tokens are stored until their expiry time, then automatically cleaned up.
type TokenBlacklist struct {
	config config.TokenBlacklistConfig
	logger *zap.Logger

	mu       sync.RWMutex
	tokens   map[string]time.Time // jti -> expiry time
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewTokenBlacklist creates a new token blacklist
func NewTokenBlacklist(cfg config.TokenBlacklistConfig, logger *zap.Logger) *TokenBlacklist {
	cfg.SetDefaults()
	return &TokenBlacklist{
		config:   cfg,
		logger:   logger.Named("token-blacklist"),
		tokens:   make(map[string]time.Time),
		stopChan: make(chan struct{}),
	}
}

// Start begins the cleanup worker for expired blacklist entries
func (b *TokenBlacklist) Start() {
	if !b.config.Enabled {
		b.logger.Info("Token blacklist disabled")
		return
	}

	b.wg.Add(1)
	go b.cleanupLoop()

	b.logger.Info("Token blacklist started",
		zap.Int("cleanup_interval_seconds", b.config.CleanupIntervalSeconds),
	)
}

// Stop gracefully stops the blacklist cleanup worker
func (b *TokenBlacklist) Stop() {
	close(b.stopChan)
	b.wg.Wait()
	b.logger.Info("Token blacklist stopped")
}

// cleanupLoop periodically removes expired entries
func (b *TokenBlacklist) cleanupLoop() {
	defer b.wg.Done()

	ticker := time.NewTicker(time.Duration(b.config.CleanupIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopChan:
			return
		case <-ticker.C:
			b.cleanup()
		}
	}
}

// cleanup removes expired entries from the blacklist
func (b *TokenBlacklist) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	removed := 0

	for jti, expiry := range b.tokens {
		if now.After(expiry) {
			delete(b.tokens, jti)
			removed++
		}
	}

	if removed > 0 {
		b.logger.Debug("Cleaned up expired blacklist entries",
			zap.Int("removed", removed),
			zap.Int("remaining", len(b.tokens)),
		)
	}
}

// Add adds a token JTI to the blacklist
// The token will be automatically removed after its expiry time.
func (b *TokenBlacklist) Add(ctx context.Context, jti string, expiry time.Time) error {
	if !b.config.Enabled {
		return nil
	}

	if jti == "" {
		// Can't blacklist tokens without JTI
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.tokens[jti] = expiry

	b.logger.Debug("Token added to blacklist",
		zap.String("jti", jti),
		zap.Time("expiry", expiry),
	)

	return nil
}

// IsBlacklisted checks if a token JTI is on the blacklist
func (b *TokenBlacklist) IsBlacklisted(ctx context.Context, jti string) bool {
	if !b.config.Enabled {
		return false
	}

	if jti == "" {
		// Tokens without JTI can't be blacklisted
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	expiry, exists := b.tokens[jti]
	if !exists {
		return false
	}

	// Check if the blacklist entry has expired (token itself expired)
	if time.Now().After(expiry) {
		return false
	}

	return true
}

// Remove removes a token from the blacklist (if needed for admin override)
func (b *TokenBlacklist) Remove(ctx context.Context, jti string) error {
	if !b.config.Enabled {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.tokens, jti)

	b.logger.Debug("Token removed from blacklist",
		zap.String("jti", jti),
	)

	return nil
}

// Count returns the number of tokens currently on the blacklist
func (b *TokenBlacklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.tokens)
}
