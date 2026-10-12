package service

import (
	"context"
	"sync"
	"time"
)

// RevocationStore holds the state that must be shared by every process that
// validates tokens: individually revoked jtis and revoked users. Callers
// never pass empty identifiers; the config.Enabled gate lives in
// TokenBlacklist, not in the store.
type RevocationStore interface {
	// Add revokes jti until expiry (the token's own exp).
	Add(ctx context.Context, jti string, expiry time.Time) error
	// Has reports whether jti is revoked and its entry has not expired.
	Has(ctx context.Context, jti string) bool
	// RevokeUser permanently revokes every token for userID.
	RevokeUser(ctx context.Context, userID string) error
	// IsUserRevoked reports whether userID was revoked via RevokeUser.
	IsUserRevoked(ctx context.Context, userID string) bool
}

// memoryRevocationStore is the process-local RevocationStore. It borrows the
// owning TokenBlacklist's lock and jti map, so the jti entries stay in one
// place for the cleanup sweep and for ConsumeOnce.
type memoryRevocationStore struct {
	mu     *sync.RWMutex
	tokens map[string]time.Time // jti -> expiry
	users  map[string]bool      // userID -> permanently revoked
}

func (s *memoryRevocationStore) Add(_ context.Context, jti string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[jti] = expiry
	return nil
}

func (s *memoryRevocationStore) Has(_ context.Context, jti string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	expiry, exists := s.tokens[jti]
	return exists && !time.Now().After(expiry)
}

func (s *memoryRevocationStore) RevokeUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[userID] = true
	return nil
}

func (s *memoryRevocationStore) IsUserRevoked(_ context.Context, userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[userID]
}
