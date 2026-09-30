package service

import (
	"context"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// memoryWIAChallengeStore wraps the existing in-memory challengeStore
// to satisfy the WIAChallengeStore interface.
type memoryWIAChallengeStore struct {
	store *challengeStore
}

func newMemoryWIAChallengeStore(maxSize, maxSizePerTenant int) *memoryWIAChallengeStore {
	return &memoryWIAChallengeStore{
		store: newChallengeStore(maxSize, maxSizePerTenant),
	}
}

func (m *memoryWIAChallengeStore) Put(_ context.Context, tenantID domain.TenantID, challenge string, expiresAt time.Time) (bool, error) {
	c := &WIAChallenge{
		Challenge: challenge,
		TenantID:  tenantID,
		ExpiresAt: expiresAt,
	}
	return m.store.put(c), nil
}

func (m *memoryWIAChallengeStore) Consume(_ context.Context, challenge string) (bool, error) {
	_, ok := m.store.consume(challenge)
	return ok, nil
}

func (m *memoryWIAChallengeStore) Len(_ context.Context) (int, error) {
	return m.store.len(), nil
}
