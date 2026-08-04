package service

import (
	"context"
	"time"
)

// memoryWIAChallengeStore wraps the existing in-memory challengeStore
// to satisfy the WIAChallengeStore interface.
type memoryWIAChallengeStore struct {
	store *challengeStore
}

func newMemoryWIAChallengeStore(maxSize int) *memoryWIAChallengeStore {
	return &memoryWIAChallengeStore{
		store: newChallengeStore(maxSize),
	}
}

func (m *memoryWIAChallengeStore) Put(_ context.Context, challenge string, expiresAt time.Time) (bool, error) {
	c := &WIAChallenge{
		Challenge: challenge,
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
