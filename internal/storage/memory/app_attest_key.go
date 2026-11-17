package memory

import (
	"context"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// AppAttestKeyStore implements storage.AppAttestKeyStore in memory.
type AppAttestKeyStore struct {
	mu   sync.Mutex
	data map[string]*domain.AppAttestKeyRecord
}

func (s *AppAttestKeyStore) Create(_ context.Context, rec *domain.AppAttestKeyRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[rec.KeyID]; ok {
		return storage.ErrAlreadyExists
	}
	stored := rec.Clone()
	now := time.Now().UTC()
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	stored.UpdatedAt = stored.CreatedAt
	s.data[rec.KeyID] = stored
	return nil
}

func (s *AppAttestKeyStore) Get(_ context.Context, keyID string) (*domain.AppAttestKeyRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data[keyID]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return rec.Clone(), nil
}

func (s *AppAttestKeyStore) AdvanceCounter(_ context.Context, keyID string, next uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data[keyID]
	if !ok {
		return storage.ErrNotFound
	}
	if !rec.IsActive() || next <= rec.Counter {
		return storage.ErrCounterNotAdvanced
	}
	rec.Counter = next
	rec.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *AppAttestKeyStore) Revoke(_ context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.data[keyID]
	if !ok {
		return storage.ErrNotFound
	}
	rec.Status = domain.AppAttestKeyRevoked
	rec.UpdatedAt = time.Now().UTC()
	return nil
}
