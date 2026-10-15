package memory

import (
	"context"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// KeyAttestationStore implements storage.KeyAttestationStore in memory.
type KeyAttestationStore struct {
	mu   sync.RWMutex
	data map[string]*domain.KeyAttestationRecord
}

func (s *KeyAttestationStore) MarkKeyAttested(_ context.Context, rec *domain.KeyAttestationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec.Previous = nil
	if existing, ok := s.data[rec.KeyThumbprint]; ok {
		rec.CreatedAt = existing.CreatedAt
		prev := *existing
		prev.Previous = nil
		rec.Previous = &prev
	} else if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	rec.WriteToken = storage.NewWriteToken()
	s.data[rec.KeyThumbprint] = rec
	return nil
}

func (s *KeyAttestationStore) DeleteIfUnchanged(_ context.Context, thumbprint, writeToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.data[thumbprint]
	if !ok || writeToken == "" || rec.WriteToken != writeToken {
		return storage.ErrNotFound
	}
	delete(s.data, thumbprint)
	return nil
}

func (s *KeyAttestationStore) RestoreIfUnchanged(_ context.Context, written, previous *domain.KeyAttestationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.data[written.KeyThumbprint]
	if !ok || written.WriteToken == "" || cur.WriteToken != written.WriteToken || previous == nil {
		return storage.ErrNotFound
	}
	restored := *previous
	restored.KeyThumbprint = written.KeyThumbprint
	restored.Previous = nil
	restored.WriteToken = storage.NewWriteToken() // a restore is itself a new write
	s.data[written.KeyThumbprint] = &restored
	return nil
}

func (s *KeyAttestationStore) GetByKeyThumbprint(_ context.Context, thumbprint string) (*domain.KeyAttestationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if rec, ok := s.data[thumbprint]; ok {
		return rec, nil
	}
	return nil, storage.ErrNotFound
}
