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

	stored := *rec.Clone()
	stored.Normalize()
	if existing, ok := s.data[rec.KeyThumbprint]; ok {
		// Never overwrite with weaker or absent evidence.
		if !stored.Supersedes(existing) {
			return nil
		}
		stored.CreatedAt = existing.CreatedAt
	} else if stored.CreatedAt.IsZero() {
		stored.CreatedAt = time.Now().UTC()
	}
	s.data[rec.KeyThumbprint] = &stored
	rec.CreatedAt = stored.CreatedAt
	return nil
}

func (s *KeyAttestationStore) GetByKeyThumbprint(_ context.Context, thumbprint string) (*domain.KeyAttestationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if rec, ok := s.data[thumbprint]; ok {
		out := rec.Clone()
		out.Normalize()
		return out, nil
	}
	return nil, storage.ErrNotFound
}

// MarkKeyRevoked implements storage.KeyAttestationStore.
func (s *KeyAttestationStore) MarkKeyRevoked(_ context.Context, thumbprint, chainFingerprint, reason string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.data[thumbprint]
	if !ok || rec.Revoked() || rec.ChainFingerprint != chainFingerprint {
		return false, nil
	}
	rec.RevokedAt = at.UTC()
	rec.RevokedReason = reason
	return true, nil
}
