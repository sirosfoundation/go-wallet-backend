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

	rec.WriteToken, rec.Previous = "", nil
	stored := *rec.Clone()
	stored.Normalize()
	stored.Previous = nil
	if existing, ok := s.data[rec.KeyThumbprint]; ok {
		// Never overwrite with weaker or absent evidence. Nothing written: no
		// write token, so a rollback of this call is a no-op.
		if !stored.Supersedes(existing) {
			return nil
		}
		stored.CreatedAt = existing.CreatedAt
		prev := *existing.Clone()
		prev.Previous = nil
		rec.Previous = &prev
	} else if stored.CreatedAt.IsZero() {
		stored.CreatedAt = time.Now().UTC()
	}
	stored.WriteToken = storage.NewWriteToken()
	s.data[rec.KeyThumbprint] = &stored
	rec.CreatedAt = stored.CreatedAt
	rec.WriteToken = stored.WriteToken
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
	restored := *previous.Clone()
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
	// A new write token: a rollback of the write that stored this record must
	// not undo the revocation.
	rec.WriteToken = storage.NewWriteToken()
	return true, nil
}

// ReplaceKeyEvidence implements storage.KeyAttestationStore.
func (s *KeyAttestationStore) ReplaceKeyEvidence(_ context.Context, rec *domain.KeyAttestationRecord, staleChainFingerprint string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.data[rec.KeyThumbprint]
	if !ok || existing.ChainFingerprint != staleChainFingerprint {
		return false, nil
	}
	stored := *rec.Clone()
	stored.Normalize()
	stored.CreatedAt = existing.CreatedAt
	stored.Previous = nil
	prev := *existing.Clone()
	prev.Previous = nil
	rec.Previous = &prev
	stored.WriteToken = storage.NewWriteToken() // a replacement is a new write: no earlier rollback may undo it
	s.data[rec.KeyThumbprint] = &stored
	rec.CreatedAt = stored.CreatedAt
	rec.WriteToken = stored.WriteToken
	return true, nil
}
