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
	undo map[string]*storage.UndoLog[domain.KeyAttestationRecord]
	// now is the clock the undo log ages by; nil means time.Now.
	now func() time.Time
}

func (s *KeyAttestationStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// logFor returns the undo log of a record, creating it. Caller holds s.mu.
func (s *KeyAttestationStore) logFor(thumbprint string) *storage.UndoLog[domain.KeyAttestationRecord] {
	if s.undo == nil {
		s.undo = make(map[string]*storage.UndoLog[domain.KeyAttestationRecord])
	}
	l, ok := s.undo[thumbprint]
	if !ok {
		l = &storage.UndoLog[domain.KeyAttestationRecord]{}
		s.undo[thumbprint] = l
	}
	return l
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
	var before *domain.KeyAttestationRecord
	if rec.Previous != nil {
		before = s.data[rec.KeyThumbprint].Clone()
	}
	s.data[rec.KeyThumbprint] = &stored
	s.logFor(rec.KeyThumbprint).Push(s.clock(), stored.WriteToken, before)
	rec.CreatedAt = stored.CreatedAt
	rec.WriteToken = stored.WriteToken
	return nil
}

// DeleteIfUnchanged undoes the write that set writeToken (see undoLog): a first
// insert is deleted, an overwrite goes back to the record it replaced. Writes
// made on top of it since are not undone. ErrNotFound if the token is not one of
// the record's recent writes.
func (s *KeyAttestationStore) DeleteIfUnchanged(_ context.Context, thumbprint, writeToken string) error {
	return s.rollback(thumbprint, writeToken)
}

// RestoreIfUnchanged undoes the write that set written.WriteToken, exactly as
// DeleteIfUnchanged does; previous is ignored: the record's own undo log, not
// what the caller read, says what the write replaced.
func (s *KeyAttestationStore) RestoreIfUnchanged(_ context.Context, written, previous *domain.KeyAttestationRecord) error {
	return s.rollback(written.KeyThumbprint, written.WriteToken)
}

func (s *KeyAttestationStore) rollback(thumbprint, writeToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[thumbprint]; !ok {
		return storage.ErrNotFound
	}
	kind, before := s.logFor(thumbprint).Take(s.clock(), writeToken)
	switch kind {
	case storage.UndoHead:
		if before == nil {
			delete(s.data, thumbprint)
			delete(s.undo, thumbprint)
			return nil
		}
		s.data[thumbprint] = before.Clone()
		return nil
	case storage.UndoSpliced:
		return nil
	}
	return storage.ErrNotFound
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
	// A new write: the revocation is on top of the log, so a rollback of the
	// write that stored this record is spliced out below it and cannot undo it.
	before := rec.Clone()
	rec.WriteToken = storage.NewWriteToken()
	s.logFor(thumbprint).Push(s.clock(), rec.WriteToken, before)
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
	stored.WriteToken = storage.NewWriteToken() // a replacement is a new write, on top of the undo log
	before := existing.Clone()
	s.data[rec.KeyThumbprint] = &stored
	s.logFor(rec.KeyThumbprint).Push(s.clock(), stored.WriteToken, before)
	rec.CreatedAt = stored.CreatedAt
	rec.WriteToken = stored.WriteToken
	return true, nil
}
