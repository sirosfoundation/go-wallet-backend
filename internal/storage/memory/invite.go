package memory

import (
	"context"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// InviteStore implements in-memory invite storage
type InviteStore struct {
	mu   sync.RWMutex
	data map[string]*domain.Invite
}

func (s *InviteStore) Create(ctx context.Context, invite *domain.Invite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[invite.ID]; exists {
		return storage.ErrAlreadyExists
	}
	s.data[invite.ID] = invite
	return nil
}

func (s *InviteStore) GetByCode(ctx context.Context, tenantID domain.TenantID, code string) (*domain.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inv := range s.data {
		if inv.TenantID == tenantID && inv.Code == code {
			return inv, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *InviteStore) GetByID(ctx context.Context, id string) (*domain.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.data[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return inv, nil
}

func (s *InviteStore) GetAllByTenant(ctx context.Context, tenantID domain.TenantID) ([]*domain.Invite, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*domain.Invite
	for _, inv := range s.data {
		if inv.TenantID == tenantID {
			result = append(result, inv)
		}
	}
	return result, nil
}

func (s *InviteStore) MarkCompleted(ctx context.Context, tenantID domain.TenantID, code string, usedBy domain.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inv := range s.data {
		if inv.TenantID == tenantID && inv.Code == code && inv.Status == domain.InviteStatusActive {
			inv.Status = domain.InviteStatusCompleted
			inv.UsedBy = &usedBy
			inv.UpdatedAt = time.Now()
			return nil
		}
	}
	return storage.ErrNotFound
}

func (s *InviteStore) Update(ctx context.Context, invite *domain.Invite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[invite.ID]; !exists {
		return storage.ErrNotFound
	}
	invite.UpdatedAt = time.Now()
	s.data[invite.ID] = invite
	return nil
}

func (s *InviteStore) Delete(ctx context.Context, tenantID domain.TenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, exists := s.data[id]
	if !exists || inv.TenantID != tenantID {
		return storage.ErrNotFound
	}
	delete(s.data, id)
	return nil
}
