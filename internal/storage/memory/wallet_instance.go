package memory

import (
	"context"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// WalletInstanceStore implements storage.WalletInstanceStore in memory.
type WalletInstanceStore struct {
	mu   sync.RWMutex
	data map[string]*domain.WalletInstance
}

func (s *WalletInstanceStore) Upsert(_ context.Context, instance *domain.WalletInstance) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.data[instance.ID]; ok {
		existing.Status = instance.Status
		existing.AttestationSource = instance.AttestationSource
		existing.LastAttestedAt = instance.LastAttestedAt
		existing.UpdatedAt = instance.UpdatedAt
		existing.AttestationCount++
		if instance.UserID != nil {
			existing.UserID = instance.UserID
		}
		if instance.DeviceInfo != nil {
			existing.DeviceInfo = instance.DeviceInfo
		}
	} else {
		instance.AttestationCount = 1
		if instance.CreatedAt.IsZero() {
			instance.CreatedAt = time.Now().UTC()
		}
		s.data[instance.ID] = instance
	}
	return nil
}

func (s *WalletInstanceStore) GetByID(_ context.Context, id string) (*domain.WalletInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if instance, ok := s.data[id]; ok {
		return instance, nil
	}
	return nil, storage.ErrNotFound
}

func (s *WalletInstanceStore) GetAllByTenant(_ context.Context, tenantID domain.TenantID) ([]*domain.WalletInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*domain.WalletInstance
	for _, instance := range s.data {
		if instance.TenantID == tenantID {
			result = append(result, instance)
		}
	}
	return result, nil
}

func (s *WalletInstanceStore) GetByUser(_ context.Context, tenantID domain.TenantID, userID domain.UserID) ([]*domain.WalletInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*domain.WalletInstance
	for _, instance := range s.data {
		if instance.TenantID == tenantID && instance.UserID != nil && *instance.UserID == userID {
			result = append(result, instance)
		}
	}
	return result, nil
}

func (s *WalletInstanceStore) UpdateStatus(_ context.Context, id string, status domain.InstanceStatus, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	instance, ok := s.data[id]
	if !ok {
		return storage.ErrNotFound
	}

	if err := domain.ValidateStatusTransition(instance.Status, status); err != nil {
		return err
	}

	instance.Status = status
	instance.UpdatedAt = time.Now().UTC()
	if status == domain.InstanceStatusSuspended || status == domain.InstanceStatusRevoked {
		now := time.Now().UTC()
		instance.DeactivatedAt = &now
		instance.DeactivationReason = reason
	} else {
		instance.DeactivatedAt = nil
		instance.DeactivationReason = ""
	}
	return nil
}

func (s *WalletInstanceStore) IncrementAttestation(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	instance, ok := s.data[id]
	if !ok {
		return storage.ErrNotFound
	}

	instance.AttestationCount++
	instance.LastAttestedAt = time.Now().UTC()
	instance.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *WalletInstanceStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[id]; !ok {
		return storage.ErrNotFound
	}
	delete(s.data, id)
	return nil
}
