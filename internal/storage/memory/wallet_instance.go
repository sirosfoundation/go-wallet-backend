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
		// Status and tenant are intentionally left untouched here — lifecycle
		// changes only happen through UpdateStatus, and an instance never
		// moves tenant (see the Mongo implementation). Otherwise a routine
		// re-attestation would silently reactivate a suspended/revoked
		// instance or re-parent it.
		existing.AttestationSource = instance.AttestationSource
		existing.LastAttestedAt = instance.LastAttestedAt
		existing.UpdatedAt = instance.UpdatedAt
		existing.AttestationCount++
		// The ownership writes below only happen inside the record's own
		// tenant. The tenant is fixed at insert, so when two first
		// attestations of the same instance key race the loser cannot move
		// the record - but it could otherwise still bind its user or its
		// passkey onto the winner's record, which the read-back in
		// WIAService.signWIA refuses a WIA for yet cannot undo.
		sameTenant := existing.TenantID == instance.TenantID
		// First user binding wins; a bound instance is never re-parented here
		// (see the Mongo implementation and WIAService.signWIA's read-back).
		if sameTenant && existing.UserID == nil && instance.UserID != nil {
			existing.UserID = instance.UserID
		}
		if instance.DeviceInfo != nil {
			existing.DeviceInfo = instance.DeviceInfo
		}
		// The passkey link is client-supplied; the first non-empty binding
		// is kept so a later attestation cannot move the instance to another
		// passkey and slip past per-instance login gating. An authenticated
		// attestation may only write it onto the record it actually owns, for
		// the same reason: the link is permanent and decides that gate
		// (SID-AUTH-06), so a racer whose bind just lost must not set it. An
		// unauthenticated one has no user to check against and keeps the
		// plain first-link-wins rule (see the Mongo implementation).
		if sameTenant && existing.CredentialID == "" && instance.CredentialID != "" &&
			(instance.UserID == nil || (existing.UserID != nil && *existing.UserID == *instance.UserID)) {
			existing.CredentialID = instance.CredentialID
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
