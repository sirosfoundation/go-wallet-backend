package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

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
		// The key is global but the record belongs to one tenant, so another
		// tenant's attestation must not touch it at all.
		if existing.TenantID != instance.TenantID {
			return storage.ErrAlreadyExists
		}
		// Status and tenant are left untouched: lifecycle changes go through
		// UpdateStatus, so re-attestation cannot reactivate or re-parent an instance.
		existing.AttestationSource = instance.AttestationSource
		existing.LastAttestedAt = instance.LastAttestedAt
		existing.UpdatedAt = instance.UpdatedAt
		existing.AttestationCount++
		// First user binding wins (see the Mongo implementation and WIAService.signWIA).
		if existing.UserID == nil && instance.UserID != nil {
			// Copied so a caller's later mutation cannot re-parent the instance.
			u := *instance.UserID
			existing.UserID = &u
		}
		if instance.DeviceInfo != nil {
			// Copied so the caller cannot mutate the stored record.
			d := *instance.DeviceInfo
			existing.DeviceInfo = &d
		}
		// First non-empty passkey link wins, so a later attestation cannot move the
		// instance past per-instance login gating (SID-AUTH-06). An authenticated
		// attestation may write it only onto a record it owns, so a racer whose bind
		// lost cannot set it; an unauthenticated one keeps plain first-link-wins.
		if existing.CredentialID == "" && instance.CredentialID != "" &&
			(instance.UserID == nil || (existing.UserID != nil && *existing.UserID == *instance.UserID)) {
			existing.CredentialID = instance.CredentialID
		}
		// Reported as the Mongo store does: bind and link ran against this generation.
		instance.Generation = existing.Generation
	} else {
		instance.AttestationCount = 1
		// Fresh generation per insert: a re-attested record is a different record to a conditional write.
		instance.Generation = uuid.NewString()
		if instance.CreatedAt.IsZero() {
			instance.CreatedAt = time.Now().UTC()
		}
		s.data[instance.ID] = cloneInstance(instance)
	}
	return nil
}

// cloneInstance copies a record, as a database would return a fresh struct, so
// callers cannot race with or mutate the stored one.
func cloneInstance(in *domain.WalletInstance) *domain.WalletInstance {
	cp := *in
	if in.UserID != nil {
		u := *in.UserID
		cp.UserID = &u
	}
	if in.DeactivatedAt != nil {
		t := *in.DeactivatedAt
		cp.DeactivatedAt = &t
	}
	// Copy the pointer fields (SecurityProperties holds slices) too.
	if in.DeviceInfo != nil {
		d := *in.DeviceInfo
		cp.DeviceInfo = &d
	}
	if in.SecurityProperties != nil {
		sp := *in.SecurityProperties
		sp.KeyStorage = append([]string(nil), in.SecurityProperties.KeyStorage...)
		sp.UserAuthentication = append([]string(nil), in.SecurityProperties.UserAuthentication...)
		cp.SecurityProperties = &sp
	}
	return &cp
}

// cloneBinding copies a binding whose Owner points into caller memory.
func cloneBinding(in domain.InstanceBinding) domain.InstanceBinding {
	if in.Owner != nil {
		o := *in.Owner
		in.Owner = &o
	}
	return in
}

func (s *WalletInstanceStore) GetByID(_ context.Context, id string) (*domain.WalletInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if instance, ok := s.data[id]; ok {
		return cloneInstance(instance), nil
	}
	return nil, storage.ErrNotFound
}

func (s *WalletInstanceStore) GetAllByTenant(_ context.Context, tenantID domain.TenantID) ([]*domain.WalletInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*domain.WalletInstance
	for _, instance := range s.data {
		if instance.TenantID == tenantID {
			result = append(result, cloneInstance(instance))
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
			result = append(result, cloneInstance(instance))
		}
	}
	return result, nil
}

// GetAllByUser lists every instance of the user across all tenants.
func (s *WalletInstanceStore) GetAllByUser(_ context.Context, userID domain.UserID) ([]*domain.WalletInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*domain.WalletInstance
	for _, instance := range s.data {
		if instance.UserID != nil && *instance.UserID == userID {
			result = append(result, cloneInstance(instance))
		}
	}
	return result, nil
}

func (s *WalletInstanceStore) UpdateStatus(_ context.Context, id string, tenantID domain.TenantID, status domain.InstanceStatus, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateStatusLocked(id, tenantID, nil, nil, status, reason)
}

func (s *WalletInstanceStore) UpdateStatusForUser(_ context.Context, id string, tenantID domain.TenantID, userID domain.UserID, status domain.InstanceStatus, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateStatusLocked(id, tenantID, &userID, nil, status, reason)
}

// UpdateStatusIfUnchanged revokes only while owner and generation still match.
func (s *WalletInstanceStore) UpdateStatusIfUnchanged(_ context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding, status domain.InstanceStatus, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding := cloneBinding(expected)
	return s.updateStatusLocked(id, tenantID, nil, &binding, status, reason)
}

// DeleteIfUnchanged deletes only while owner and generation still match.
func (s *WalletInstanceStore) DeleteIfUnchanged(_ context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expected = cloneBinding(expected)
	inst, ok := s.data[id]
	if !ok || inst.TenantID != tenantID {
		return storage.ErrNotFound
	}
	if !expected.Matches(inst) {
		return storage.ErrBindingChanged
	}
	delete(s.data, id)
	return nil
}

// updateStatusLocked is the shared body of the status updates; owner and
// binding, when non-nil, are part of the match (ErrBindingChanged on mismatch).
// The caller holds s.mu.
func (s *WalletInstanceStore) updateStatusLocked(id string, tenantID domain.TenantID, owner *domain.UserID, binding *domain.InstanceBinding, status domain.InstanceStatus, reason string) error {
	instance, ok := s.data[id]
	if !ok || instance.TenantID != tenantID {
		return storage.ErrNotFound
	}
	if owner != nil && (instance.UserID == nil || *instance.UserID != *owner) {
		return storage.ErrNotFound
	}
	if binding != nil && !binding.Matches(instance) {
		return storage.ErrBindingChanged
	}

	// Revocation is the only status written, as in Mongo; "active" is refused
	// rather than treated as a no-op that stamps a revocation time.
	if status != domain.InstanceStatusRevoked {
		return fmt.Errorf("%w: cannot set wallet instance status to %q", domain.ErrInvalidStatusTransition, status)
	}
	// An already-revoked record is refused, not re-stamped: Mongo's conditional
	// filter matches nothing and answers ErrInvalidStatusTransition, which the WIA
	// compensating path reads as "someone else already revoked this".
	if instance.Status == domain.InstanceStatusRevoked {
		return fmt.Errorf("%w: wallet instance is already revoked", domain.ErrInvalidStatusTransition)
	}
	if err := domain.ValidateStatusTransition(instance.Status, status); err != nil {
		return err
	}

	instance.Status = status
	now := time.Now().UTC()
	instance.UpdatedAt = now
	instance.DeactivatedAt = &now
	instance.DeactivationReason = reason
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

// DeleteIfRemovable deletes only while the instance is still removable.
func (s *WalletInstanceStore) DeleteIfRemovable(_ context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	expected = cloneBinding(expected)
	inst, ok := s.data[id]
	if !ok || inst.TenantID != tenantID {
		return storage.ErrNotFound
	}
	if !expected.Matches(inst) {
		return storage.ErrBindingChanged
	}
	if !inst.Status.IsLive() {
		return domain.ErrInvalidStatusTransition
	}
	delete(s.data, id)
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

// DeleteForUser deletes only while the record is in tenantID and bound to userID.
func (s *WalletInstanceStore) DeleteForUser(_ context.Context, id string, tenantID domain.TenantID, userID domain.UserID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	inst, ok := s.data[id]
	if !ok || inst.TenantID != tenantID || inst.UserID == nil || *inst.UserID != userID {
		return storage.ErrNotFound
	}
	delete(s.data, id)
	return nil
}
