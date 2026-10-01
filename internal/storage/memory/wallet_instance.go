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
		// The instance key is global while the record belongs to one tenant
		// (the tenant is fixed at insert), so an attestation from another
		// tenant must not touch this record at all - not even its
		// attestation metadata. Callers map this to a refusal.
		if existing.TenantID != instance.TenantID {
			return storage.ErrAlreadyExists
		}
		// Status and tenant are intentionally left untouched here — lifecycle
		// changes only happen through UpdateStatus, and an instance never
		// moves tenant (see the Mongo implementation). Otherwise a routine
		// re-attestation would silently reactivate a revoked instance or
		// re-parent it.
		existing.AttestationSource = instance.AttestationSource
		existing.LastAttestedAt = instance.LastAttestedAt
		existing.UpdatedAt = instance.UpdatedAt
		existing.AttestationCount++
		// First user binding wins; a bound instance is never re-parented here
		// (see the Mongo implementation and WIAService.signWIA's read-back).
		if existing.UserID == nil && instance.UserID != nil {
			// Copied: the caller's pointer must not stay an alias of the
			// stored owner, or mutating it later would re-parent the instance
			// and change which user's login is gated.
			u := *instance.UserID
			existing.UserID = &u
		}
		if instance.DeviceInfo != nil {
			// Copied, so a caller that keeps mutating its own struct cannot
			// change the stored record.
			d := *instance.DeviceInfo
			existing.DeviceInfo = &d
		}
		// The passkey link is client-supplied; the first non-empty binding
		// is kept so a later attestation cannot move the instance to another
		// passkey and slip past per-instance login gating. An authenticated
		// attestation may only write it onto the record it actually owns, for
		// the same reason: the link is permanent and decides that gate
		// (SID-AUTH-06), so a racer whose bind just lost must not set it. An
		// unauthenticated one has no user to check against and keeps the
		// plain first-link-wins rule (see the Mongo implementation).
		if existing.CredentialID == "" && instance.CredentialID != "" &&
			(instance.UserID == nil || (existing.UserID != nil && *existing.UserID == *instance.UserID)) {
			existing.CredentialID = instance.CredentialID
		}
	} else {
		instance.AttestationCount = 1
		// A fresh generation per insert: a record deleted and attested again
		// under the same id is a different record to a conditional write.
		instance.Generation = uuid.NewString()
		if instance.CreatedAt.IsZero() {
			instance.CreatedAt = time.Now().UTC()
		}
		s.data[instance.ID] = cloneInstance(instance)
	}
	return nil
}

// cloneInstance copies a record, as a database would hand back a fresh
// decoded struct rather than a pointer into its own storage. Sharing pointers
// lets a caller's read race a concurrent write and lets a caller's local
// mutation change the stored record, neither of which can happen against
// MongoDB, so tests over this store would prove less than they appear to.
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
	// DeviceInfo and SecurityProperties are pointers too, and the latter
	// holds slices: copy them all, or a caller mutating a returned instance
	// changes the stored record and races with metadata updates.
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

// cloneBinding copies a binding, whose Owner is a pointer into the caller's
// memory. The conditional operations only read it, but a caller mutating it
// concurrently would race with the comparison, and Mongo takes a value copy.
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

// GetAllByUser lists every instance of the user across all tenants. See the
// interface for why account deletion cannot use the per-tenant listing.
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

// UpdateStatusIfUnchanged revokes only while the record still matches the
// expected owner and generation. See the interface.
func (s *WalletInstanceStore) UpdateStatusIfUnchanged(_ context.Context, id string, tenantID domain.TenantID, expected domain.InstanceBinding, status domain.InstanceStatus, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	binding := cloneBinding(expected)
	return s.updateStatusLocked(id, tenantID, nil, &binding, status, reason)
}

// DeleteIfUnchanged deletes only while the record still matches the expected
// owner and generation. See the interface.
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

// updateStatusLocked is the shared body of UpdateStatus and
// UpdateStatusForUser; owner, when non-nil, is part of the match, and so is
// binding (owner and generation) when non-nil, answering ErrBindingChanged on
// a mismatch. The caller holds s.mu.
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

	// Revocation is the only status this writes, exactly as the Mongo
	// implementation does: an instance is active from insert and can never
	// be returned to it, so "active" is refused here rather than treated as
	// a no-op that would still stamp a revocation time.
	if status != domain.InstanceStatusRevoked {
		return fmt.Errorf("%w: cannot set wallet instance status to %q", domain.ErrInvalidStatusTransition, status)
	}
	// An already-revoked record is refused rather than re-stamped.
	// ValidateStatusTransition treats a same-state write as a no-op, which is
	// right for a caller asking "may this transition happen"; it is wrong
	// here, because Mongo's conditional filter matches nothing and answers
	// ErrInvalidStatusTransition. Callers depend on that answer - the WIA
	// compensating path reads it as "someone else already revoked this" -
	// so the two stores must not disagree.
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

// DeleteIfRemovable deletes only while the instance is still removable. See
// the interface for why a tombstone must survive a racing revocation.
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
	if !inst.Status.IsLive() && inst.UserID != nil {
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

// DeleteForUser deletes only while the record is still in tenantID and bound
// to userID. See the interface for why the owner travels with the delete.
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
