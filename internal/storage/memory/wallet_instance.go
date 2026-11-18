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
	undo map[string]*storage.UndoLog[domain.WalletInstance]
	// now is the clock the undo log ages by; nil means time.Now.
	now func() time.Time
}

func (s *WalletInstanceStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// logFor returns the undo log of a record, creating it. Caller holds s.mu.
func (s *WalletInstanceStore) logFor(id string) *storage.UndoLog[domain.WalletInstance] {
	if s.undo == nil {
		s.undo = make(map[string]*storage.UndoLog[domain.WalletInstance])
	}
	l, ok := s.undo[id]
	if !ok {
		l = &storage.UndoLog[domain.WalletInstance]{}
		s.undo[id] = l
	}
	return l
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
		before := cloneInstance(existing)
		existing.WriteToken = uuid.NewString()
		instance.WriteToken = existing.WriteToken
		s.logFor(instance.ID).Push(s.clock(), existing.WriteToken, before)
		existing.AttestationSource = instance.AttestationSource
		existing.VerifiedAppID = instance.VerifiedAppID
		if instance.WSCDType != "" {
			existing.WSCDType = instance.WSCDType
		}
		existing.LastAttestedAt = instance.LastAttestedAt
		existing.UpdatedAt = instance.UpdatedAt
		existing.AttestationCount++
		// Bind and link only while live: a revocation landing between the caller's
		// status check and this write must not gain an owner or a passkey link.
		// First user binding wins (see the Mongo implementation and WIAService.signWIA).
		if existing.UserID == nil && instance.UserID != nil && existing.Status.IsLive() {
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
		if existing.Status.IsLive() && existing.CredentialID == "" && instance.CredentialID != "" &&
			(instance.UserID == nil || (existing.UserID != nil && *existing.UserID == *instance.UserID)) {
			existing.CredentialID = instance.CredentialID
		}
		// Reported as the Mongo store does: bind and link ran against this generation.
		instance.Generation = existing.Generation
		instance.Inserted = false
	} else {
		instance.AttestationCount = 1
		instance.WriteToken = uuid.NewString()
		s.logFor(instance.ID).Push(s.clock(), instance.WriteToken, nil)
		instance.Inserted = true
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
	delete(s.undo, id)
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
	delete(s.undo, id)
	return nil
}

// RestoreAttestation undoes the Upsert that set written.WriteToken and matched
// an existing record (see undoLog): when it is the newest attestation the fields
// go back to the record it replaced, including that record's write token; when
// newer attestations sit on top it is spliced out and their values stay, only
// the attestation counter is undone (a newer attestation may rely on the owner
// or passkey link this one set, so those stay). The
// caller's before is ignored: the record's own undo log says what was replaced.
// An Upsert that inserted the record has nothing to restore (ErrBindingChanged).
func (s *WalletInstanceStore) RestoreAttestation(_ context.Context, _, written *domain.WalletInstance) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	inst, ok := s.data[written.ID]
	if !ok || inst.TenantID != written.TenantID {
		return storage.ErrNotFound
	}
	if inst.Generation != written.Generation {
		return storage.ErrBindingChanged
	}
	log := s.logFor(written.ID)
	before, found := log.Peek(s.clock(), written.WriteToken)
	if !found || before == nil {
		// A write that is no longer on the record (or none of ours): nothing to undo.
		return storage.ErrBindingChanged
	}
	kind, _ := log.Take(s.clock(), written.WriteToken)
	if kind == storage.UndoHead {
		inst.WriteToken = before.WriteToken
		inst.AttestationSource = before.AttestationSource
		inst.VerifiedAppID = before.VerifiedAppID
		inst.WSCDType = before.WSCDType
		inst.LastAttestedAt = before.LastAttestedAt
		inst.UpdatedAt = before.UpdatedAt
		if before.DeviceInfo != nil {
			d := *before.DeviceInfo
			inst.DeviceInfo = &d
		} else {
			inst.DeviceInfo = nil
		}
		// Only the newest attestation unbinds: a newer one that found the owner or
		// link already set may rely on it, so a spliced-out write leaves them.
		if before.UserID == nil && inst.UserID != nil && written.UserID != nil && *inst.UserID == *written.UserID {
			inst.UserID = nil
		}
		if before.CredentialID == "" && written.CredentialID != "" && inst.CredentialID == written.CredentialID {
			inst.CredentialID = ""
		}
	}
	inst.AttestationCount--
	return nil
}

func (s *WalletInstanceStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[id]; !ok {
		return storage.ErrNotFound
	}
	delete(s.data, id)
	delete(s.undo, id)
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
	delete(s.undo, id)
	return nil
}
