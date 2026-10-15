package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirosfoundation/go-siros-set/set"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
)

// ErrWalletInstanceNotOwned is returned when a user-initiated change names an
// instance that is not that user's. Handlers map it to 404 so other users'
// instances are not disclosed.
var ErrWalletInstanceNotOwned = errors.New("wallet instance does not belong to this user")

// ErrErasureIncomplete means the status change persisted but part of the
// cascade failed; handlers map it to 409 and repeating the request finishes it.
var ErrErasureIncomplete = errors.New("wallet instance status changed but erasure incomplete")

// revokeAllMaxPasses bounds RevokeAllForUser's re-listing (see there).
const revokeAllMaxPasses = 3

// LifecycleActor says who asked for a wallet instance status change.
type LifecycleActor struct {
	// Kind is "user" for self-service changes and "provider" for admin ones.
	Kind string
	// UserID is set for self-service changes: the instance must belong to it.
	UserID *domain.UserID
}

// WalletLifecycleService implements SID-AUTH-06: validated status changes,
// audit events and the revocation cascade. Revocation is terminal; revoking a
// user's last live instance erases the wallet data, never while one remains live.
// Erasing then is a SIROS decision, not an ARF v3 requirement (docs/API.md,
// "Why revoking the last instance erases").
type WalletLifecycleService struct {
	store          storage.Store
	logger         *zap.Logger
	audit          *audit.Emitter
	sessionCleaner SessionCleaner
	// locks serializes, per user and process, an attestation's instance write
	// against the cascade's "anything live? then erase" step; across processes
	// revokeIfWalletDeactivatedMeanwhile covers it.
	locks userLocks
}

// userLocks is a set of per-user mutexes, dropped again when idle.
type userLocks struct {
	mu sync.Mutex
	m  map[domain.UserID]*userLockEntry
}

type userLockEntry struct {
	mu   sync.Mutex
	refs int
}

func (l *userLocks) lock(id domain.UserID) func() {
	l.mu.Lock()
	if l.m == nil {
		l.m = map[domain.UserID]*userLockEntry{}
	}
	e := l.m[id]
	if e == nil {
		e = &userLockEntry{}
		l.m[id] = e
	}
	e.refs++
	l.mu.Unlock()
	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		l.mu.Lock()
		if e.refs--; e.refs == 0 {
			delete(l.m, id)
		}
		l.mu.Unlock()
	}
}

// LockUser takes the user's lifecycle lock and returns its release. Not
// reentrant: a holder calls CascadeForRevokedLocked.
func (s *WalletLifecycleService) LockUser(userID domain.UserID) func() {
	return s.locks.lock(userID)
}

// NewWalletLifecycleService creates a WalletLifecycleService. auditor may be nil.
func NewWalletLifecycleService(store storage.Store, logger *zap.Logger, auditor *audit.Emitter) *WalletLifecycleService {
	return &WalletLifecycleService{store: store, logger: logger.Named("wallet-lifecycle"), audit: auditor}
}

// SetSessionCleaner wires the session store dropped on revocation.
func (s *WalletLifecycleService) SetSessionCleaner(sc SessionCleaner) { s.sessionCleaner = sc }

// ListForUser returns the wallet instances registered for a user in a tenant.
func (s *WalletLifecycleService) ListForUser(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) ([]*domain.WalletInstance, error) {
	instances, err := s.store.WalletInstances().GetByUser(ctx, tenantID, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("list wallet instances: %w", err)
	}
	if instances == nil {
		instances = []*domain.WalletInstance{}
	}
	return instances, nil
}

// changeStatusMaxAttempts bounds retries after losing to a concurrent owner bind.
const changeStatusMaxAttempts = 3

// ChangeStatus moves one instance to target after checking tenant, ownership
// and transition rules, then runs the cascade. If the cascade fails the instance
// is returned with ErrErasureIncomplete and a repeat re-runs it.
func (s *WalletLifecycleService) ChangeStatus(ctx context.Context, actor LifecycleActor, tenantID domain.TenantID, instanceID string, target domain.InstanceStatus, reason string) (*domain.WalletInstance, error) {
	inst, err := s.store.WalletInstances().GetByID(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	if inst.TenantID != tenantID {
		return nil, storage.ErrNotFound
	}
	if actor.UserID != nil && (inst.UserID == nil || *inst.UserID != *actor.UserID) {
		return nil, ErrWalletInstanceNotOwned
	}
	if err := domain.ValidateStatusTransition(inst.Status, target); err != nil {
		return nil, err
	}
	if inst.Status == target {
		if target != domain.InstanceStatusActive {
			// Idempotent retry: finish an incomplete cascade, advancing a stale
			// cut-off but leaving a current one so a complete retry is a no-op.
			if err := s.advanceCutoffIfStale(ctx, inst, actor); err != nil {
				return inst, errors.Join(err, s.cascade(ctx, tenantID, inst, actor))
			}
			return inst, s.cascade(ctx, tenantID, inst, actor)
		}
		return inst, nil
	}
	// The write carries the binding read (owner, generation) so it only lands on
	// that record, which may meanwhile have been replaced. On mismatch, a new
	// owner at the same generation is re-checked and retried; a new generation
	// is reported as not found.
	for attempt := 1; ; attempt++ {
		// The user-wide cut-off is taken after this write, not before: the user
		// comes from a snapshot the write may reject, which would log out the
		// wrong user. A crash in between is healed by the retry.
		err := s.store.WalletInstances().UpdateStatusIfUnchanged(ctx, instanceID, tenantID, inst.Binding(), target, reason)
		if err == nil {
			break
		}
		if !errors.Is(err, storage.ErrBindingChanged) {
			return nil, err
		}
		cur, gerr := s.store.WalletInstances().GetByID(ctx, instanceID)
		if gerr != nil {
			return nil, gerr
		}
		if cur.TenantID != tenantID || cur.Generation != inst.Generation {
			return nil, storage.ErrNotFound
		}
		if actor.UserID != nil && (cur.UserID == nil || *cur.UserID != *actor.UserID) {
			return nil, ErrWalletInstanceNotOwned
		}
		if err := domain.ValidateStatusTransition(cur.Status, target); err != nil {
			return nil, err
		}
		if attempt >= changeStatusMaxAttempts {
			return nil, err
		}
		inst = cur
	}
	// Work from the persisted record: an attestation may have bound an anonymous
	// instance after the write. A failed re-read is ErrErasureIncomplete.
	persisted, err := s.store.WalletInstances().GetByID(ctx, instanceID)
	if err != nil {
		inst.Status = target
		inst.UpdatedAt = time.Now().UTC()
		s.emitAudit(inst.ID, target, reason, actor)
		return inst, fmt.Errorf("%w: re-read instance after the status write: %w", ErrErasureIncomplete, err)
	}
	if persisted.Generation != inst.Generation || persisted.TenantID != tenantID {
		// The id now belongs to a replacement this request never revoked, so
		// neither cut-off nor cascade may run against it.
		inst.Status = target
		inst.UpdatedAt = time.Now().UTC()
		s.emitAudit(inst.ID, target, reason, actor)
		return inst, fmt.Errorf("%w: the instance was replaced after the status write; no cut-off or cascade was run against the replacement", ErrErasureIncomplete)
	}
	inst = persisted
	s.emitAudit(inst.ID, target, reason, actor)
	if target != domain.InstanceStatusActive {
		// Taken after the write, so a token minted by a login before it is cut off
		// too. Serializing logins with lifecycle changes is go-wallet-backend#330.
		if err := s.cutOffTokens(ctx, inst, actor); err != nil {
			return inst, errors.Join(fmt.Errorf("%w: re-cut tokens after the status write: %w", ErrErasureIncomplete, err), s.cascade(ctx, tenantID, inst, actor))
		}
		return inst, s.cascade(ctx, tenantID, inst, actor)
	}
	return inst, nil
}

// advanceCutoffIfStale re-cuts the user's tokens when the recorded cut-off
// predates the revocation (an earlier attempt's cut-off write failed).
func (s *WalletLifecycleService) advanceCutoffIfStale(ctx context.Context, inst *domain.WalletInstance, actor LifecycleActor) error {
	if inst.UserID == nil || inst.DeactivatedAt == nil {
		return nil
	}
	cutoff, err := s.store.Users().GetAuthCutoff(ctx, *inst.UserID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("%w: read token cut-off on retry: %w", ErrErasureIncomplete, err)
	}
	if !cutoff.Before(*inst.DeactivatedAt) {
		return nil
	}
	if err := s.cutOffTokens(ctx, inst, actor); err != nil {
		return fmt.Errorf("%w: re-cut stale tokens on retry: %w", ErrErasureIncomplete, err)
	}
	return nil
}

// cutOffTokens records the token cut-off (internal/tokengate) for the
// instance's user. It is user-wide because a bearer token carries no instance
// identity (docs/API.md, "Scope of the cut-off").
func (s *WalletLifecycleService) cutOffTokens(ctx context.Context, inst *domain.WalletInstance, actor LifecycleActor) error {
	if inst.UserID == nil {
		return nil
	}
	if err := s.store.Users().InvalidateAuthBefore(ctx, *inst.UserID, time.Now()); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("cut off issued tokens: %w", err)
	}
	return nil
}

// RevokeAllForUser revokes every non-revoked instance of the user in the tenant
// ("deactivate my wallet") and returns how many changed. Like ChangeStatus it
// returns ErrErasureIncomplete if the cascade did not complete.
func (s *WalletLifecycleService) RevokeAllForUser(ctx context.Context, actor LifecycleActor, tenantID domain.TenantID, userID domain.UserID, reason string) (int, error) {
	// A user actor may only sweep their own wallet.
	if actor.UserID != nil && *actor.UserID != userID {
		return 0, ErrWalletInstanceNotOwned
	}
	changed := 0
	var last *domain.WalletInstance
	// An attestation can insert an instance while the sweep runs, so repeat until a
	// pass revokes nothing, bounded so an attesting loop cannot hold the request
	// (real serialization: go-wallet-backend#330).
	for pass := 0; pass < revokeAllMaxPasses; pass++ {
		instances, err := s.ListForUser(ctx, tenantID, userID)
		if err != nil {
			if last != nil {
				// Revocations already persisted must not keep their sessions until a retry.
				return changed, errors.Join(fmt.Errorf("%w: list instances during the revoke-all sweep: %w", ErrErasureIncomplete, err), s.cascade(ctx, tenantID, last, actor))
			}
			return changed, err
		}
		revokedThisPass := 0
		for _, inst := range instances {
			if inst.Status == domain.InstanceStatusRevoked {
				continue
			}
			if err := s.store.WalletInstances().UpdateStatusIfUnchanged(ctx, inst.ID, tenantID, inst.Binding(), domain.InstanceStatusRevoked, reason); err != nil {
				err = fmt.Errorf("revoke instance %s: %w", inst.ID, err)
				if last != nil {
					// As above; cascade returns nil here, so join ErrErasureIncomplete for the 409.
					return changed, errors.Join(fmt.Errorf("%w: %w", ErrErasureIncomplete, err), s.cascade(ctx, tenantID, last, actor))
				}
				return changed, err
			}
			inst.Status = domain.InstanceStatusRevoked
			// ensureCutoff compares the cut-off with DeactivatedAt; without it an older
			// cut-off would pass as sufficient.
			revokedAt := time.Now().UTC()
			inst.DeactivatedAt = &revokedAt
			inst.UpdatedAt = revokedAt
			s.emitAudit(inst.ID, domain.InstanceStatusRevoked, reason, actor)
			changed++
			revokedThisPass++
			last = inst
		}
		if revokedThisPass == 0 {
			if last == nil && len(instances) > 0 {
				// A retry: the cut-off has to cover the latest revocation.
				last = latestRevoked(instances)
			}
			break
		}
	}
	if last == nil {
		return changed, nil
	}
	if changed == 0 {
		// A retry: repair a stale cut-off (cascade only creates a missing one).
		if err := s.advanceCutoffIfStale(ctx, last, actor); err != nil {
			return changed, errors.Join(err, s.cascade(ctx, tenantID, last, actor))
		}
	}
	if changed > 0 {
		// A token minted during the sweep is newer than the first cut-off.
		if err := s.cutOffTokens(ctx, last, actor); err != nil {
			return changed, errors.Join(fmt.Errorf("%w: %w", ErrErasureIncomplete, err), s.cascade(ctx, tenantID, last, actor))
		}
	}
	// An instance can appear after the last pass; do not report success then.
	return changed, errors.Join(s.cascade(ctx, tenantID, last, actor), s.unsweptErr(ctx, tenantID, userID))
}

// latestRevoked returns the most recently revoked instance (the last listed if
// none has a revocation time).
func latestRevoked(instances []*domain.WalletInstance) *domain.WalletInstance {
	best := instances[len(instances)-1]
	for _, inst := range instances {
		if inst.DeactivatedAt == nil {
			continue
		}
		if best.DeactivatedAt == nil || inst.DeactivatedAt.After(*best.DeactivatedAt) {
			best = inst
		}
	}
	return best
}

// unsweptErr reports ErrErasureIncomplete when an instance is still live after
// the sweep; cascade treats that as "nothing to erase" and would report success.
func (s *WalletLifecycleService) unsweptErr(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) error {
	instances, err := s.ListForUser(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("%w: list instances after the revoke-all pass bound: %w", ErrErasureIncomplete, err)
	}
	for _, inst := range instances {
		if inst.Status != domain.InstanceStatusRevoked {
			return fmt.Errorf("%w: revoke-all reached its %d-pass bound with instance %s still %s",
				ErrErasureIncomplete, revokeAllMaxPasses, inst.ID, inst.Status)
		}
	}
	return nil
}

// cascade drops the user's sessions (user-wide, like the cut-off) and erases the
// wallet data once no live instance remains, returning ErrErasureIncomplete on
// any failed step.
func (s *WalletLifecycleService) cascade(ctx context.Context, tenantID domain.TenantID, inst *domain.WalletInstance, actor LifecycleActor) error {
	if inst.UserID == nil {
		return nil
	}
	defer s.LockUser(*inst.UserID)()
	return s.cascadeLocked(ctx, tenantID, inst, actor)
}

// cascadeLocked is cascade for a caller that already holds LockUser.
func (s *WalletLifecycleService) cascadeLocked(ctx context.Context, tenantID domain.TenantID, inst *domain.WalletInstance, actor LifecycleActor) error {
	if inst.UserID == nil {
		return nil
	}
	userID := *inst.UserID
	var errs []error
	// The status may have been persisted elsewhere, so ensure a cut-off at least as
	// new as the revocation first; without it an old token could write after the
	// erasure. Failure aborts before anything is dropped or erased.
	if err := s.ensureCutoff(ctx, userID, inst); err != nil {
		return s.incomplete(userID, []error{err})
	}
	if s.sessionCleaner != nil {
		if err := s.sessionCleaner.DeleteByUser(ctx, userID.String()); err != nil {
			errs = append(errs, fmt.Errorf("drop sessions: %w", err))
		}
	}
	remaining, err := s.store.WalletInstances().GetByUser(ctx, tenantID, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("list remaining instances: %w", err))
		return s.incomplete(userID, errs)
	}
	for _, other := range remaining {
		if other.Status.IsLive() {
			return s.incomplete(userID, errs) // the wallet still has a usable instance
		}
		if !other.Status.IsKnownNonLive() {
			// Fail closed on an unrecognized status.
			errs = append(errs, fmt.Errorf("instance %s has unrecognized status %q: not erasing", other.ID, other.Status))
			return s.incomplete(userID, errs)
		}
	}
	errs = append(errs, s.eraseWalletData(ctx, tenantID, userID)...)
	return s.incomplete(userID, errs)
}

// CascadeForRevokedLocked is CascadeForRevoked for a caller that already holds
// LockUser for the instance's user (WIAService).
func (s *WalletLifecycleService) CascadeForRevokedLocked(ctx context.Context, tenantID domain.TenantID, inst *domain.WalletInstance, actor LifecycleActor) error {
	return s.cascadeLocked(ctx, tenantID, inst, actor)
}

// CascadeForRevoked runs the cascade for an instance whose revocation another
// component persisted (WIAService revokes a raced first attestation itself).
func (s *WalletLifecycleService) CascadeForRevoked(ctx context.Context, tenantID domain.TenantID, inst *domain.WalletInstance, actor LifecycleActor) error {
	return s.cascade(ctx, tenantID, inst, actor)
}

// ensureCutoff sets the user's cut-off to now unless a current one exists.
func (s *WalletLifecycleService) ensureCutoff(ctx context.Context, userID domain.UserID, inst *domain.WalletInstance) error {
	cutoff, err := s.store.Users().GetAuthCutoff(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("read token cut-off: %w", err)
	}
	// Without a recorded revocation time, advance (fail closed).
	if !cutoff.IsZero() && inst.DeactivatedAt != nil && !cutoff.Before(*inst.DeactivatedAt) {
		return nil
	}
	if err := s.store.Users().InvalidateAuthBefore(ctx, userID, time.Now()); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("cut off issued tokens: %w", err)
	}
	return nil
}

// incomplete turns the collected cascade failures into ErrErasureIncomplete
// (nil when there were none), logging them once.
func (s *WalletLifecycleService) incomplete(userID domain.UserID, errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	joined := errors.Join(errs...)
	s.logger.Error("wallet lifecycle cascade incomplete", zap.String("user_id", userID.String()), zap.Error(joined))
	return fmt.Errorf("%w: %w", ErrErasureIncomplete, joined)
}

// eraseWalletData is the SID-AUTH-06 secure erasure: unless a live instance
// remains in any tenant it deletes holder data per tenant and the user-level
// state. The user record and passkeys stay so the revocation is attributable.
func (s *WalletLifecycleService) eraseWalletData(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) []error {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return []error{fmt.Errorf("load user: %w", err)}
	}
	// Holder data is keyed by DID, or by user id when there is none.
	holder := user.DID
	if holder == "" {
		holder = userID.String()
	}
	// A failed liveness check counts as live (fail closed).
	tenants, err := s.userTenants(ctx, userID, tenantID)
	if err != nil {
		return []error{err}
	}
	var errs []error
	if s.liveInstanceIn(ctx, tenants, tenantID, userID, &errs) {
		s.logger.Info("wallet data kept: a live instance remains in another tenant",
			zap.String("user_id", userID.String()), zap.String("tenant_id", string(tenantID)))
		return errs
	}
	// Advance the cut-off before the first holder sweep: the holder-write fence
	// (tokengate.ConfirmWrite) is only sound if every erasure does, or a token
	// minted since ensureCutoff could write after the sweep.
	if err := s.store.Users().InvalidateAuthBefore(ctx, userID, time.Now()); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return append(errs, fmt.Errorf("advance token cut-off before the holder-data sweep: %w", err))
	}
	for _, tid := range tenants {
		errs = append(errs, s.eraseHolderData(ctx, tid, holder)...)
	}
	// WIA challenges carry only a tenant and are short-lived; GenerateWIA refuses
	// a deactivated wallet anyway.
	if err := s.store.Challenges().DeleteByUserID(ctx, userID.String()); err != nil {
		errs = append(errs, fmt.Errorf("delete webauthn challenges: %w", err))
	}
	// Erases the key material and advances the cut-off in one atomic update.
	if err := s.store.Users().EraseWalletData(ctx, userID, time.Now()); err != nil {
		errs = append(errs, fmt.Errorf("erase wallet key material: %w", err))
	}
	// Final sweep after the last cut-off advance: a write by a token valid at the
	// first advance can pass its post-write re-check until then. Runs even if the
	// key-material erase failed.
	for _, tid := range tenants {
		errs = append(errs, s.eraseHolderData(ctx, tid, holder)...)
	}
	if len(errs) == 0 {
		s.logger.Info("wallet data erased: last wallet instance revoked", zap.String("user_id", userID.String()), zap.String("tenant_id", string(tenantID)))
	} else {
		s.logger.Error("wallet data erasure incomplete: last wallet instance revoked but some data remains",
			zap.String("user_id", userID.String()), zap.String("tenant_id", string(tenantID)), zap.Error(errors.Join(errs...)))
	}
	return errs
}

// userTenants lists the tenants holding the user's wallet data (memberships,
// instances, default and current tenant). A failed lookup is an error: erasing
// on a guess could destroy a wallet still in use.
func (s *WalletLifecycleService) userTenants(ctx context.Context, userID domain.UserID, include domain.TenantID) ([]domain.TenantID, error) {
	memberships, err := s.store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list tenant memberships: %w", err)
	}
	// A membership can be removed while an instance remains (admin tenant-user
	// DELETE); missing that tenant would erase key material it could still use.
	instances, err := s.store.WalletInstances().GetAllByUser(ctx, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("list wallet instances: %w", err)
	}
	seen := map[domain.TenantID]bool{}
	var out []domain.TenantID
	for _, tid := range append([]domain.TenantID{include, domain.DefaultTenantID}, memberships...) {
		if !seen[tid] {
			seen[tid] = true
			out = append(out, tid)
		}
	}
	for _, inst := range instances {
		if !seen[inst.TenantID] {
			seen[inst.TenantID] = true
			out = append(out, inst.TenantID)
		}
	}
	return out, nil
}

// liveInstanceIn reports whether the user has a live instance outside exclude;
// a listing failure or unrecognized status counts as live (fail closed).
func (s *WalletLifecycleService) liveInstanceIn(ctx context.Context, tenants []domain.TenantID, exclude domain.TenantID, userID domain.UserID, errs *[]error) bool {
	for _, tid := range tenants {
		if tid == exclude {
			continue
		}
		instances, err := s.store.WalletInstances().GetByUser(ctx, tid, userID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			*errs = append(*errs, fmt.Errorf("list instances in tenant %s: %w", tid, err))
			return true
		}
		for _, inst := range instances {
			if inst.Status.IsLive() {
				return true
			}
			if !inst.Status.IsKnownNonLive() {
				*errs = append(*errs, fmt.Errorf("instance %s in tenant %s has unrecognized status %q: not erasing", inst.ID, tid, inst.Status))
				return true
			}
		}
	}
	return false
}

// eraseHolderData deletes the holder's credentials and presentations in one
// tenant, continuing past failures, and returns every failure.
func (s *WalletLifecycleService) eraseHolderData(ctx context.Context, tid domain.TenantID, did string) []error {
	var errs []error
	creds, err := s.store.Credentials().GetAllByHolder(ctx, tid, did)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("list credentials: %w", err))
	}
	for _, c := range creds {
		if err := s.store.Credentials().Delete(ctx, tid, did, c.CredentialIdentifier); err != nil && !errors.Is(err, storage.ErrNotFound) {
			errs = append(errs, fmt.Errorf("delete credential %s: %w", c.CredentialIdentifier, err))
		}
	}
	pres, err := s.store.Presentations().GetAllByHolder(ctx, tid, did)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("list presentations: %w", err))
	}
	for _, p := range pres {
		if err := s.store.Presentations().Delete(ctx, tid, did, p.PresentationIdentifier); err != nil && !errors.Is(err, storage.ErrNotFound) {
			errs = append(errs, fmt.Errorf("delete presentation %s: %w", p.PresentationIdentifier, err))
		}
	}
	return errs
}

func (s *WalletLifecycleService) emitAudit(instanceID string, status domain.InstanceStatus, reason string, actor LifecycleActor) {
	if s.audit == nil {
		return
	}
	// Anything but revocation is recorded as a deactivation rather than dropped.
	event := set.EventWIDeactivated
	if status == domain.InstanceStatusRevoked {
		event = set.EventWIRevoked
	}
	s.audit.EmitWithSubject(event, instanceID, map[string]any{
		"status": string(status),
		"reason": reason,
		"actor":  actor.Kind,
	})
}
