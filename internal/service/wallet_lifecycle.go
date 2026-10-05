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

// ErrWalletInstanceNotOwned is returned when a user-initiated lifecycle change
// names an instance that does not belong to that user. Handlers map it to 404
// so the existence of other users' instances is not disclosed.
var ErrWalletInstanceNotOwned = errors.New("wallet instance does not belong to this user")

// ErrErasureIncomplete is returned by ChangeStatus and RevokeAllForUser when
// the status change was persisted (the instance *is* revoked)
// but part of the cascade - dropping sessions, erasing wallet data - failed.
// Handlers map it to 409: the client repeats the request to finish the
// erasure. It wraps the underlying failures.
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

// WalletLifecycleService implements SID-AUTH-06 wallet lifecycle management on
// top of the domain.WalletInstance model (go-wallet-backend#195): status
// changes with validated transitions, audit events, and the cascade a
// deactivation implies.
//
// Revocation is the only status change there is and it is terminal: sessions
// are dropped, new WIAs are refused (WIAService), and login with the linked
// passkey is refused (WebAuthnService.checkWalletLifecycle). Revoking the last
// live instance of a user deactivates the wallet: the encrypted private data -
// the only durable custodian of the user's keys - and any server-side
// credentials, presentations and pending WebAuthn challenges are erased, and
// login is refused for every passkey of that user, so a new enrollment is
// required. Data is never erased while a live instance remains. A record left
// in the legacy "suspended" state is not live and can only be revoked; see
// domain.InstanceStatus.
//
// Erasing on the last revocation rather than only on an explicit "deactivate
// my wallet" is a SIROS decision, not a requirement: ARF v3 lets a Wallet
// Unit sit in its terminal Revoked state with the user still able to view
// what it holds. It is kept because here the login gate, not the erasure,
// is what ends that access - once nothing live remains every passkey of the
// user is refused and a new attestation is refused too - so the data could
// only be retained, never read. See docs/API.md, "Why revoking the last
// instance erases"; if the login gate is ever narrowed to deactivation
// alone, this trigger has to be revisited with it.
type WalletLifecycleService struct {
	store          storage.Store
	logger         *zap.Logger
	audit          *audit.Emitter
	sessionCleaner SessionCleaner
	// locks serializes, per user and within this process, a first
	// attestation's instance write with the cascade's "is anything live?
	// then erase" step (see LockUser). Across processes the WIA post-write
	// re-check (revokeIfWalletDeactivatedMeanwhile) is what keeps the wallet
	// consistent: a record inserted after the erasure is revoked again.
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

// LockUser takes the user's lifecycle lock and returns its release. It is
// held by the cascade while it decides whether anything is live and erases,
// and by WIAService from the instance write to the end of its post-write
// re-check, so a first attestation cannot land between the cascade's liveness
// check and the erasure. The lock is not reentrant: a holder calls
// CascadeForRevokedLocked, not CascadeForRevoked.
func (s *WalletLifecycleService) LockUser(userID domain.UserID) func() {
	return s.locks.lock(userID)
}

// NewWalletLifecycleService creates a WalletLifecycleService. auditor may be nil.
func NewWalletLifecycleService(store storage.Store, logger *zap.Logger, auditor *audit.Emitter) *WalletLifecycleService {
	return &WalletLifecycleService{store: store, logger: logger.Named("wallet-lifecycle"), audit: auditor}
}

// SetSessionCleaner wires the engine session store so revocation drops the
// user's live sessions.
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

// changeStatusMaxAttempts bounds how often ChangeStatus retries a write that
// lost to an owner bind on the same record.
const changeStatusMaxAttempts = 3

// ChangeStatus moves one instance to target after checking tenant, ownership
// (for a user actor) and the domain transition rules, then runs the cascade.
// Returns storage.ErrNotFound, ErrWalletInstanceNotOwned or
// domain.ErrInvalidStatusTransition for the caller to map. When the status
// change was persisted but the cascade did not fully complete, the updated
// instance is returned together with ErrErasureIncomplete; repeating the same
// request re-runs the cascade, so the caller can retry until it succeeds.
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
			// Idempotent retry: finish a cascade (token cut-off, session
			// drop, erasure) that did not complete last time.
			//
			// cascade's ensureCutoff only establishes a cut-off that is
			// missing, which is not enough here. The first attempt may have
			// persisted the revocation and then failed to record the cut-off
			// (or recorded one older than the revocation, as an earlier
			// version did) - leaving none, or one that predates the
			// revocation, and with it any token minted in between. So a cut-off older than the revocation is advanced
			// now. A cut-off already after it is left alone, which keeps a
			// retry after a complete cascade the no-op it should be.
			if err := s.advanceCutoffIfStale(ctx, inst, actor); err != nil {
				return inst, errors.Join(err, s.cascade(ctx, tenantID, inst, actor))
			}
			return inst, s.cascade(ctx, tenantID, inst, actor)
		}
		return inst, nil
	}
	// The write carries the binding that was read (owner, including "none",
	// and generation), so it can only land on that exact record. The id is a
	// global key: between the read above and the write the record can be
	// deleted and the same thumbprint attested again, possibly by another
	// user of the tenant, and a write keyed by id and tenant alone would
	// revoke that replacement - and the re-read below would then run the
	// cascade against its owner.
	//
	// A mismatch is sorted out by re-reading. The same generation with a
	// different owner is the record itself, bound by an attestation in the
	// meantime (an anonymous instance gaining its user): the checks run again
	// against the fresh state and the write is retried, which keeps that
	// legitimate bind from failing the request. A different generation is a
	// replacement the caller never asked about: it is left alone and the
	// instance reported as not found.
	for attempt := 1; ; attempt++ {
		// The cut-off is deliberately NOT taken before this write. It is
		// user-wide, and the user it would hit is read from a snapshot that
		// the conditional write may reject: if the record was deleted and
		// attested again for another user in between, a cut-off taken first
		// would log out the user of the old snapshot while the write fails
		// and the replacement stays untouched. The binding is confirmed by
		// the write; the cut-off follows it, below.
		//
		// Fail closed all the same: a crash or failure between the write and
		// the cut-off leaves a revoked instance whose tokens still work, but
		// the caller is told (ErrErasureIncomplete) and repeating the
		// request lands in the idempotent branch, where advanceCutoffIfStale
		// and the cascade's ensureCutoff establish the cut-off.
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
	// Work from the record as persisted, not from the copy read before the
	// write. An attestation can bind an anonymous instance to a user after
	// the write (the bind is not conditional on status), and the pre-write
	// copy still says "no owner": cutting off tokens and running the cascade
	// from it would skip the very user the revocation now belongs to, leaving
	// their tokens and sessions alive. If the record was meanwhile replaced
	// (a different generation) the persisted copy is somebody else's, and
	// the record that was revoked is the one this request observed. The cut-off below runs from the persisted owner, so a bind
	// that landed after the write is covered. When the re-read fails the status is already persisted,
	// so the caller gets ErrErasureIncomplete and the same request, which
	// re-reads in its idempotent branch above, finishes the job.
	persisted, err := s.store.WalletInstances().GetByID(ctx, instanceID)
	if err != nil {
		inst.Status = target
		inst.UpdatedAt = time.Now().UTC()
		s.emitAudit(inst.ID, target, reason, actor)
		return inst, fmt.Errorf("%w: re-read instance after the status write: %w", ErrErasureIncomplete, err)
	}
	if persisted.Generation == inst.Generation {
		inst = persisted
	} else {
		inst.Status = target
		inst.UpdatedAt = time.Now().UTC()
		if target == domain.InstanceStatusRevoked {
			// Same as in RevokeAllForUser: the cascade's cut-off check
			// needs the revocation time, which this local copy lacks.
			revokedAt := inst.UpdatedAt
			inst.DeactivatedAt = &revokedAt
		}
	}
	s.emitAudit(inst.ID, target, reason, actor)
	if target != domain.InstanceStatusActive {
		// Cut the tokens off now that the status is persisted and the
		// binding confirmed, so only the user of the record that was really
		// revoked is affected. A login that raced the write and minted a
		// token before it is refused too, since the cut-off is taken after
		// the write. Serializing lifecycle changes with login outright is
		// go-wallet-backend#330.
		if err := s.cutOffTokens(ctx, inst, actor); err != nil {
			return inst, errors.Join(fmt.Errorf("%w: re-cut tokens after the status write: %w", ErrErasureIncomplete, err), s.cascade(ctx, tenantID, inst, actor))
		}
		return inst, s.cascade(ctx, tenantID, inst, actor)
	}
	return inst, nil
}

// advanceCutoffIfStale re-cuts the user's tokens when the recorded cut-off
// is older than the revocation it belongs to. That happens when the cut-off
// after the status write failed on an earlier attempt: tokens minted between
// an older cut-off and the write itself would otherwise stay valid
// forever, since nothing later looks at them again.
//
// Instances with no user, and revocations with no recorded time, have nothing
// to compare and are left alone.
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

// cutOffTokens records the SID-AUTH-06 token cut-off for the instance's
// user (see internal/tokengate): bearer tokens issued before now stop
// working, except the one carrying this request. Instances without a user
// have no tokens to cut off.
//
// The cut-off is user-wide even when one instance changed, because a bearer
// token carries no instance identity: its claims are the user, the tenant,
// an iat and a jti (UserService.generateToken), and the gate has nothing
// finer than User.AuthInvalidBefore to compare them against. Cutting off the
// user is the only sound over-approximation available - narrowing it to the
// affected device would leave that device's already-issued token working
// until it expires, and nothing downstream of login checks instance status,
// so it could keep running issuance and presentation flows. Narrowing this
// needs an instance identity to survive login; see the note in
// docs/API.md under "Scope of the cut-off".
func (s *WalletLifecycleService) cutOffTokens(ctx context.Context, inst *domain.WalletInstance, actor LifecycleActor) error {
	if inst.UserID == nil {
		return nil
	}
	if err := s.store.Users().InvalidateAuthBefore(ctx, *inst.UserID, time.Now()); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("cut off issued tokens: %w", err)
	}
	return nil
}

// RevokeAllForUser revokes every non-revoked instance of the user in the
// tenant - the "deactivate my wallet" action - and returns how many changed.
// The cascade then erases the wallet data, since nothing live remains in the
// tenant. Like ChangeStatus it returns ErrErasureIncomplete when the
// revocations were persisted but the erasure did not complete; calling it
// again with everything already revoked re-runs the erasure.
func (s *WalletLifecycleService) RevokeAllForUser(ctx context.Context, actor LifecycleActor, tenantID domain.TenantID, userID domain.UserID, reason string) (int, error) {
	// A user actor may only sweep their own wallet. No route reaches this
	// with a user actor today - revoking is a provider action and the
	// self-service surface is list, logout-everywhere and account removal -
	// but ChangeStatus checks the same thing and the asymmetry is the sort
	// that gets noticed by whoever wires the next caller, not before.
	if actor.UserID != nil && *actor.UserID != userID {
		return 0, ErrWalletInstanceNotOwned
	}
	changed := 0
	var last *domain.WalletInstance
	// A first attestation can insert a new instance while this sweep runs
	// (it works from a listing, not a lock). Repeat until a pass finds
	// nothing left to revoke, so such an instance cannot end up as the only
	// live one and leave the wallet undeactivated. Bounded, so a client
	// attesting in a tight loop cannot hold the request here; serializing
	// attestation with lifecycle transitions outright is go-wallet-backend#330.
	for pass := 0; pass < revokeAllMaxPasses; pass++ {
		instances, err := s.ListForUser(ctx, tenantID, userID)
		if err != nil {
			if last != nil {
				// An earlier pass already persisted revocations: they must
				// not keep their sessions and cleanup until the retry, so
				// cascade for them now and report the request as incomplete
				// (the documented retry-by-repeating path) rather than as a
				// plain storage error.
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
					// Revocations already persisted must not keep their
					// tokens and sessions until the retry: cascade for them
					// now (the not-yet-revoked instance keeps the erasure
					// off) and report the request as incomplete. cascade
					// returns nil in exactly that case, so ErrErasureIncomplete
					// is joined explicitly - without it the partially
					// persisted operation would surface as a plain 500 and
					// not as the documented 409 retry-by-repeating.
					return changed, errors.Join(fmt.Errorf("%w: %w", ErrErasureIncomplete, err), s.cascade(ctx, tenantID, last, actor))
				}
				return changed, err
			}
			inst.Status = domain.InstanceStatusRevoked
			// Carry the revocation time on the local copy: the early
			// cascade returns below hand it to ensureCutoff, which compares
			// the user's cut-off with DeactivatedAt. Without it an older
			// non-zero cut-off (a logout-everywhere) would pass as
			// sufficient and the erasure would run without a cut-off past
			// this revocation. Taken after the write, so it is never
			// earlier than the stored time.
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
				// Everything already revoked: a retry. Take the most recently
				// revoked instance, since the cut-off has to cover the latest
				// revocation, not an arbitrary one.
				last = latestRevoked(instances)
			}
			break
		}
	}
	if last == nil {
		return changed, nil
	}
	if changed == 0 {
		// A retry over instances an earlier attempt already revoked. That
		// attempt may have failed at the cut-off it takes after the sweep,
		// leaving one that predates the last revocation; cascade only
		// establishes a missing cut-off, so repair a stale one here, as
		// ChangeStatus does on its own retry.
		if err := s.advanceCutoffIfStale(ctx, last, actor); err != nil {
			return changed, errors.Join(err, s.cascade(ctx, tenantID, last, actor))
		}
	}
	if changed > 0 {
		// Advance the cut-off again now that every instance of the tenant is
		// revoked: a token minted while the sweep was still running carries
		// an iat after the first cut-off and would otherwise stay valid.
		if err := s.cutOffTokens(ctx, last, actor); err != nil {
			return changed, errors.Join(fmt.Errorf("%w: %w", ErrErasureIncomplete, err), s.cascade(ctx, tenantID, last, actor))
		}
	}
	// Checked however the sweep ended: an instance can be inserted after the
	// last pass reported a fixed point just as well as during it, and either
	// way the request must not report success for a wallet it did not
	// deactivate. Repeating it resumes the sweep, like the other
	// ErrErasureIncomplete cases.
	return changed, errors.Join(s.cascade(ctx, tenantID, last, actor), s.unsweptErr(ctx, tenantID, userID))
}

// latestRevoked returns the instance revoked most recently, falling back to
// the last one listed when none records a revocation time.
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

// unsweptErr reports ErrErasureIncomplete when an instance of the tenant is
// still live after RevokeAllForUser swept it: the pass bound ran out, or an
// attestation landed after the last pass. cascade treats a remaining
// non-revoked instance as the ordinary "nothing to erase" case, so without
// this the request would report success for a wallet it did not deactivate.
// Serializing attestation with lifecycle transitions - so no instance can
// appear during the sweep at all - is go-wallet-backend#330.
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

// cascade runs after an instance left the active state: drop the user's live
// sessions, and erase the wallet data once no instance the user could
// reactivate remains in the tenant. Wallet instances are per tenant, so the
// decision is taken per tenant. It returns ErrErasureIncomplete (wrapping the
// underlying failures) when any step did not complete; the status change
// itself is already persisted at that point.
//
// The session drop is user-wide for the same reason the cut-off is (see
// cutOffTokens): a session record carries the user and the tenant and
// nothing that says which wallet instance authenticated it. Scoping it alone
// would change nothing a user could observe anyway, since the user-wide
// cut-off already forces every device to authenticate again.
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
	// The status is normally persisted only after cutOffTokens, but a
	// cascade can also run for a status recorded elsewhere - the standalone
	// admin path, an older deployment, or the idempotent retry of a request
	// whose cut-off never landed. Establish the cut-off when the user has
	// none, without advancing one that is already set (that would need-
	// lessly invalidate tokens issued since).
	//
	// Without an established cut-off at least as new as the revocation, an
	// already-issued token could write wallet data back after the erasure, so
	// a failure here aborts the cascade before anything is dropped or erased.
	// It is reported as ErrErasureIncomplete, so the request stays retryable.
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
			// Neither live nor known to be dead: an unrecognized or corrupted
			// status. Declaring the wallet deactivated on it could erase data
			// that instance still needs, so fail closed.
			errs = append(errs, fmt.Errorf("instance %s has unrecognized status %q: not erasing", other.ID, other.Status))
			return s.incomplete(userID, errs)
		}
	}
	errs = append(errs, s.eraseWalletData(ctx, tenantID, userID)...)
	return s.incomplete(userID, errs)
}

// CascadeForRevokedLocked is CascadeForRevoked for a caller that already holds
// LockUser for the instance's user (WIAService, which holds it across its
// instance write and re-check).
func (s *WalletLifecycleService) CascadeForRevokedLocked(ctx context.Context, tenantID domain.TenantID, inst *domain.WalletInstance, actor LifecycleActor) error {
	return s.cascadeLocked(ctx, tenantID, inst, actor)
}

// CascadeForRevoked runs the revocation cascade for an instance whose
// revocation was persisted by another component (WIAService revokes a raced
// first attestation itself). See cascade.
func (s *WalletLifecycleService) CascadeForRevoked(ctx context.Context, tenantID domain.TenantID, inst *domain.WalletInstance, actor LifecycleActor) error {
	return s.cascade(ctx, tenantID, inst, actor)
}

// ensureCutoff makes sure the user's token cut-off exists and is not older
// than the instance's revocation. Used by cascade for statuses persisted
// outside ChangeStatus/RevokeAllForUser. A cut-off that is already at or past
// the revocation is left alone (advancing it would needlessly invalidate
// tokens issued since); a missing one, or one that predates inst.DeactivatedAt
// (the second advance of an earlier attempt never landed), is set to now.
func (s *WalletLifecycleService) ensureCutoff(ctx context.Context, userID domain.UserID, inst *domain.WalletInstance) error {
	cutoff, err := s.store.Users().GetAuthCutoff(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("read token cut-off: %w", err)
	}
	// A revoked instance without a recorded time cannot prove the cut-off is
	// new enough, so it is advanced (fail closed) rather than trusted.
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

// eraseWalletData is the SID-AUTH-06 "secure erasure on deactivation". It
// first checks, across every tenant the user belongs to, that no live
// instance remains; only then are the credentials and presentations the user
// holds in each tenant deleted (nothing is erased while any live instance
// remains, and nothing if the check itself fails). The user-level state - the encrypted private data and legacy key
// blob (the only durable custodians of the user's keys) and pending
// challenges - is shared by all of the user's tenants, so it is erased only
// when no non-revoked instance remains in any tenant the user belongs to.
// The user record and its passkeys stay so the revocation remains attributable
// and login can be refused with a clear reason rather than "user not found".
func (s *WalletLifecycleService) eraseWalletData(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) []error {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		return []error{fmt.Errorf("load user: %w", err)}
	}
	// Credentials and presentations are keyed by holder DID; users without a
	// DID have theirs stored under the user id (the API's getHolderDID fallback).
	holder := user.DID
	if holder == "" {
		holder = userID.String()
	}
	// The global liveness check comes first and gates every erasure: nothing
	// is erased, in any tenant, while a live instance remains anywhere. A
	// failed check counts as "live" (fail closed) and is reported.
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
	// No live instance anywhere: the wallet is deactivated. Erase the holder
	// data of every tenant the user belongs to (#195: stored VCs/VPs for all
	// of the user's tenants) and the pending challenges, then the user-level
	// key material. That last write also advances the token cut-off (one
	// atomic update, see UserStore.EraseWalletData) so a record loaded
	// before it is fenced out of Update. The cut-off catches every token of
	// the user, the one the request arrived on included: a deactivated
	// wallet needs a new enrollment, and the session that deactivated it
	// must not be able to write new wallet data afterwards.
	//
	// The cut-off is advanced HERE, before the first holder sweep, and not only
	// by the EraseWalletData below: the holder-write fence (tokengate.
	// ConfirmWrite) is sound only if every erasure advances the cut-off before
	// it sweeps. ensureCutoff/cutOffTokens already set one at least as new as
	// the revocation, but a token minted after that and before this sweep
	// would still pass the fence and could write after the sweep. A failure
	// stops the erasure before anything is deleted and is retryable.
	if err := s.store.Users().InvalidateAuthBefore(ctx, userID, time.Now()); err != nil && !errors.Is(err, storage.ErrNotFound) {
		return append(errs, fmt.Errorf("advance token cut-off before the holder-data sweep: %w", err))
	}
	for _, tid := range tenants {
		errs = append(errs, s.eraseHolderData(ctx, tid, holder)...)
	}
	// WebAuthn challenges are per user and deleted here. WIA challenges are
	// not: they are single-use, short-lived nonces that carry only a tenant,
	// belong to no user (anyone can request one, so there is nothing of the
	// wallet's in them to erase), and are useless to a deactivated wallet
	// because GenerateWIA refuses it before signing anything.
	if err := s.store.Challenges().DeleteByUserID(ctx, userID.String()); err != nil {
		errs = append(errs, fmt.Errorf("delete webauthn challenges: %w", err))
	}
	// This is the write that erases the user-level key material, and it
	// advances the token cut-off in the same atomic update. Once the vault
	// is gone the wallet is deactivated and needs a new enrollment; no
	// pre-cut-off token can write new wallet data (private data,
	// credentials) after it. A failure here leaves the cut-off as it was and
	// is reported as ERASURE_INCOMPLETE, so the request can be repeated.
	if err := s.store.Users().EraseWalletData(ctx, userID, time.Now()); err != nil {
		errs = append(errs, fmt.Errorf("erase wallet key material: %w", err))
	}
	// Final sweep, after the point where the wallet is refused everything it
	// can be refused: the revocation is persisted (the login gate refuses new
	// logins, and refreshes, for the wallet, and a login whose gate check
	// predates it fails the re-check after it mints, see mintTokens), and the
	// token cut-off has been advanced twice since, the last time atomically
	// with the erasure of the key material just above. The sweeps above ran
	// between those advances. A holder write by a token that was valid at the
	// first one (iat after it) passes the post-write re-check until the last
	// one lands, so it can persist after the first sweep listed the holder's
	// records and be missed by it. This sweep lists after the last advance
	// and finds it, which is what DeleteUser's sweep after the record's
	// removal does for an account. It runs whether or not the key-material
	// erase succeeded: the data it may find is erased either way, and a
	// failure here, like any other step, is ErrErasureIncomplete and
	// retryable - repeating the request sweeps again.
	for _, tid := range tenants {
		errs = append(errs, s.eraseHolderData(ctx, tid, holder)...)
	}
	// Only claim the erasure happened when every step of it did: an
	// ErrErasureIncomplete cascade would otherwise leave a "wallet data
	// erased" line in the log for data that is still there, which is
	// exactly the wrong thing to find during incident response.
	if len(errs) == 0 {
		s.logger.Info("wallet data erased: last wallet instance revoked", zap.String("user_id", userID.String()), zap.String("tenant_id", string(tenantID)))
	} else {
		s.logger.Error("wallet data erasure incomplete: last wallet instance revoked but some data remains",
			zap.String("user_id", userID.String()), zap.String("tenant_id", string(tenantID)), zap.Error(errors.Join(errs...)))
	}
	return errs
}

// userTenants lists the tenants whose wallet data belongs to the user: the
// explicit memberships, the default tenant (where users registered without a
// membership row live) and the tenant at hand, without duplicates. A failed
// membership lookup is an error: erasing on a guess could destroy a wallet
// still in use elsewhere.
func (s *WalletLifecycleService) userTenants(ctx context.Context, userID domain.UserID, include domain.TenantID) ([]domain.TenantID, error) {
	memberships, err := s.store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list tenant memberships: %w", err)
	}
	// The instances are asked as well, because a membership can be gone
	// while an instance of that tenant is not: the admin
	// DELETE /admin/tenants/{id}/users/{user_id} removes a membership and
	// nothing else. Missing such a tenant here is the worst kind of miss on
	// this path - liveInstanceIn would not see a live instance there, the
	// wallet would be declared deactivated, and the user's shared key
	// material would be erased while that instance could still log in. A
	// failed lookup is an error for the same reason a failed membership
	// lookup is: erasing on a guess could destroy a wallet still in use.
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

// liveInstanceIn reports whether the user still has a non-revoked wallet
// instance in any of tenants other than exclude. A listing failure, and an
// instance whose status is neither live nor a known non-live one, is
// recorded in errs and counts as "live" (fail closed: keep the data).
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
// tenant, continuing past individual failures so as much as possible is
// erased, and returns every failure.
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
	// Revocation is the only status change there is; anything else reaching
	// here is a caller that got past the store, so it is recorded as a
	// deactivation rather than dropped.
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
