package service

import (
	"context"
	"errors"
	"fmt"
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
// the status change was persisted (the instance *is* suspended or revoked)
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
	// TokenJTI is the id of the bearer token that carries the request, for
	// self-service changes. It stays valid across the token cut-off the
	// change triggers, so the user can reactivate a suspended instance or
	// repeat the request after 409 ERASURE_INCOMPLETE from the same session.
	TokenJTI string
}

// WalletLifecycleService implements SID-AUTH-06 wallet lifecycle management on
// top of the domain.WalletInstance model (go-wallet-backend#195): status
// changes with validated transitions, audit events, and the cascade a
// deactivation implies.
//
// Suspension is reversible and only blocks: sessions are dropped, new WIAs are
// refused (WIAService), and login with the linked passkey is refused
// (WebAuthnService.checkWalletLifecycle). Revocation is terminal. Revoking the
// last non-revoked instance of a user deactivates the wallet: the encrypted
// private data - the only durable custodian of the user's keys - and any
// server-side credentials, presentations and pending WebAuthn challenges are
// erased, and login is refused for every passkey of that user, so re-activation
// requires a full new enrollment. Data is never erased while an instance the
// user could still reactivate remains.
type WalletLifecycleService struct {
	store          storage.Store
	logger         *zap.Logger
	audit          *audit.Emitter
	sessionCleaner SessionCleaner
}

// NewWalletLifecycleService creates a WalletLifecycleService. auditor may be nil.
func NewWalletLifecycleService(store storage.Store, logger *zap.Logger, auditor *audit.Emitter) *WalletLifecycleService {
	return &WalletLifecycleService{store: store, logger: logger.Named("wallet-lifecycle"), audit: auditor}
}

// SetSessionCleaner wires the engine session store so suspend/revoke drop the
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
			// drop, erasure) that did not complete last time - for a
			// suspension as much as for a revocation.
			return inst, s.cascade(ctx, tenantID, inst, actor)
		}
		return inst, nil
	}
	if target != domain.InstanceStatusActive {
		// Fail closed: cut off issued tokens before the status is persisted.
		// If the cut-off cannot be recorded nothing changes and the caller
		// gets an error; if the status write then fails, the user's tokens
		// are cut off while the instance stays active, which only costs a
		// re-login. The reverse order would leave a blocked instance whose
		// pre-cut-off tokens keep working until a retry.
		if err := s.cutOffTokens(ctx, inst, actor); err != nil {
			return nil, err
		}
	}
	if err := s.store.WalletInstances().UpdateStatus(ctx, instanceID, target, reason); err != nil {
		return nil, err
	}
	inst.Status = target
	inst.UpdatedAt = time.Now().UTC()
	s.emitAudit(inst.ID, target, reason, actor)
	if target != domain.InstanceStatusActive {
		return inst, s.cascade(ctx, tenantID, inst, actor)
	}
	return inst, nil
}

// cutOffTokens records the SID-AUTH-06 token cut-off for the instance's
// user (see internal/tokengate): bearer tokens issued before now stop
// working, except the one carrying this request. Instances without a user
// have no tokens to cut off.
func (s *WalletLifecycleService) cutOffTokens(ctx context.Context, inst *domain.WalletInstance, actor LifecycleActor) error {
	if inst.UserID == nil {
		return nil
	}
	if err := s.store.Users().InvalidateAuthBefore(ctx, *inst.UserID, time.Now(), actor.TokenJTI); err != nil && !errors.Is(err, storage.ErrNotFound) {
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
			if changed == 0 {
				if err := s.cutOffTokens(ctx, inst, actor); err != nil {
					return 0, err
				}
			}
			if err := s.store.WalletInstances().UpdateStatus(ctx, inst.ID, domain.InstanceStatusRevoked, reason); err != nil {
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
			s.emitAudit(inst.ID, domain.InstanceStatusRevoked, reason, actor)
			changed++
			revokedThisPass++
			last = inst
		}
		if revokedThisPass == 0 {
			if last == nil && len(instances) > 0 {
				last = instances[len(instances)-1] // everything already revoked: retry the erasure
			}
			break
		}
	}
	if last == nil {
		return changed, nil
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
func (s *WalletLifecycleService) cascade(ctx context.Context, tenantID domain.TenantID, inst *domain.WalletInstance, actor LifecycleActor) error {
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
	if err := s.ensureCutoff(ctx, userID, actor); err != nil {
		errs = append(errs, err)
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
		if other.Status != domain.InstanceStatusRevoked {
			return s.incomplete(userID, errs) // something is still active or reactivatable
		}
	}
	errs = append(errs, s.eraseWalletData(ctx, tenantID, userID)...)
	return s.incomplete(userID, errs)
}

// ensureCutoff records a token cut-off for a user that has none. Used by
// cascade for statuses persisted outside ChangeStatus/RevokeAllForUser.
func (s *WalletLifecycleService) ensureCutoff(ctx context.Context, userID domain.UserID, actor LifecycleActor) error {
	cutoff, _, err := s.store.Users().GetAuthCutoff(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("read token cut-off: %w", err)
	}
	if !cutoff.IsZero() {
		return nil
	}
	if err := s.store.Users().InvalidateAuthBefore(ctx, userID, time.Now(), actor.TokenJTI); err != nil && !errors.Is(err, storage.ErrNotFound) {
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

// eraseWalletData is the SID-AUTH-06 "secure erasure on deactivation" for one
// tenant: the credentials and presentations the user holds in that tenant are
// deleted. The user-level state - the encrypted private data and legacy key
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
	errs := s.eraseHolderData(ctx, tenantID, holder)

	tenants, err := s.userTenants(ctx, userID, tenantID)
	if err != nil {
		return append(errs, err)
	}
	if s.liveInstanceIn(ctx, tenants, tenantID, userID, &errs) {
		s.logger.Info("wallet data erased in tenant; user-level data kept, a live instance remains in another tenant",
			zap.String("user_id", userID.String()), zap.String("tenant_id", string(tenantID)))
		return errs
	}
	// No live instance anywhere: the wallet is deactivated. Erase the holder
	// data of every tenant the user belongs to (#195: stored VCs/VPs for all
	// of the user's tenants) and the pending challenges, then the user-level
	// key material. That last write also advances the token cut-off (one
	// atomic update, see UserStore.EraseWalletData) so a record loaded
	// before it is fenced out of Update. When everything succeeded the
	// acting token's exemption is dropped as well: a deactivated wallet
	// needs a new enrollment, and the session that deactivated it must not
	// be able to write new wallet data afterwards. When something failed the
	// exemption stays so the same session can repeat the request.
	for _, tid := range tenants {
		if tid != tenantID {
			errs = append(errs, s.eraseHolderData(ctx, tid, holder)...)
		}
	}
	// WebAuthn challenges are per user and deleted here. WIA challenges are
	// not: they are single-use, short-lived nonces that carry only a tenant,
	// belong to no user, and are useless to a deactivated wallet because
	// GenerateWIA refuses it before consuming one.
	if err := s.store.Challenges().DeleteByUserID(ctx, userID.String()); err != nil {
		errs = append(errs, fmt.Errorf("delete webauthn challenges: %w", err))
	}
	// The acting session's exemption exists to retry the erasure, so it ends
	// with the erasure: once the vault is gone the wallet is deactivated and
	// needs a new enrollment, and that session must not be able to write new
	// wallet data (private data, credentials) with its pre-cut-off token.
	// When this write fails the exemption stays as it was, so the same
	// session can repeat the request.
	if err := s.store.Users().EraseWalletData(ctx, userID, time.Now(), ""); err != nil {
		errs = append(errs, fmt.Errorf("erase wallet key material: %w", err))
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
	seen := map[domain.TenantID]bool{}
	var out []domain.TenantID
	for _, tid := range append([]domain.TenantID{include, domain.DefaultTenantID}, memberships...) {
		if !seen[tid] {
			seen[tid] = true
			out = append(out, tid)
		}
	}
	return out, nil
}

// liveInstanceIn reports whether the user still has a non-revoked wallet
// instance in any of tenants other than exclude. A listing failure is
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
			if inst.Status != domain.InstanceStatusRevoked {
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
		if err := s.store.Credentials().Delete(ctx, tid, did, c.CredentialIdentifier); err != nil {
			errs = append(errs, fmt.Errorf("delete credential %s: %w", c.CredentialIdentifier, err))
		}
	}
	pres, err := s.store.Presentations().GetAllByHolder(ctx, tid, did)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("list presentations: %w", err))
	}
	for _, p := range pres {
		if err := s.store.Presentations().Delete(ctx, tid, did, p.PresentationIdentifier); err != nil {
			errs = append(errs, fmt.Errorf("delete presentation %s: %w", p.PresentationIdentifier, err))
		}
	}
	return errs
}

func (s *WalletLifecycleService) emitAudit(instanceID string, status domain.InstanceStatus, reason string, actor LifecycleActor) {
	if s.audit == nil {
		return
	}
	var event set.EventURI
	switch status {
	case domain.InstanceStatusRevoked:
		event = set.EventWIRevoked
	case domain.InstanceStatusSuspended:
		event = set.EventWISuspended
	case domain.InstanceStatusActive:
		event = set.EventWICreated // re-activation
	default:
		event = set.EventWIDeactivated
	}
	s.audit.EmitWithSubject(event, instanceID, map[string]any{
		"status": string(status),
		"reason": reason,
		"actor":  actor.Kind,
	})
}
