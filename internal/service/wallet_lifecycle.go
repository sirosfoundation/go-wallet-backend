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
// server-side credentials, presentations and pending challenges are erased,
// and login is refused for every passkey of that user, so re-activation
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

// RevokeAllForUser revokes every non-revoked instance of the user in the
// tenant - the "deactivate my wallet" action - and returns how many changed.
// The cascade then erases the wallet data, since nothing live remains in the
// tenant. Like ChangeStatus it returns ErrErasureIncomplete when the
// revocations were persisted but the erasure did not complete; calling it
// again with everything already revoked re-runs the erasure.
func (s *WalletLifecycleService) RevokeAllForUser(ctx context.Context, actor LifecycleActor, tenantID domain.TenantID, userID domain.UserID, reason string) (int, error) {
	instances, err := s.ListForUser(ctx, tenantID, userID)
	if err != nil {
		return 0, err
	}
	changed := 0
	var last *domain.WalletInstance
	for _, inst := range instances {
		if inst.Status == domain.InstanceStatusRevoked {
			continue
		}
		if err := s.store.WalletInstances().UpdateStatus(ctx, inst.ID, domain.InstanceStatusRevoked, reason); err != nil {
			err = fmt.Errorf("revoke instance %s: %w", inst.ID, err)
			if last != nil {
				// Revocations already persisted in this loop must not keep
				// their tokens and sessions until the retry: cascade for
				// them now (the not-yet-revoked instance keeps the erasure
				// off) and report the request as incomplete.
				return changed, errors.Join(err, s.cascade(ctx, tenantID, last, actor))
			}
			return changed, err
		}
		inst.Status = domain.InstanceStatusRevoked
		s.emitAudit(inst.ID, domain.InstanceStatusRevoked, reason, actor)
		changed++
		last = inst
	}
	if last == nil && len(instances) > 0 {
		last = instances[len(instances)-1] // everything already revoked: retry the erasure
	}
	if last != nil {
		return changed, s.cascade(ctx, tenantID, last, actor)
	}
	return changed, nil
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
	// Bearer tokens already issued outlive the sessions dropped below (legacy
	// HMAC tokens for up to a day, refresh tokens longer); cut them off at
	// this instant so a suspended or revoked instance cannot keep calling
	// user-authorized endpoints. See internal/tokengate.
	if err := s.store.Users().InvalidateAuthBefore(ctx, userID, time.Now(), actor.TokenJTI); err != nil && !errors.Is(err, storage.ErrNotFound) {
		errs = append(errs, fmt.Errorf("cut off issued tokens: %w", err))
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

	live, err := s.liveInstanceElsewhere(ctx, userID, tenantID)
	if err != nil {
		return append(errs, err)
	}
	if live {
		s.logger.Info("wallet data erased in tenant; user-level data kept, a live instance remains in another tenant",
			zap.String("user_id", userID.String()), zap.String("tenant_id", string(tenantID)))
		return errs
	}
	// Field-scoped: a full-record Update from the user loaded above would
	// overwrite anything written concurrently (e.g. a passkey registration).
	if err := s.store.Users().ClearWalletData(ctx, userID); err != nil {
		errs = append(errs, fmt.Errorf("clear private data: %w", err))
	}
	if err := s.store.Challenges().DeleteByUserID(ctx, userID.String()); err != nil {
		errs = append(errs, fmt.Errorf("delete challenges: %w", err))
	}
	s.logger.Info("wallet data erased: last wallet instance revoked", zap.String("user_id", userID.String()), zap.String("tenant_id", string(tenantID)))
	return errs
}

// liveInstanceElsewhere reports whether the user still has a non-revoked
// wallet instance in any tenant other than exclude: the explicit memberships
// plus the default tenant, where users registered without a membership row
// live. A failed membership lookup is an error, because erasing the user-level
// data on a guess could destroy a wallet that is still in use elsewhere.
func (s *WalletLifecycleService) liveInstanceElsewhere(ctx context.Context, userID domain.UserID, exclude domain.TenantID) (bool, error) {
	tenantIDs, err := s.store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("list tenant memberships: %w", err)
	}
	tenantIDs = append(tenantIDs, domain.DefaultTenantID)
	seen := map[domain.TenantID]bool{exclude: true}
	for _, tid := range tenantIDs {
		if seen[tid] {
			continue
		}
		seen[tid] = true
		instances, err := s.store.WalletInstances().GetByUser(ctx, tid, userID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return false, fmt.Errorf("list instances in tenant %s: %w", tid, err)
		}
		for _, inst := range instances {
			if inst.Status != domain.InstanceStatusRevoked {
				return true, nil
			}
		}
	}
	return false, nil
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
