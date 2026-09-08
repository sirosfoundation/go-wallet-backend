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
// domain.ErrInvalidStatusTransition for the caller to map.
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
		return inst, nil
	}
	if err := s.store.WalletInstances().UpdateStatus(ctx, instanceID, target, reason); err != nil {
		return nil, err
	}
	inst.Status = target
	inst.UpdatedAt = time.Now().UTC()
	s.emitAudit(inst.ID, target, reason, actor)
	if target != domain.InstanceStatusActive {
		s.cascade(ctx, tenantID, inst)
	}
	return inst, nil
}

// RevokeAllForUser revokes every non-revoked instance of the user in the
// tenant - the "deactivate my wallet" action - and returns how many changed.
// The cascade then erases the wallet data, since nothing live remains.
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
			return changed, fmt.Errorf("revoke instance %s: %w", inst.ID, err)
		}
		inst.Status = domain.InstanceStatusRevoked
		s.emitAudit(inst.ID, domain.InstanceStatusRevoked, reason, actor)
		changed++
		last = inst
	}
	if last != nil {
		s.cascade(ctx, tenantID, last)
	}
	return changed, nil
}

// cascade runs after an instance left the active state: drop the user's live
// sessions, and erase the wallet data once no instance the user could
// reactivate remains.
func (s *WalletLifecycleService) cascade(ctx context.Context, tenantID domain.TenantID, inst *domain.WalletInstance) {
	if inst.UserID == nil {
		return
	}
	userID := *inst.UserID
	if s.sessionCleaner != nil {
		if err := s.sessionCleaner.DeleteByUser(ctx, userID.String()); err != nil {
			s.logger.Warn("failed to drop sessions after instance status change", zap.Error(err))
		}
	}
	remaining, err := s.store.WalletInstances().GetByUser(ctx, tenantID, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		s.logger.Warn("failed to list remaining instances; not erasing wallet data", zap.Error(err))
		return
	}
	for _, other := range remaining {
		if other.Status != domain.InstanceStatusRevoked {
			return // something is still active or reactivatable
		}
	}
	s.eraseWalletData(ctx, userID)
}

// eraseWalletData is the SID-AUTH-06 "secure erasure on deactivation": the
// same server-side data UserService.DeleteUser removes, but the user record
// and its passkeys stay so the revocation remains attributable and login can
// be refused with a clear reason rather than "user not found".
func (s *WalletLifecycleService) eraseWalletData(ctx context.Context, userID domain.UserID) {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		s.logger.Warn("failed to load user for wallet erasure", zap.Error(err))
		return
	}
	user.PrivateData = nil
	user.PrivateDataETag = ""
	user.UpdatedAt = time.Now()
	if err := s.store.Users().Update(ctx, user); err != nil {
		s.logger.Warn("failed to clear private data", zap.Error(err))
	}

	tenantIDs, err := s.store.UserTenants().GetUserTenants(ctx, userID)
	if err != nil || len(tenantIDs) == 0 {
		tenantIDs = []domain.TenantID{domain.DefaultTenantID}
	}
	if user.DID != "" {
		for _, tid := range tenantIDs {
			creds, err := s.store.Credentials().GetAllByHolder(ctx, tid, user.DID)
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				s.logger.Warn("failed to list credentials for erasure", zap.Error(err))
			}
			for _, c := range creds {
				if err := s.store.Credentials().Delete(ctx, tid, user.DID, c.CredentialIdentifier); err != nil {
					s.logger.Warn("failed to delete credential", zap.Error(err))
				}
			}
			pres, err := s.store.Presentations().GetAllByHolder(ctx, tid, user.DID)
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				s.logger.Warn("failed to list presentations for erasure", zap.Error(err))
			}
			for _, p := range pres {
				if err := s.store.Presentations().Delete(ctx, tid, user.DID, p.PresentationIdentifier); err != nil {
					s.logger.Warn("failed to delete presentation", zap.Error(err))
				}
			}
		}
	}
	if err := s.store.Challenges().DeleteByUserID(ctx, userID.String()); err != nil {
		s.logger.Warn("failed to delete challenges", zap.Error(err))
	}
	s.logger.Info("wallet data erased: last wallet instance revoked", zap.String("user_id", userID.String()))
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
