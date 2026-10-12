package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// ReconcileOutcome is what ReconcileUser decided for one user.
type ReconcileOutcome string

const (
	// ReconcileClean: not a deactivated wallet, or nothing left to erase.
	ReconcileClean ReconcileOutcome = "clean"
	// ReconcileLive: an instance is live (or has an unrecognized status), so nothing may be erased.
	ReconcileLive ReconcileOutcome = "live"
	// ReconcileGrace: the latest revocation is not yet older than the grace period.
	ReconcileGrace ReconcileOutcome = "grace"
	// ReconcileErased: wallet data was found and the cascade erased it.
	ReconcileErased ReconcileOutcome = "erased"
)

// reconcilerActor marks cascades run by the erasure reconciler.
var reconcilerActor = LifecycleActor{Kind: "reconciler"}

// ReconcileUser finishes the erasure of a deactivated wallet: a user whose
// instances are all non-live, at least one revoked, the latest revoked at or
// before revokedBefore, and who still has key material, private data or holder
// data, gets the normal cascade. It takes the same per-user lock as the
// cascade and re-checks liveness inside it. Errors are
// ErrErasureIncomplete from the cascade or a failed probe; both are retryable
// and nothing is erased on a probe failure.
func (s *WalletLifecycleService) ReconcileUser(ctx context.Context, userID domain.UserID, revokedBefore time.Time) (ReconcileOutcome, error) {
	defer s.LockUser(userID)()

	instances, err := s.store.WalletInstances().GetAllByUser(ctx, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return "", fmt.Errorf("list wallet instances: %w", err)
	}
	var revoked []*domain.WalletInstance
	for _, inst := range instances {
		switch {
		case inst.Status.IsLive() || !inst.Status.IsKnownNonLive():
			return ReconcileLive, nil
		case inst.Status == domain.InstanceStatusRevoked:
			revoked = append(revoked, inst)
		}
	}
	if len(revoked) == 0 {
		return ReconcileClean, nil
	}
	latest := latestRevoked(revoked)
	if latest.DeactivatedAt == nil || latest.DeactivatedAt.After(revokedBefore) {
		return ReconcileGrace, nil
	}
	present, err := s.walletDataPresent(ctx, userID, latest.TenantID)
	if err != nil {
		return "", err
	}
	if !present {
		return ReconcileClean, nil
	}
	if err := s.cascadeLocked(ctx, latest.TenantID, latest, reconcilerActor); err != nil {
		return "", err
	}
	return ReconcileErased, nil
}

// walletDataPresent reports whether the user still has private data, key
// material or holder data in any tenant. Sessions and challenges are not
// probed; the cascade drops them whenever it runs.
func (s *WalletLifecycleService) walletDataPresent(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (bool, error) {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("load user: %w", err)
	}
	if len(user.PrivateData) > 0 || len(user.Keys) > 0 {
		return true, nil
	}
	tenants, err := s.userTenants(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	holder := holderKey(user, userID)
	for _, tid := range tenants {
		creds, err := s.store.Credentials().GetAllByHolder(ctx, tid, holder)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return false, fmt.Errorf("list credentials: %w", err)
		}
		pres, err := s.store.Presentations().GetAllByHolder(ctx, tid, holder)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return false, fmt.Errorf("list presentations: %w", err)
		}
		if len(creds) > 0 || len(pres) > 0 {
			return true, nil
		}
	}
	return false, nil
}
