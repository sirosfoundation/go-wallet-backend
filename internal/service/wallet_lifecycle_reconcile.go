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

// ReconcileWouldErase is the dry-run outcome for a user ReconcileUser would erase.
const ReconcileWouldErase ReconcileOutcome = "would_erase"

// Categories of leftover data a reconciliation reports; never contents.
const (
	leftoverPrivateData   = "private_data"
	leftoverKeyMaterial   = "key_material"
	leftoverCredentials   = "credentials"
	leftoverPresentations = "presentations"
)

// ReconcileUser finishes the erasure of a deactivated wallet: a user whose
// instances are all non-live, at least one revoked, the latest revoked at or
// before revokedBefore, and who still has key material, private data or holder
// data, gets the normal cascade. It takes the same per-user lock as the
// cascade and re-checks liveness inside it. Errors are
// ErrErasureIncomplete from the cascade or a failed probe; both are retryable
// and nothing is erased on a probe failure.
func (s *WalletLifecycleService) ReconcileUser(ctx context.Context, userID domain.UserID, revokedBefore time.Time) (ReconcileOutcome, error) {
	out, _, err := s.reconcile(ctx, userID, revokedBefore, false)
	return out, err
}

// ReconcileUserDryRun makes the same decision as ReconcileUser but writes
// nothing (not even the cut-off). A user that would be erased yields
// ReconcileWouldErase and the categories of data found.
func (s *WalletLifecycleService) ReconcileUserDryRun(ctx context.Context, userID domain.UserID, revokedBefore time.Time) (ReconcileOutcome, []string, error) {
	return s.reconcile(ctx, userID, revokedBefore, true)
}

func (s *WalletLifecycleService) reconcile(ctx context.Context, userID domain.UserID, revokedBefore time.Time, dryRun bool) (ReconcileOutcome, []string, error) {
	unlock, err := s.lockUserCtx(ctx, userID)
	if err != nil {
		return "", nil, fmt.Errorf("lock user: %w", err)
	}
	defer unlock()

	latest, outcome, err := s.reconcileCandidate(ctx, userID, revokedBefore)
	if err != nil || latest == nil {
		return outcome, nil, err
	}
	leftover, err := s.leftoverData(ctx, userID, latest.TenantID)
	if err != nil {
		return "", nil, err
	}
	if len(leftover) == 0 {
		return ReconcileClean, nil, nil
	}
	if dryRun {
		return ReconcileWouldErase, leftover, nil
	}
	if err := s.cascadeLocked(ctx, latest.TenantID, latest, reconcilerActor); err != nil {
		return "", leftover, err
	}
	return ReconcileErased, leftover, nil
}

// reconcileCandidate applies the liveness and grace checks. It returns the
// latest revoked instance when the user may be erased, else nil and why.
func (s *WalletLifecycleService) reconcileCandidate(ctx context.Context, userID domain.UserID, revokedBefore time.Time) (*domain.WalletInstance, ReconcileOutcome, error) {
	instances, err := s.store.WalletInstances().GetAllByUser(ctx, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, "", fmt.Errorf("list wallet instances: %w", err)
	}
	var revoked []*domain.WalletInstance
	for _, inst := range instances {
		switch {
		case inst.Status.IsLive() || !inst.Status.IsKnownNonLive():
			return nil, ReconcileLive, nil
		case inst.Status == domain.InstanceStatusRevoked:
			revoked = append(revoked, inst)
		}
	}
	if len(revoked) == 0 {
		return nil, ReconcileClean, nil
	}
	latest := latestRevoked(revoked)
	if latest.DeactivatedAt == nil || latest.DeactivatedAt.After(revokedBefore) {
		return nil, ReconcileGrace, nil
	}
	return latest, "", nil
}

// leftoverData lists the categories of wallet data the user still has in any
// tenant. Sessions and challenges are not probed; the cascade drops them
// whenever it runs.
func (s *WalletLifecycleService) leftoverData(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) ([]string, error) {
	user, err := s.store.Users().GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("load user: %w", err)
	}
	var found []string
	if len(user.PrivateData) > 0 {
		found = append(found, leftoverPrivateData)
	}
	if len(user.Keys) > 0 {
		found = append(found, leftoverKeyMaterial)
	}
	tenants, err := s.userTenants(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	holder := holderKey(user, userID)
	var hasCreds, hasPres bool
	for _, tid := range tenants {
		creds, err := s.store.Credentials().GetAllByHolder(ctx, tid, holder)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("list credentials: %w", err)
		}
		pres, err := s.store.Presentations().GetAllByHolder(ctx, tid, holder)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("list presentations: %w", err)
		}
		hasCreds = hasCreds || len(creds) > 0
		hasPres = hasPres || len(pres) > 0
	}
	if hasCreds {
		found = append(found, leftoverCredentials)
	}
	if hasPres {
		found = append(found, leftoverPresentations)
	}
	return found, nil
}
