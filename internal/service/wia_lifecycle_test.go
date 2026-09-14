package service

import (
	"context"
	"errors"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

func seedWIAInstance(t *testing.T, instances interface {
	Upsert(context.Context, *domain.WalletInstance) error
	UpdateStatus(context.Context, string, domain.InstanceStatus, string) error
}, id string, userID domain.UserID, status domain.InstanceStatus) {
	t.Helper()
	ctx := context.Background()
	if err := instances.Upsert(ctx, &domain.WalletInstance{
		ID: id, TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatalf("Upsert %s: %v", id, err)
	}
	if status != domain.InstanceStatusActive {
		if err := instances.UpdateStatus(ctx, id, status, "seed"); err != nil {
			t.Fatalf("UpdateStatus %s: %v", id, err)
		}
	}
}

// A deactivated wallet (every instance revoked, data erased) must not be
// revived by attesting a brand-new instance key with an access token that
// outlived the deactivation: that would record a new active instance and
// re-open passkey login without the required new enrollment.
func TestWIAService_GenerateWIA_RefusesNewKeyForDeactivatedWallet(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()
	uid := domain.UserIDFromString("user-deactivated")
	seedWIAInstance(t, instances, "old-key-1", uid, domain.InstanceStatusRevoked)
	seedWIAInstance(t, instances, "old-key-2", uid, domain.InstanceStatusRevoked)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, _ := createTestPop(t, challenge) // a fresh instance key

	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
	if !errors.Is(err, ErrWIAInstanceDeactivated) {
		t.Fatalf("GenerateWIA with a new key for a deactivated wallet: got err=%v, want ErrWIAInstanceDeactivated", err)
	}

	byUser, err := instances.GetByUser(ctx, domain.DefaultTenantID, uid)
	if err != nil {
		t.Fatalf("GetByUser: %v", err)
	}
	if len(byUser) != 2 {
		t.Fatalf("instances after refused attempt = %d, want the 2 revoked ones only (no new instance recorded)", len(byUser))
	}
	for _, inst := range byUser {
		if inst.Status != domain.InstanceStatusRevoked {
			t.Errorf("instance %s status = %s, want revoked", inst.ID, inst.Status)
		}
	}
}

// A suspended instance is reactivatable, so the wallet is not deactivated and
// the user may still enroll another device.
func TestWIAService_GenerateWIA_AllowsNewKeyWhileAnInstanceIsSuspended(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	ctx := context.Background()
	uid := domain.UserIDFromString("user-suspended")
	seedWIAInstance(t, instances, "old-key-1", uid, domain.InstanceStatusRevoked)
	seedWIAInstance(t, instances, "old-key-2", uid, domain.InstanceStatusSuspended)

	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	pop, _ := createTestPop(t, challenge)

	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("GenerateWIA with a suspended (live) instance remaining: %v", err)
	}
	byUser, err := instances.GetByUser(ctx, domain.DefaultTenantID, uid)
	if err != nil {
		t.Fatalf("GetByUser: %v", err)
	}
	if len(byUser) != 3 {
		t.Errorf("instances = %d, want 3 (the new key was recorded)", len(byUser))
	}
}
