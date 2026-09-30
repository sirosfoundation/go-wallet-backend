package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

func TestWIAService_WIALifetime(t *testing.T) {
	svc, _ := newTestWIAServiceWithInstances(t)
	cases := []struct {
		name      string
		life, max int
		want      time.Duration
	}{
		{"within the cap", 300, 3600, 300 * time.Second},
		{"unset lifetime falls back to the cap", 0, 3600, time.Hour},
		{"lifetime above the cap is capped", 7200, 3600, time.Hour},
		{"no cap configured defaults to a day", 0, 0, 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc.cfg.WalletProvider.Attestation.LifetimeSeconds = tc.life
			svc.cfg.WalletProvider.WIA.MaxExpirySeconds = tc.max
			assert.Equal(t, tc.want, svc.wiaLifetime())
		})
	}
}

// A claimed passkey needs a user to belong to and a store to check against;
// without either the claim is refused, never waved through.
func TestWIAService_CheckCredentialOwnership_Refusals(t *testing.T) {
	ctx := context.Background()
	uid := domain.NewUserID()

	t.Run("no claim is fine", func(t *testing.T) {
		svc, _ := newTestWIAServiceWithInstances(t)
		assert.NoError(t, svc.checkCredentialOwnership(ctx, domain.DefaultTenantID, nil, ""))
	})
	t.Run("anonymous attestation cannot claim a passkey", func(t *testing.T) {
		svc, _ := newTestWIAServiceWithInstances(t)
		assert.ErrorIs(t, svc.checkCredentialOwnership(ctx, domain.DefaultTenantID, nil, "pk"), ErrWIACredentialNotOwned)
	})
	t.Run("no user store cannot verify", func(t *testing.T) {
		svc, _ := newTestWIAServiceWithInstances(t)
		assert.ErrorIs(t, svc.checkCredentialOwnership(ctx, domain.DefaultTenantID, &uid, "pk"), ErrWIACredentialNotOwned)
	})
	t.Run("unknown user", func(t *testing.T) {
		svc, _ := newTestWIAServiceWithUsers(t)
		assert.ErrorIs(t, svc.checkCredentialOwnership(ctx, domain.DefaultTenantID, &uid, "pk"), ErrWIACredentialNotOwned)
	})
	t.Run("store failure is not reported as not-owned", func(t *testing.T) {
		fs := newFailStore("users.GetByID")
		svc := newTestWIAServiceUsingStores(t, fs.WalletInstances(), fs.Users())
		err := svc.checkCredentialOwnership(ctx, domain.DefaultTenantID, &uid, "pk")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrWIACredentialNotOwned)
	})
}

func TestWIAService_RefuseIfUserGone(t *testing.T) {
	ctx := context.Background()
	uid := domain.NewUserID()

	t.Run("a store failure is an error, not a pass", func(t *testing.T) {
		fs := newFailStore("users.GetByID")
		svc := newTestWIAServiceUsingStores(t, fs.WalletInstances(), fs.Users())
		err := svc.refuseIfUserGone(ctx, &uid)
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrWIAUnknownUser)
	})
	t.Run("deleted user", func(t *testing.T) {
		svc, _ := newTestWIAServiceWithUsers(t)
		assert.ErrorIs(t, svc.refuseIfUserGone(ctx, &uid), ErrWIAUnknownUser)
	})
	t.Run("anonymous and unchecked", func(t *testing.T) {
		svc, _ := newTestWIAServiceWithInstances(t)
		assert.NoError(t, svc.refuseIfUserGone(ctx, nil))
		assert.NoError(t, svc.refuseIfUserGone(ctx, &uid), "no user store configured: nothing to check")
	})
}

func TestWIAService_LifecycleReads_FailClosed(t *testing.T) {
	ctx := context.Background()
	uid := domain.NewUserID()

	t.Run("refuseIfWalletDeactivated: listing fails", func(t *testing.T) {
		fs := newFailStore("instances.GetByUser")
		svc := newTestWIAServiceUsing(t, fs.WalletInstances())
		assert.Error(t, svc.refuseIfWalletDeactivated(ctx, domain.DefaultTenantID, &uid))
		assert.NoError(t, svc.refuseIfWalletDeactivated(ctx, domain.DefaultTenantID, nil), "anonymous has no wallet")
	})
	t.Run("revokeIfWalletDeactivatedMeanwhile: listing fails", func(t *testing.T) {
		fs := newFailStore("instances.GetByUser")
		svc := newTestWIAServiceUsing(t, fs.WalletInstances())
		assert.Error(t, svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &uid, "new-key"))
		assert.NoError(t, svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, nil, "new-key"))
	})
	t.Run("recheckLifecycleAfterWrite: read-back fails", func(t *testing.T) {
		fs := newFailStore("instances.GetByID")
		svc := newTestWIAServiceUsing(t, fs.WalletInstances())
		assert.Error(t, svc.recheckLifecycleAfterWrite(ctx, domain.DefaultTenantID, &uid, "k", "", false))
	})
}

// The post-insert deactivation re-check must not revoke on evidence that only
// shows the record belongs to someone else, and must tolerate the record being
// gone.
func TestWIAService_RevokeIfWalletDeactivatedMeanwhile_OwnershipAndAbsence(t *testing.T) {
	ctx := context.Background()
	mine, other := domain.NewUserID(), domain.NewUserID()

	newSvc := func(t *testing.T) (*WIAService, *failStore) {
		fs := newFailStore()
		return newTestWIAServiceUsing(t, fs.WalletInstances()), fs
	}
	// The wallet looks deactivated (an old instance is revoked), so the
	// function proceeds to look at the new record.
	seedDeactivated := func(t *testing.T, fs *failStore) {
		seedWIAInstance(t, fs.WalletInstances(), "old", mine, domain.InstanceStatusRevoked)
	}

	t.Run("new record vanished", func(t *testing.T) {
		svc, fs := newSvc(t)
		seedDeactivated(t, fs)
		assert.NoError(t, svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &mine, "gone"))
	})
	t.Run("new record read fails", func(t *testing.T) {
		svc, fs := newSvc(t)
		seedDeactivated(t, fs)
		fs.fail["instances.GetByID"] = true
		assert.Error(t, svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &mine, "new"))
	})
	t.Run("record belongs to another tenant", func(t *testing.T) {
		svc, fs := newSvc(t)
		seedDeactivated(t, fs)
		require.NoError(t, fs.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "new", TenantID: "elsewhere", UserID: &mine, Status: domain.InstanceStatusActive,
		}))
		assert.ErrorIs(t, svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &mine, "new"), ErrWIAInstanceNotOwned)
		got, err := fs.WalletInstances().GetByID(ctx, "new")
		require.NoError(t, err)
		assert.Equal(t, domain.InstanceStatusActive, got.Status, "another tenant's instance must not be revoked")
	})
	t.Run("record bound to another user", func(t *testing.T) {
		svc, fs := newSvc(t)
		seedDeactivated(t, fs)
		require.NoError(t, fs.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "new", TenantID: domain.DefaultTenantID, UserID: &other, Status: domain.InstanceStatusActive,
		}))
		assert.ErrorIs(t, svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &mine, "new"), ErrWIAInstanceNotOwned)
		got, err := fs.WalletInstances().GetByID(ctx, "new")
		require.NoError(t, err)
		assert.Equal(t, domain.InstanceStatusActive, got.Status, "the winner's instance must not be revoked")
	})
	t.Run("revocation fails", func(t *testing.T) {
		svc, fs := newSvc(t)
		seedDeactivated(t, fs)
		require.NoError(t, fs.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "new", TenantID: domain.DefaultTenantID, UserID: &mine, Status: domain.InstanceStatusActive,
		}))
		fs.fail["instances.UpdateStatus"] = true
		err := svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &mine, "new")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrWIAInstanceDeactivated, "an unrevoked instance must not be reported as handled")
	})
}
