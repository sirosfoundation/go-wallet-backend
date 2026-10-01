package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
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

// The lifecycle cascade that revoked the user's last other instance may have
// listed a raced first attestation while it was still active and so kept the
// vault. When the attestation path then revokes that instance itself, nothing
// live is left and the erasure has to happen now.
func TestWIAService_RevokeIfWalletDeactivatedMeanwhile_RunsTheCascade(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore()
	svc := newTestWIAServiceUsingStores(t, fs.WalletInstances(), fs.Users())
	svc.SetLifecycle(NewWalletLifecycleService(fs, zap.NewNop(), nil))
	uid := seedWalletUser(t, fs.Store)
	require.NoError(t, fs.Store.WalletInstances().UpdateStatus(ctx, "inst-"+uid.String(), domain.DefaultTenantID, domain.InstanceStatusRevoked, "stolen"))
	require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "raced", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
	}))

	err := svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &uid, "raced")
	require.ErrorIs(t, err, ErrWIAInstanceDeactivated)

	u, gerr := fs.Store.Users().GetByID(ctx, uid)
	require.NoError(t, gerr)
	assert.Empty(t, u.PrivateData, "the deactivated wallet's vault must be erased")
	c, p := countHolderData(t, fs.Store, domain.DefaultTenantID, uid)
	assert.Zero(t, c+p)
	cutoff, _ := fs.Store.Users().GetAuthCutoff(ctx, uid)
	assert.False(t, cutoff.IsZero(), "tokens are cut off")

	t.Run("a cascade that fails is reported with the refusal", func(t *testing.T) {
		fs := newFailStore("users.EraseWalletData")
		svc := newTestWIAServiceUsingStores(t, fs.WalletInstances(), fs.Users())
		svc.SetLifecycle(NewWalletLifecycleService(fs, zap.NewNop(), nil))
		uid := seedWalletUser(t, fs.Store)
		require.NoError(t, fs.Store.WalletInstances().UpdateStatus(ctx, "inst-"+uid.String(), domain.DefaultTenantID, domain.InstanceStatusRevoked, "x"))
		require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "raced", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
		}))
		err := svc.revokeIfWalletDeactivatedMeanwhile(ctx, domain.DefaultTenantID, &uid, "raced")
		assert.ErrorIs(t, err, ErrWIAInstanceDeactivated)
		assert.ErrorIs(t, err, ErrErasureIncomplete)
	})
}

// A token admitted before a user-wide cut-off (revoking one instance while
// another stays live) must not still obtain a WIA: GenerateWIA judges it at the
// point of signing.
func TestWIAService_GenerateWIA_RefusesATokenTheCutoffPredates(t *testing.T) {
	svc, store := newTestWIAServiceWithUsers(t)
	base := context.Background()
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid}))
	cutoff := time.Now().Truncate(time.Second)
	require.NoError(t, store.Users().InvalidateAuthBefore(base, uid, cutoff))

	attest := func(ctx context.Context) error {
		challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
		require.NoError(t, err)
		pop, _ := createTestPop(t, challenge)
		_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
		return err
	}
	assert.ErrorIs(t, attest(tokengate.WithSubject(base, uid.String(), cutoff.Add(-time.Minute))), tokengate.ErrRevoked)
	assert.NoError(t, attest(tokengate.WithSubject(base, uid.String(), cutoff.Add(time.Minute))))
}

// cutoffAdvancingUsers stands in for a user-wide revocation that lands while a
// request is in flight: GetAuthCutoff reports no cut-off for the first `after`
// reads and the given cut-off from then on.
type cutoffAdvancingUsers struct {
	storage.UserStore
	after  int
	cutoff time.Time
	reads  int
}

func (u *cutoffAdvancingUsers) GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error) {
	u.reads++
	if u.reads <= u.after {
		return time.Time{}, nil
	}
	return u.cutoff, nil
}

// A revocation landing after GenerateWIA's first cut-off check (before or during
// signing and the instance write) must still refuse the request, and when it
// lands before the write it must not record the instance either.
func TestWIAService_GenerateWIA_RevocationLandingBeforeSigningIsRefused(t *testing.T) {
	// GenerateWIA's own check is read 1; the signing-boundary check is read 2;
	// the release check is read 3.
	for _, tc := range []struct {
		name         string
		after        int
		wantRecorded bool
	}{
		{"between the first check and signing", 1, false},
		{"during the instance write", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := context.Background()
			store := memory.NewStore()
			uid := domain.NewUserID()
			require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid}))
			cutoff := time.Now().Truncate(time.Second)
			users := &cutoffAdvancingUsers{UserStore: store.Users(), after: tc.after, cutoff: cutoff}
			svc := newTestWIAServiceUsingStores(t, store.WalletInstances(), users)

			challenge, _, err := svc.CreateChallenge(base, domain.DefaultTenantID)
			require.NoError(t, err)
			pop, _ := createTestPop(t, challenge)
			ctx := tokengate.WithSubject(base, uid.String(), cutoff.Add(-time.Minute))

			token, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, &uid, &WIARequest{Pop: pop, Challenge: challenge})
			assert.ErrorIs(t, err, tokengate.ErrRevoked)
			assert.Empty(t, token, "no WIA may be released")

			recorded, gerr := store.WalletInstances().GetByUser(base, domain.DefaultTenantID, uid)
			require.NoError(t, gerr)
			if tc.wantRecorded {
				assert.Len(t, recorded, 1)
			} else {
				assert.Empty(t, recorded, "a refused request must not record the instance")
			}
		})
	}
}
