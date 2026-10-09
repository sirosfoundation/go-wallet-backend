package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// Every account-deletion sweep failure must answer ErrDeletionIncomplete and keep
// the user record: a deleted user cannot authenticate to ask again.
func TestDeleteUser_EveryFailureKeepsTheAccount(t *testing.T) {
	ops := []string{
		"users.GetByID",
		"usertenants.GetUserTenants",
		"instances.GetAllByUser",
		"instances.Delete",
		"credentials.GetAllByHolder",
		"credentials.Delete",
		"presentations.GetAllByHolder",
		"presentations.Delete",
	}
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			ctx := context.Background()
			fs := newFailStore()
			svc := NewUserService(fs, testConfig(), zap.NewNop())
			uid := seedWalletUser(t, fs.Store, domain.DefaultTenantID, "acme")

			fs.fail[op] = true
			err := svc.DeleteUser(ctx, uid, uid.String())
			require.ErrorIs(t, err, ErrDeletionIncomplete)
			_, gerr := fs.Store.Users().GetByID(ctx, uid)
			assert.NoError(t, gerr, "the user record must survive an incomplete deletion")

			// Repeating the request once the fault clears finishes the job.
			fs.fail[op] = false
			require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
			_, gerr = fs.Store.Users().GetByID(ctx, uid)
			assert.ErrorIs(t, gerr, storage.ErrNotFound)
			c, p := countHolderData(t, fs.Store, "acme", uid)
			assert.Zero(t, c+p, "holder data in every tenant is gone")
			left, _ := fs.Store.WalletInstances().GetAllByUser(ctx, uid)
			assert.Empty(t, left)
		})
	}
}

func TestUserService_LogoutEverywhere(t *testing.T) {
	ctx := context.Background()

	t.Run("cuts off tokens and drops sessions", func(t *testing.T) {
		fs := newFailStore()
		svc := NewUserService(fs, testConfig(), zap.NewNop())
		cleaner := &scriptedCleaner{}
		svc.SetSessionCleaner(cleaner)
		uid := seedWalletUser(t, fs.Store)
		require.NoError(t, svc.LogoutEverywhere(ctx, uid))
		assert.Equal(t, 1, cleaner.calls)
		cutoff, err := fs.Store.Users().GetAuthCutoff(ctx, uid)
		require.NoError(t, err)
		assert.False(t, cutoff.IsZero())
	})
	t.Run("unknown user", func(t *testing.T) {
		svc := NewUserService(newFailStore(), testConfig(), zap.NewNop())
		assert.ErrorIs(t, svc.LogoutEverywhere(ctx, domain.NewUserID()), ErrUserNotFound)
	})
	t.Run("user lookup fails", func(t *testing.T) {
		fs := newFailStore("users.GetByID")
		svc := NewUserService(fs, testConfig(), zap.NewNop())
		err := svc.LogoutEverywhere(ctx, domain.NewUserID())
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrUserNotFound)
	})
	t.Run("cut-off fails: nothing changes, sessions kept", func(t *testing.T) {
		fs := newFailStore("users.InvalidateAuthBefore")
		svc := NewUserService(fs, testConfig(), zap.NewNop())
		cleaner := &scriptedCleaner{}
		svc.SetSessionCleaner(cleaner)
		uid := seedWalletUser(t, fs.Store)
		require.Error(t, svc.LogoutEverywhere(ctx, uid))
		assert.Zero(t, cleaner.calls, "sessions must not be dropped while the tokens still work")
	})
	t.Run("session cleaner fails", func(t *testing.T) {
		fs := newFailStore()
		svc := NewUserService(fs, testConfig(), zap.NewNop())
		svc.SetSessionCleaner(&scriptedCleaner{failOn: map[int]bool{1: true}})
		uid := seedWalletUser(t, fs.Store)
		assert.Error(t, svc.LogoutEverywhere(ctx, uid))
	})
}
