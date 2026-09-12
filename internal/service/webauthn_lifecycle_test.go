package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func seedLifecycleInstance(t *testing.T, s *WebAuthnService, id string, userID domain.UserID, credentialID string, status domain.InstanceStatus) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, s.store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: id, TenantID: domain.DefaultTenantID, UserID: &userID, CredentialID: credentialID, Status: domain.InstanceStatusActive,
	}))
	if status != domain.InstanceStatusActive {
		require.NoError(t, s.store.WalletInstances().UpdateStatus(ctx, id, status, "test"))
	}
}

// The SID-AUTH-06 login gate: which passkeys may still log in given the
// user's wallet instances.
func TestCheckWalletLifecycle(t *testing.T) {
	ctx := context.Background()
	userID := domain.NewUserID()

	t.Run("no instances yet: allowed", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		assert.NoError(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"))
	})

	t.Run("linked instance suspended: refused with suspended", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusSuspended)
		seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusActive)
		assert.ErrorIs(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"), ErrWalletInstanceSuspended)
		assert.NoError(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-2"), "the other device still logs in")
	})

	t.Run("linked instance revoked: refused with revoked", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusRevoked)
		seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusActive)
		assert.ErrorIs(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"), ErrWalletInstanceRevoked)
	})

	t.Run("unlinked suspended instance does not block other passkeys", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "", domain.InstanceStatusSuspended)
		assert.NoError(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"),
			"the user must be able to log in from another device to manage a suspended one")
	})

	t.Run("every instance revoked: wallet deactivated, any passkey refused", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "", domain.InstanceStatusRevoked)
		seedLifecycleInstance(t, s, "i2", userID, "", domain.InstanceStatusRevoked)
		assert.ErrorIs(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-new"), ErrWalletInstanceRevoked)
	})
}
