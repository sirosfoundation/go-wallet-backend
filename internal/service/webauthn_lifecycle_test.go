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
		require.NoError(t, s.store.WalletInstances().UpdateStatus(ctx, id, domain.DefaultTenantID, status, "test"))
	}
}

// The SID-AUTH-06 login gate: which passkeys may still log in.
func TestCheckWalletLifecycle(t *testing.T) {
	ctx := context.Background()
	userID := domain.NewUserID()

	t.Run("no instances yet: allowed", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		assert.NoError(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"))
	})

	// The gate is per tenant: a user live in another tenant is still refused
	// here and their cross-tenant data is kept (eraseWalletData).
	t.Run("deactivated in this tenant while another tenant is live", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		other := domain.TenantID("tenant-other")
		seedLifecycleInstance(t, s, "inst-here", userID, "pk-1", domain.InstanceStatusRevoked)
		require.NoError(t, s.store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: "inst-there", TenantID: other, UserID: &userID, CredentialID: "pk-2", Status: domain.InstanceStatusActive,
		}))

		assert.ErrorIs(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"), ErrWalletDeactivated,
			"no instance is left in this tenant, so this login is refused as a deactivated wallet")
		assert.NoError(t, s.checkWalletLifecycle(ctx, other, userID, "pk-2"),
			"the same user keeps logging in where they still have a live instance")
	})

	t.Run("linked instance revoked: refused with revoked", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusRevoked)
		seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusActive)
		assert.ErrorIs(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"), ErrWalletInstanceRevoked)
		assert.NoError(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-2"), "the other device still logs in")
	})

	t.Run("unlinked revoked instance does not block other passkeys", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "", domain.InstanceStatusRevoked)
		seedLifecycleInstance(t, s, "i2", userID, "", domain.InstanceStatusActive)
		assert.NoError(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"),
			"a revoked instance this passkey is not linked to must not block the login")
	})

	// An unrecognized status fails closed: refused, but not reported as a
	// deactivated wallet, and never treated as enrollment or live.
	t.Run("unknown status instance: refused, not reported as deactivated", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedRawInstance(t, s.store, domain.DefaultTenantID, "i1", userID, "pk-1", unknownInstanceStatus)
		err := s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrWalletDeactivated)
		assert.NotErrorIs(t, err, ErrWalletInstanceRevoked)
	})

	t.Run("unknown status linked to this passkey beside an active one: refused", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedRawInstance(t, s.store, domain.DefaultTenantID, "i1", userID, "pk-1", unknownInstanceStatus)
		seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusActive)
		for _, pk := range []string{"pk-1", "pk-2"} {
			err := s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, pk)
			require.Error(t, err, "an unrecognized status refuses every passkey, not only the linked one: %s", pk)
			assert.NotErrorIs(t, err, ErrWalletDeactivated)
			assert.NotErrorIs(t, err, ErrWalletInstanceRevoked, "no lifecycle state was established")
		}
	})

	t.Run("unknown status beside a revoked linked instance: unrecognized, not revoked", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusRevoked)
		seedRawInstance(t, s.store, domain.DefaultTenantID, "i2", userID, "pk-2", unknownInstanceStatus)
		seedLifecycleInstance(t, s, "i3", userID, "pk-3", domain.InstanceStatusActive)
		err := s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrWalletInstanceRevoked)
		assert.Contains(t, err.Error(), "unrecognized status")
	})

	t.Run("every instance revoked: wallet deactivated, any passkey refused", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "", domain.InstanceStatusRevoked)
		seedLifecycleInstance(t, s, "i2", userID, "", domain.InstanceStatusRevoked)
		err := s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-new")
		assert.ErrorIs(t, err, ErrWalletDeactivated)
		assert.ErrorIs(t, err, ErrWalletInstanceRevoked, "deactivation is a kind of revocation for callers that do not distinguish")
	})

	t.Run("every instance revoked: the linked passkey is told deactivated, not merely revoked", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusRevoked)
		seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusRevoked)
		err := s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1")
		assert.ErrorIs(t, err, ErrWalletDeactivated,
			"no device can log in any more, so the refusal must not suggest using another one")
	})

	t.Run("passkey linked to both a revoked and an active instance fails closed", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		// Store ordering must not decide: seed the active duplicate first.
		seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusActive)
		seedLifecycleInstance(t, s, "i2", userID, "pk-1", domain.InstanceStatusRevoked)
		assert.ErrorIs(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"), ErrWalletInstanceRevoked,
			"an active duplicate link must not let a passkey of a revoked instance log in")

	})

	t.Run("linked instance revoked while another is live is not deactivation", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusRevoked)
		seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusActive)
		err := s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1")
		assert.ErrorIs(t, err, ErrWalletInstanceRevoked)
		assert.NotErrorIs(t, err, ErrWalletDeactivated, "the user can still log in from the other device")
	})
}

// A record left in the legacy "suspended" state must still be refused at
// login; reading it as live would restore a login a provider removed.
func TestCheckWalletLifecycle_LegacySuspended(t *testing.T) {
	ctx := context.Background()
	userID := domain.NewUserID()

	seedLegacy := func(t *testing.T, s *WebAuthnService, id, credentialID string) {
		t.Helper()
		require.NoError(t, s.store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
			ID: id, TenantID: domain.DefaultTenantID, UserID: &userID, CredentialID: credentialID,
			Status: domain.InstanceStatusLegacySuspended,
		}))
	}

	t.Run("the linked passkey is refused", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLegacy(t, s, "i1", "pk-1")
		seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusActive)
		assert.ErrorIs(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1"), ErrWalletInstanceRevoked)
		assert.NoError(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-2"), "the other device still logs in")
	})

	t.Run("it does not count as a live instance", func(t *testing.T) {
		s := &WebAuthnService{store: memory.NewStore()}
		seedLegacy(t, s, "i1", "pk-1")
		seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusRevoked)
		assert.ErrorIs(t, s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-new"), ErrWalletDeactivated,
			"nothing live is left, so every passkey is refused as a deactivated wallet")
	})
}
