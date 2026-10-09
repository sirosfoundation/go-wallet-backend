package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
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

// A lifecycle change landing between the login gate and token hand-out must
// not yield usable tokens; a same-second cut-off only delays minting.
func TestMintTokens(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	s := &WebAuthnService{store: store, logger: zap.NewNop(), cfg: &config.Config{JWT: config.JWTConfig{Secret: "s", ExpiryHours: 1, RefreshDays: 7, Issuer: "t"}}}
	userID := domain.NewUserID()
	user := &domain.User{UUID: userID, WebauthnCredentials: []domain.WebauthnCredential{{ID: "pk-1"}}}
	require.NoError(t, store.Users().Create(ctx, user))
	seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusActive)
	seedLifecycleInstance(t, s, "i2", userID, "pk-2", domain.InstanceStatusActive)
	gate := func() error { return s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1") }

	access, refresh, err := s.mintTokens(ctx, user, domain.DefaultTenantID, "", gate, ErrVerificationFailed)
	require.NoError(t, err, "no cut-off: tokens issued")
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)

	// Same-second cut-off: minted again in the next second and passes.
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, userID, time.Now()))
	access, refresh, err = s.mintTokens(ctx, user, domain.DefaultTenantID, "", gate, ErrVerificationFailed)
	require.NoError(t, err)
	cutoff, _ := store.Users().GetAuthCutoff(ctx, userID)
	// Both tokens must postdate the cut-off: the access token is minted first,
	// so gating on the refresh token alone could let a refused one out when the
	// mints straddle a second boundary.
	assert.False(t, tokengate.IssuedBeforeCutoff(tokengate.IssuedAt(access), cutoff), "the re-minted access token postdates the cut-off")
	require.NotEmpty(t, refresh)
	assert.False(t, tokengate.IssuedBeforeCutoff(tokengate.IssuedAt(refresh), cutoff), "the re-minted refresh token postdates the cut-off")

	// Future cut-off (a mid-request revocation) with the passkey's instance
	// revoked: the precise lifecycle refusal.
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "i1", domain.DefaultTenantID, domain.InstanceStatusRevoked, "stolen"))
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, userID, time.Now().Add(5*time.Second)))
	_, _, err = s.mintTokens(ctx, user, domain.DefaultTenantID, "", gate, ErrVerificationFailed)
	assert.ErrorIs(t, err, ErrWalletInstanceRevoked)

	// Same cut-off but the gate passes (other instance active): the caller's
	// refusal, so the client logs in again.
	gate2 := func() error { return s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-2") }
	_, _, err = s.mintTokens(ctx, user, domain.DefaultTenantID, "", gate2, ErrVerificationFailed)
	assert.ErrorIs(t, err, ErrVerificationFailed)
	_, _, err = s.mintTokens(ctx, user, domain.DefaultTenantID, "", nil, ErrInvalidRefreshToken)
	assert.ErrorIs(t, err, ErrInvalidRefreshToken, "refresh flow uses its own refusal")
}

// The cut-off is recorded before the status is persisted, so a login that
// passed its check earlier can mint a token past the cut-off mid-revocation;
// mintTokens' recheck must refuse it.
func TestMintTokens_RechecksLifecycleOnTheSuccessPath(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", ExpiryHours: 1, RefreshDays: 7, Issuer: "t"}}
	s := &WebAuthnService{store: store, cfg: cfg, logger: zap.NewNop()}
	userID := domain.NewUserID()
	user := &domain.User{UUID: userID, DID: "did:x"}
	require.NoError(t, store.Users().Create(ctx, user))
	seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusActive)

	// No cut-off: only the recheck can see the revocation.
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "i1", domain.DefaultTenantID, domain.InstanceStatusRevoked, "racing"))
	_, _, err := s.mintTokens(ctx, user, domain.DefaultTenantID, "", func() error {
		return s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1")
	}, ErrVerificationFailed)
	assert.ErrorIs(t, err, ErrWalletInstanceRevoked)
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
