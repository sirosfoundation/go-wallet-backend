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

	// The gate, and so the scope on the wire, is per tenant: a user live in
	// another tenant is still refused here, and their cross-tenant data is
	// kept (WalletLifecycleService.eraseWalletData). ErrWalletDeactivated
	// therefore means "no instance of this wallet is left in this tenant",
	// not "nothing of this user remains anywhere".
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

// A suspension or revocation that lands between the login gate and the
// sign-count save must not be undone by the stale user record, and must
// still refuse the login.
func TestPersistLoginState_LifecycleChangeDuringLogin(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	s := &WebAuthnService{store: store, logger: zap.NewNop()}
	userID := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: userID, PrivateData: []byte("vault"),
		WebauthnCredentials: []domain.WebauthnCredential{{ID: "pk-1"}}}))
	seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusActive)

	loaded, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	stale := *loaded
	stale.WebauthnCredentials = []domain.WebauthnCredential{{ID: "pk-1"}}
	stale.WebauthnCredentials[0].Authenticator.SignCount = 7

	t.Run("no lifecycle change: the sign count is saved", func(t *testing.T) {
		copyOf := stale
		require.NoError(t, s.persistLoginState(ctx, &copyOf, domain.DefaultTenantID, "pk-1"))
		u, _ := store.Users().GetByID(ctx, userID)
		assert.EqualValues(t, 7, u.WebauthnCredentials[0].Authenticator.SignCount)
	})

	t.Run("revoked during login: refused, erased data stays erased", func(t *testing.T) {
		require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "i1", domain.InstanceStatusRevoked, "stolen"))
		require.NoError(t, store.Users().InvalidateAuthBefore(ctx, userID, time.Now()))
		require.NoError(t, store.Users().EraseWalletData(ctx, userID, time.Now()))
		copyOf := stale // loaded before the revocation
		err := s.persistLoginState(ctx, &copyOf, domain.DefaultTenantID, "pk-1")
		assert.ErrorIs(t, err, ErrWalletInstanceRevoked)
		u, _ := store.Users().GetByID(ctx, userID)
		assert.Nil(t, u.PrivateData, "the stale record must not restore the vault")
		assert.False(t, u.AuthInvalidBefore.IsZero(), "the cut-off must not be rolled back")
	})
}

// A lifecycle change that lands after the login gate but before the tokens
// are handed out must not yield usable tokens; a cut-off in the very same
// second only delays minting to the next second.
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

	access, refresh, err := s.mintTokens(ctx, user, domain.DefaultTenantID, gate, ErrVerificationFailed)
	require.NoError(t, err, "no cut-off: tokens issued")
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)

	// Cut-off in the same second as minting: the tokens are minted again in
	// the next second and pass.
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, userID, time.Now()))
	access, refresh, err = s.mintTokens(ctx, user, domain.DefaultTenantID, gate, ErrVerificationFailed)
	require.NoError(t, err)
	cutoff, _ := store.Users().GetAuthCutoff(ctx, userID)
	// Both handed-out tokens have to postdate the cut-off, not just the last
	// one minted: the access token is minted first, so gating on the refresh
	// token alone would let an access token the token gate already refuses
	// out whenever the two mints straddle a second boundary.
	assert.False(t, tokengate.IssuedBeforeCutoff(tokengate.IssuedAt(access), cutoff), "the re-minted access token postdates the cut-off")
	require.NotEmpty(t, refresh)
	assert.False(t, tokengate.IssuedBeforeCutoff(tokengate.IssuedAt(refresh), cutoff), "the re-minted refresh token postdates the cut-off")

	// A cut-off set in the future (as a revocation landing mid-request would
	// be, relative to the minted iat) with the passkey's instance revoked:
	// the precise lifecycle refusal.
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "i1", domain.InstanceStatusRevoked, "stolen"))
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, userID, time.Now().Add(5*time.Second)))
	_, _, err = s.mintTokens(ctx, user, domain.DefaultTenantID, gate, ErrVerificationFailed)
	assert.ErrorIs(t, err, ErrWalletInstanceRevoked)

	// Same future cut-off but the gate passes (the other passkey's instance
	// is still active): refused with the caller's refusal so the client
	// logs in again.
	gate2 := func() error { return s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-2") }
	_, _, err = s.mintTokens(ctx, user, domain.DefaultTenantID, gate2, ErrVerificationFailed)
	assert.ErrorIs(t, err, ErrVerificationFailed)
	_, _, err = s.mintTokens(ctx, user, domain.DefaultTenantID, nil, ErrInvalidRefreshToken)
	assert.ErrorIs(t, err, ErrInvalidRefreshToken, "refresh flow uses its own refusal")
}

// The reload after ErrStaleWrite re-applies this login's sign count, and only
// this login's: the stale copy knows nothing about the other passkeys, so
// copying their counters back would roll back a raise a concurrent login on
// another device had already made - the very regression clone detection
// watches for.
func TestPersistLoginState_ReloadKeepsOtherPasskeySignCounts(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	s := &WebAuthnService{store: store, logger: zap.NewNop()}
	userID := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: userID,
		WebauthnCredentials: []domain.WebauthnCredential{{ID: "pk-1"}, {ID: "pk-2"}}}))
	seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusActive)

	// This login authenticated pk-1 and raised its counter to 7; it loaded
	// the record while pk-2 was still at 0.
	loaded, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	stale := *loaded
	stale.WebauthnCredentials = []domain.WebauthnCredential{{ID: "pk-1"}, {ID: "pk-2"}}
	stale.WebauthnCredentials[0].Authenticator.SignCount = 7

	// Meanwhile another device logged in with pk-2 and raised it to 42. That
	// write also moves the fence, so this login's copy is refused and
	// reloaded.
	fresh, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	fresh.WebauthnCredentials[1].Authenticator.SignCount = 42
	require.NoError(t, store.Users().Update(ctx, fresh))
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, userID, time.Now()))

	require.NoError(t, s.persistLoginState(ctx, &stale, domain.DefaultTenantID, "pk-1"))
	u, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.EqualValues(t, 7, u.WebauthnCredentials[0].Authenticator.SignCount, "this login's passkey is saved")
	assert.EqualValues(t, 42, u.WebauthnCredentials[1].Authenticator.SignCount, "the other device's raise survives")
}

// The cut-off is recorded before the new status is persisted, so a login that
// passed its lifecycle check earlier in the flow mints a token whose fresh
// iat clears the cut-off while the instance is being revoked. mintTokens
// runs the caller's check again over the post-mint state, so that login is
// refused rather than handed a working token for a revoked wallet.
func TestMintTokens_RechecksLifecycleOnTheSuccessPath(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", ExpiryHours: 1, RefreshDays: 7, Issuer: "t"}}
	s := &WebAuthnService{store: store, cfg: cfg, logger: zap.NewNop()}
	userID := domain.NewUserID()
	user := &domain.User{UUID: userID, DID: "did:x"}
	require.NoError(t, store.Users().Create(ctx, user))
	seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusActive)

	// No cut-off at all: the minted token is unimpeachable by iat alone, so
	// only the recheck can see the revocation that landed meanwhile.
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, "i1", domain.InstanceStatusRevoked, "racing"))
	_, _, err := s.mintTokens(ctx, user, domain.DefaultTenantID, func() error {
		return s.checkWalletLifecycle(ctx, domain.DefaultTenantID, userID, "pk-1")
	}, ErrVerificationFailed)
	assert.ErrorIs(t, err, ErrWalletInstanceRevoked)
}

// Two logins on the same passkey can interleave: the one that reloads after
// ErrStaleWrite may find the record already ahead of the assertion it
// verified. Re-applying its own count then would roll the counter back - the
// regression clone detection looks for - so the merge only ever moves it up.
func TestPersistLoginState_ReloadNeverRollsBackTheSamePasskey(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	s := &WebAuthnService{store: store, logger: zap.NewNop()}
	userID := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: userID,
		WebauthnCredentials: []domain.WebauthnCredential{{ID: "pk-1"}}}))
	seedLifecycleInstance(t, s, "i1", userID, "pk-1", domain.InstanceStatusActive)

	// This login verified an assertion at 8 and loaded the record before the
	// other one landed.
	loaded, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	stale := *loaded
	stale.WebauthnCredentials = []domain.WebauthnCredential{{ID: "pk-1"}}
	stale.WebauthnCredentials[0].Authenticator.SignCount = 8

	// A concurrent login on the same passkey already stored 10, and a
	// lifecycle write moved the fence, so this copy is refused and reloaded.
	fresh, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	fresh.WebauthnCredentials[0].Authenticator.SignCount = 10
	require.NoError(t, store.Users().Update(ctx, fresh))
	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, userID, time.Now()))

	require.NoError(t, s.persistLoginState(ctx, &stale, domain.DefaultTenantID, "pk-1"))
	u, err := store.Users().GetByID(ctx, userID)
	require.NoError(t, err)
	assert.EqualValues(t, 10, u.WebauthnCredentials[0].Authenticator.SignCount, "the counter only moves forward")
}
