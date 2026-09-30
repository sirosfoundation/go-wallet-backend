package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// The login no longer rewrites the whole user document (there is no
// persistLoginState any more): it persists the sign count with a field-scoped
// atomic update, and relies on mintTokens' post-mint lifecycle recheck plus the
// cut-off the revocation records after its status write. This test races the
// two directly and asserts the property that matters: a login that returns a
// token for an instance while that instance is being revoked never returns one
// the token gate would still accept once the revocation has completed.
func TestLoginRacingRevocation_NoTokenSurvivesTheRevocation(t *testing.T) {
	const workers = 12
	store := memory.NewStore()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", ExpiryHours: 1, RefreshDays: 7, Issuer: "t"}}
	s := &WebAuthnService{store: store, cfg: cfg, logger: zap.NewNop()}
	lifecycle := NewWalletLifecycleService(store, zap.NewNop(), nil)
	gate := tokengate.New(store.Users())
	ctx := context.Background()

	type outcome struct {
		token   string
		loginOK bool
		revoked bool
	}
	results := make([]outcome, workers)
	users := make([]domain.UserID, workers)
	for i := range users {
		users[i] = domain.NewUserID()
		require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: users[i], DID: "did:x:" + users[i].String()}))
		seedLifecycleInstance(t, s, "inst-"+users[i].String(), users[i], "pk-"+users[i].String(), domain.InstanceStatusActive)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		i := i
		uid := users[i]
		instID := "inst-" + uid.String()
		credID := "pk-" + uid.String()
		wg.Add(2)
		go func() { // the login
			defer wg.Done()
			<-start
			user, err := store.Users().GetByID(ctx, uid)
			if err != nil {
				return
			}
			access, _, err := s.mintTokens(ctx, user, domain.DefaultTenantID, func() error {
				return s.checkWalletLifecycle(ctx, domain.DefaultTenantID, uid, credID)
			}, ErrVerificationFailed)
			if err == nil {
				results[i].token, results[i].loginOK = access, true
			}
		}()
		go func() { // the provider revoking the instance
			defer wg.Done()
			<-start
			// Spread the interleavings over the window instead of always
			// starting both at the same instant.
			time.Sleep(time.Duration(i) * 20 * time.Millisecond)
			_, err := lifecycle.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, instID, domain.InstanceStatusRevoked, "race")
			results[i].revoked = err == nil
		}()
	}
	close(start)
	wg.Wait()

	returned := 0
	for i, r := range results {
		require.True(t, r.revoked, "worker %d: revocation must complete", i)
		if !r.loginOK {
			continue
		}
		returned++
		// The revocation is complete. A token the login handed out must be
		// refused, whichever side of the revocation it was minted on.
		err := gate.Check(ctx, users[i].String(), tokengate.IssuedAt(r.token))
		assert.ErrorIs(t, err, tokengate.ErrRevoked, "worker %d: a token minted around the revocation still passes the gate", i)
	}
	t.Logf("%d of %d logins returned a token (all refused by the gate afterwards)", returned, workers)
}

// hookStore runs a callback just before a wallet instance is revoked, i.e. in
// the window after the revocation's first cut-off and before its status write.
type hookStore struct {
	storage.Store
	beforeRevoke func()
}

type hookInstances struct {
	storage.WalletInstanceStore
	h *hookStore
}

func (s *hookStore) WalletInstances() storage.WalletInstanceStore {
	return &hookInstances{s.Store.WalletInstances(), s}
}

func (s *hookInstances) UpdateStatus(ctx context.Context, id string, tenantID domain.TenantID, st domain.InstanceStatus, reason string) error {
	if s.h.beforeRevoke != nil {
		s.h.beforeRevoke()
	}
	return s.WalletInstanceStore.UpdateStatus(ctx, id, tenantID, st, reason)
}

// The narrow window, made deterministic: a login completes entirely between the
// revocation's pre-write cut-off and its status write. It sees a live instance,
// mints a token whose iat is past that first cut-off and returns it. The
// re-cut after the status write is what makes the token die with the
// revocation; without it this token would be accepted by every gate.
func TestLoginInsideTheRevocationWindow_TokenIsCutOffByTheSecondCutoff(t *testing.T) {
	ctx := context.Background()
	mem := memory.NewStore()
	h := &hookStore{Store: mem}
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", ExpiryHours: 1, RefreshDays: 7, Issuer: "t"}}
	s := &WebAuthnService{store: h, cfg: cfg, logger: zap.NewNop()}
	lifecycle := NewWalletLifecycleService(h, zap.NewNop(), nil)
	gate := tokengate.New(mem.Users())

	uid := domain.NewUserID()
	user := &domain.User{UUID: uid, DID: "did:x"}
	require.NoError(t, mem.Users().Create(ctx, user))
	seedLifecycleInstance(t, s, "inst-w", uid, "pk-w", domain.InstanceStatusActive)
	// A second live instance keeps the wallet alive, so the cascade does not
	// erase and the erasure's own cut-off cannot mask a missing second one.
	seedLifecycleInstance(t, s, "inst-other", uid, "pk-other", domain.InstanceStatusActive)

	var token string
	var loginErr error
	h.beforeRevoke = func() {
		// Move past the second the first cut-off was recorded in, so the
		// token's iat is strictly after it and only the second cut-off can
		// refuse it.
		time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 10*time.Millisecond)))
		token, _, loginErr = s.mintTokens(ctx, user, domain.DefaultTenantID, func() error {
			return s.checkWalletLifecycle(ctx, domain.DefaultTenantID, uid, "pk-w")
		}, ErrVerificationFailed)
	}
	_, err := lifecycle.ChangeStatus(ctx, LifecycleActor{Kind: "provider"}, domain.DefaultTenantID, "inst-w", domain.InstanceStatusRevoked, "stolen")
	require.NoError(t, err)

	require.NoError(t, loginErr, "the login saw a live instance and completed inside the window")
	require.NotEmpty(t, token)
	assert.ErrorIs(t, gate.Check(ctx, uid.String(), tokengate.IssuedAt(token)), tokengate.ErrRevoked,
		"a token minted between the first cut-off and the status write must not survive the revocation")
}
