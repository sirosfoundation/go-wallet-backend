package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Clients switch on the code and scope, never on the message: a deactivated
// wallet must be told apart from one revoked instance whose siblings still
// answer for themselves.
func TestLifecycleRefusalDetails(t *testing.T) {
	wallet := LifecycleRefusalDetails(fmt.Errorf("login: %w", ErrWalletDeactivated))
	assert.Equal(t, "WALLET_REVOKED", wallet.Code)
	assert.Equal(t, LifecycleScopeWallet, wallet.Scope)
	assert.NotEmpty(t, wallet.Message)

	instance := LifecycleRefusalDetails(fmt.Errorf("login: %w", ErrWalletInstanceRevoked))
	assert.Equal(t, "WALLET_REVOKED", instance.Code, "the code stays the one existing clients switch on")
	assert.Equal(t, LifecycleScopeInstance, instance.Scope)
	assert.NotEqual(t, wallet.Message, instance.Message)
}

func TestRefuseIfSourceCutOff(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", ExpiryHours: 1, RefreshDays: 7, Issuer: "t"}}
	newSvc := func(fs *failStore) *WebAuthnService {
		return &WebAuthnService{store: fs, cfg: cfg, logger: zap.NewNop()}
	}
	cutoff := time.Now().Truncate(time.Second)

	t.Run("a refresh token from before the cut-off is refused", func(t *testing.T) {
		fs := newFailStore()
		uid := seedWalletUser(t, fs.Store)
		require.NoError(t, fs.Store.Users().InvalidateAuthBefore(ctx, uid, cutoff))
		s := newSvc(fs)
		assert.ErrorIs(t, s.refuseIfSourceCutOff(ctx, uid, cutoff.Add(-time.Minute)), ErrInvalidRefreshToken)
		assert.NoError(t, s.refuseIfSourceCutOff(ctx, uid, cutoff.Add(time.Minute)))
	})
	t.Run("an unknown user cannot refresh", func(t *testing.T) {
		assert.ErrorIs(t, newSvc(newFailStore()).refuseIfSourceCutOff(ctx, domain.NewUserID(), time.Now()), ErrInvalidRefreshToken)
	})
	t.Run("a store failure is not a refusal of the token", func(t *testing.T) {
		fs := newFailStore("users.GetAuthCutoff")
		err := newSvc(fs).refuseIfSourceCutOff(ctx, domain.NewUserID(), time.Now())
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrInvalidRefreshToken)
	})
}
