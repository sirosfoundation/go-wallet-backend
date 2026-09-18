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
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// SID-AUTH-06: a refresh token issued before the wallet was
// revoked must not mint new access tokens.
func TestRefreshAccessToken_RefusesTokenBeforeAuthCutoff(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", ExpiryHours: 1, RefreshDays: 7, Issuer: "t"}}
	svc := &WebAuthnService{store: store, cfg: cfg, logger: zap.NewNop()}
	user := &domain.User{UUID: domain.NewUserID(), DID: "did:x"}
	require.NoError(t, store.Users().Create(ctx, user))

	refresh, err := svc.generateRefreshToken(user, domain.DefaultTenantID)
	require.NoError(t, err)
	require.NotEmpty(t, refresh)

	_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refresh})
	require.NoError(t, err, "no cut-off yet")

	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, user.UUID, time.Now().Add(time.Second)))
	_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refresh})
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
}

// cutoffAfterFirstRead advances the user's cut-off once the flow has read it,
// i.e. after the refresh token was accepted and while the new tokens are
// being minted.
type cutoffAfterFirstRead struct {
	storage.UserStore
	uid   domain.UserID
	fired bool
}

func (u *cutoffAfterFirstRead) GetAuthCutoff(ctx context.Context, id domain.UserID) (time.Time, error) {
	cutoff, err := u.UserStore.GetAuthCutoff(ctx, id)
	if err == nil && !u.fired {
		u.fired = true
		if err := u.UserStore.InvalidateAuthBefore(ctx, u.uid, time.Now()); err != nil {
			return time.Time{}, err
		}
	}
	return cutoff, err
}

type racingUserStore struct {
	storage.Store
	users storage.UserStore
}

func (r *racingUserStore) Users() storage.UserStore { return r.users }

// A revocation landing while the refresh request runs must not be outrun by
// the freshly minted timestamps: the source refresh token is re-checked
// after minting.
func TestRefreshAccessToken_CutoffDuringRefreshIsRefused(t *testing.T) {
	ctx := context.Background()
	base := memory.NewStore()
	cfg := &config.Config{JWT: config.JWTConfig{Secret: "s", ExpiryHours: 1, RefreshDays: 7, Issuer: "t"}}
	user := &domain.User{UUID: domain.NewUserID(), DID: "did:x"}
	require.NoError(t, base.Users().Create(ctx, user))
	racing := &racingUserStore{Store: base, users: &cutoffAfterFirstRead{UserStore: base.Users(), uid: user.UUID}}
	svc := &WebAuthnService{store: racing, cfg: cfg, logger: zap.NewNop()}

	refresh, err := svc.generateRefreshToken(user, domain.DefaultTenantID)
	require.NoError(t, err)
	_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refresh})
	assert.ErrorIs(t, err, ErrInvalidRefreshToken, "the source refresh token predates the cut-off that landed mid-request")
}
