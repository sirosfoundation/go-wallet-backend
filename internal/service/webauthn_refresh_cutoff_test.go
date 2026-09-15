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
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// SID-AUTH-06: a refresh token issued before the wallet was suspended or
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

	require.NoError(t, store.Users().InvalidateAuthBefore(ctx, user.UUID, time.Now().Add(time.Second), ""))
	_, err = svc.RefreshAccessToken(ctx, &RefreshTokenRequest{RefreshToken: refresh})
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
}
