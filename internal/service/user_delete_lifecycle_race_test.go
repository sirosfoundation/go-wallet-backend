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

// hookCleaner runs onCall on its first invocation, which is the window between
// the request's initial cut-off check and the irreversible phase.
type hookCleaner struct {
	onCall func()
	calls  int
}

func (c *hookCleaner) DeleteByUser(context.Context, string) error {
	c.calls++
	if c.calls == 1 && c.onCall != nil {
		c.onCall()
	}
	return nil
}

// A lifecycle revocation that lands while the deletion is running advances the
// cut-off independently. The token admitted before it must be refused before the
// permanent revocations and the user deletion, not just have its cut-off
// silently overwritten.
func TestDeleteUser_RefusesATokenCutOffByALifecycleRevocationMidDeletion(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), zap.NewNop())
	bl, ur := &countingRevoker{}, &countingUserRevoker{}
	svc.SetTokenBlacklist(bl)
	svc.AddUserRevoker(ur)
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}))

	iat := time.Now().Add(-time.Minute)
	svc.SetSessionCleaner(&hookCleaner{onCall: func() {
		require.NoError(t, store.Users().InvalidateAuthBefore(ctx, uid, time.Now()))
	}})

	err := svc.DeleteUser(tokengate.WithIssuedAt(ctx, iat), uid, uid.String())
	require.ErrorIs(t, err, tokengate.ErrRevoked)
	assert.Zero(t, bl.calls, "no permanent revocation")
	assert.Zero(t, ur.calls)
	_, gerr := store.Users().GetByID(ctx, uid)
	assert.NoError(t, gerr, "the account is not deleted")
}

// The deletion's own cut-off advance must not refuse its own token: a normal
// deletion with a token issued before it still completes.
func TestDeleteUser_OwnCutOffAdvanceDoesNotRefuseTheCaller(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), zap.NewNop())
	svc.SetSessionCleaner(&hookCleaner{})
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}))

	require.NoError(t, svc.DeleteUser(tokengate.WithIssuedAt(ctx, time.Now().Add(-time.Minute)), uid, uid.String()))
	_, gerr := store.Users().GetByID(ctx, uid)
	assert.ErrorIs(t, gerr, storage.ErrNotFound)
}
