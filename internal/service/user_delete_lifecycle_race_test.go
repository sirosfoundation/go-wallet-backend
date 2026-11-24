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

// A lifecycle revocation landing after the deletion was admitted must not turn
// it into a 401 over a half-erased account: the cut-off was advanced up front,
// so the deletion runs to completion and the later cut-off stands.
func TestDeleteUser_RevocationAfterAdmissionDoesNotStrandAHalfErasedAccount(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), zap.NewNop())
	uid := seedWalletUser(t, store, domain.DefaultTenantID, "acme")

	later := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	svc.SetSessionCleaner(&hookCleaner{onCall: func() {
		require.NoError(t, store.Users().InvalidateAuthBefore(ctx, uid, later))
	}})

	err := svc.DeleteUser(tokengate.WithIssuedAt(ctx, time.Now().Add(-time.Minute)), uid, uid.String())
	require.NoError(t, err)
	_, gerr := store.Users().GetByID(ctx, uid)
	assert.ErrorIs(t, gerr, storage.ErrNotFound, "the admitted deletion completes")
	for _, tid := range []domain.TenantID{domain.DefaultTenantID, "acme"} {
		creds, pres := countHolderData(t, store, tid, uid)
		assert.Zero(t, creds+pres, "holder data in %s erased", tid)
	}
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
