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

// erasingOnLoadUsers plays the lifecycle cascade landing after the request was
// admitted but before its write: the vault is erased and the cut-off advanced
// just ahead of the Modify. Modify reads the post-cascade record, so the
// cut-off check inside its callback sees what the write would replace.
type erasingOnLoadUsers struct {
	storage.UserStore
	store storage.Store
	fired bool
}

func (u *erasingOnLoadUsers) Modify(ctx context.Context, id domain.UserID, fn storage.UserModifier) (*domain.User, error) {
	if !u.fired {
		u.fired = true
		_ = u.UserStore.EraseWalletData(ctx, id, time.Now())
	}
	return u.UserStore.Modify(ctx, id, fn)
}

type erasingOnLoadStore struct {
	storage.Store
	users *erasingOnLoadUsers
}

func (s *erasingOnLoadStore) Users() storage.UserStore { return s.users }

// A private-data write admitted before the cascade must not land after it: the
// token's iat predates the cut-off the cascade advanced, which the Modify
// callback judges against the record it is about to replace.
func TestUserService_UpdatePrivateData_AuthFenceRaceIsRefused(t *testing.T) {
	base := context.Background()
	inner := memory.NewStore()
	uid := domain.NewUserID()
	require.NoError(t, inner.Users().Create(base, &domain.User{UUID: uid, PrivateData: []byte("vault")}))
	st := &erasingOnLoadStore{Store: inner, users: &erasingOnLoadUsers{UserStore: inner.Users(), store: inner}}
	svc := NewUserService(st, testConfig(), zap.NewNop())

	// A token issued a minute before the cascade's cut-off.
	ctx := tokengate.WithSubject(base, uid.String(), time.Now().Add(-time.Minute))

	_, err := svc.UpdatePrivateData(ctx, uid, []byte("late write"), "")
	require.ErrorIs(t, err, tokengate.ErrRevoked)
	got, gerr := inner.Users().GetByID(base, uid)
	require.NoError(t, gerr)
	assert.Nil(t, got.PrivateData, "the erased vault must not be restored by the stale write")
}
