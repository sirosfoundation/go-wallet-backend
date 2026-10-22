package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// erasingOnLoadUsers plays the lifecycle cascade landing right after
// UpdatePrivateData loaded the record: the vault is erased and the AuthFence
// advanced before the write.
type erasingOnLoadUsers struct {
	storage.UserStore
	store storage.Store
	fired bool
}

func (u *erasingOnLoadUsers) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	user, err := u.UserStore.GetByID(ctx, id)
	if err == nil && !u.fired {
		u.fired = true
		_ = u.UserStore.EraseWalletData(ctx, id, user.AuthInvalidBefore.Add(1))
	}
	return user, err
}

type erasingOnLoadStore struct {
	storage.Store
	users *erasingOnLoadUsers
}

func (s *erasingOnLoadStore) Users() storage.UserStore { return s.users }

// A private-data write admitted before the cascade must not land after it: the
// full-record Update is fenced on the AuthFence the record was loaded with.
func TestUserService_UpdatePrivateData_AuthFenceRaceIsRefused(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewStore()
	uid := domain.NewUserID()
	require.NoError(t, inner.Users().Create(ctx, &domain.User{UUID: uid, PrivateData: []byte("vault")}))
	st := &erasingOnLoadStore{Store: inner, users: &erasingOnLoadUsers{UserStore: inner.Users(), store: inner}}
	svc := NewUserService(st, testConfig(), zap.NewNop())

	_, err := svc.UpdatePrivateData(ctx, uid, []byte("late write"), "")
	require.ErrorIs(t, err, storage.ErrStaleWrite)
	got, gerr := inner.Users().GetByID(ctx, uid)
	require.NoError(t, gerr)
	assert.Nil(t, got.PrivateData, "the erased vault must not be restored by the stale write")
}
