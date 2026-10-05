package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// failAfterRemovalStore fails holder-data listing once the user record is
// removed, so only the sweep that follows the removal fails.
type failAfterRemovalStore struct {
	storage.Store
	removed atomic.Bool
}

type removalFlagUsers struct {
	storage.UserStore
	s *failAfterRemovalStore
}

func (s *failAfterRemovalStore) Users() storage.UserStore {
	return &removalFlagUsers{s.Store.Users(), s}
}

func (u *removalFlagUsers) Delete(ctx context.Context, id domain.UserID) error {
	err := u.UserStore.Delete(ctx, id)
	if err == nil {
		u.s.removed.Store(true)
	}
	return err
}

type failAfterRemovalCreds struct {
	storage.CredentialStore
	s *failAfterRemovalStore
}

func (s *failAfterRemovalStore) Credentials() storage.CredentialStore {
	return &failAfterRemovalCreds{s.Store.Credentials(), s}
}

func (c *failAfterRemovalCreds) GetAllByHolder(ctx context.Context, tid domain.TenantID, did string) ([]*domain.VerifiableCredential, error) {
	if c.s.removed.Load() {
		return nil, errors.New("db down")
	}
	return c.CredentialStore.GetAllByHolder(ctx, tid, did)
}

// The sweep after the user's removal cannot hold the record back, so when it
// fails the account is already gone. That must not surface as
// ErrDeletionIncomplete, whose contract is "the account still exists, repeat
// the request".
func TestDeleteUser_PostRemovalSweepFailureIsDistinctFromRetryable(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewStore()
	fs := &failAfterRemovalStore{Store: inner}
	svc := NewUserService(fs, testConfig(), zap.NewNop())
	uid := domain.NewUserID()
	did := "did:key:" + uid.String()
	require.NoError(t, inner.Users().Create(ctx, &domain.User{UUID: uid, DID: did}))

	err := svc.DeleteUser(ctx, uid, did)
	require.ErrorIs(t, err, ErrDeletionCleanupPending)
	assert.NotErrorIs(t, err, ErrDeletionIncomplete, "the account is gone; repeating cannot work")

	_, gerr := inner.Users().GetByID(ctx, uid)
	assert.ErrorIs(t, gerr, storage.ErrNotFound, "the user record is removed")
	_, terr := inner.Users().GetDeletionTombstone(ctx, uid.String())
	assert.NoError(t, terr, "the tombstone stands, so every further write is refused")
}
