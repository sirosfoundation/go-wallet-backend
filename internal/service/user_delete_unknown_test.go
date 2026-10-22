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

// A token for an identity this wallet has never held passes the gate as an
// external identity. DeleteUser for it must answer not-found and leave no
// tombstone, or any authenticated caller could lock out an arbitrary subject.
func TestDeleteUser_UnknownSubjectIsNotFoundAndLeavesNoTombstone(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), zap.NewNop())
	ghost := domain.NewUserID()

	require.ErrorIs(t, svc.DeleteUser(ctx, ghost, ghost.String()), ErrUserNotFound)

	_, err := store.Users().GetDeletionTombstone(ctx, ghost.String())
	require.ErrorIs(t, err, storage.ErrNotFound, "no tombstone may be written for an unknown subject")
	gate := tokengate.New(store.Users())
	assert.NoError(t, gate.Check(ctx, ghost.String(), time.Now()), "later tokens for the subject are unaffected")
}

// A deletion that already left its tombstone but whose record is gone is
// retried to completion rather than refused as not-found.
func TestDeleteUser_RetryWithTombstoneAndNoRecordStillCompletes(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), zap.NewNop())
	uid := seedWalletUser(t, store, domain.DefaultTenantID)
	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
	_, err := store.Users().GetDeletionTombstone(ctx, uid.String())
	require.NoError(t, err)

	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
}
