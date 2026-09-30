package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// flakyStore fails wallet-instance deletes while failDeletes is set.
type flakyStore struct {
	storage.Store
	failDeletes bool
}

type flakyInstances struct {
	storage.WalletInstanceStore
	f *flakyStore
}

func (s *flakyStore) WalletInstances() storage.WalletInstanceStore {
	return &flakyInstances{s.Store.WalletInstances(), s}
}

func (s *flakyInstances) Delete(ctx context.Context, id string) error {
	if s.f.failDeletes {
		return errors.New("instance store is down")
	}
	return s.WalletInstanceStore.Delete(ctx, id)
}

func (s *flakyInstances) DeleteForUser(ctx context.Context, id string, _ domain.TenantID, _ domain.UserID) error {
	return s.Delete(ctx, id)
}

type countingRevoker struct{ calls int }

func (r *countingRevoker) RevokeUser(context.Context, string) error { r.calls++; return nil }

type countingUserRevoker struct{ calls int }

func (r *countingUserRevoker) RevokeUser(string) { r.calls++ }

// scriptedCleaner fails on the listed (1-based) calls.
type scriptedCleaner struct {
	calls  int
	failOn map[int]bool
}

func (c *scriptedCleaner) DeleteByUser(context.Context, string) error {
	c.calls++
	if c.failOn[c.calls] {
		return errors.New("session store is down")
	}
	return nil
}

func newDeleteFixture(t *testing.T) (*UserService, *flakyStore, domain.UserID, *countingRevoker, *countingUserRevoker) {
	t.Helper()
	ctx := context.Background()
	fs := &flakyStore{Store: memory.NewStore()}
	svc := NewUserService(fs, testConfig(), zap.NewNop())
	bl, ur := &countingRevoker{}, &countingUserRevoker{}
	svc.SetTokenBlacklist(bl)
	svc.AddUserRevoker(ur)
	uid := domain.NewUserID()
	require.NoError(t, fs.Store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}))
	require.NoError(t, fs.Store.WalletInstances().Upsert(ctx, &domain.WalletInstance{
		ID: "inst-1", TenantID: domain.DefaultTenantID, UserID: &uid, Status: domain.InstanceStatusActive,
	}))
	return svc, fs, uid, bl, ur
}

// ErrDeletionIncomplete promises that the caller can authenticate and repeat
// the request. The token blacklist and the engine revoke a user id for good, so
// they must not fire until the sweep is known to be complete - otherwise the
// retry the error promises is refused at the door.
func TestDeleteUser_IncompleteLeavesTheCallerAbleToRetry(t *testing.T) {
	ctx := context.Background()
	svc, fs, uid, bl, ur := newDeleteFixture(t)
	cleaner := &scriptedCleaner{}
	svc.SetSessionCleaner(cleaner)

	fs.failDeletes = true
	err := svc.DeleteUser(ctx, uid, uid.String())
	require.ErrorIs(t, err, ErrDeletionIncomplete)
	assert.Zero(t, bl.calls, "no permanent token revocation while the deletion is incomplete")
	assert.Zero(t, ur.calls, "no permanent engine revocation while the deletion is incomplete")
	assert.Zero(t, cleaner.calls, "sessions stay while the deletion is incomplete")
	_, gerr := fs.Store.Users().GetByID(ctx, uid)
	assert.NoError(t, gerr, "the user record is kept")

	// The retry, once the fault clears, finishes the job.
	fs.failDeletes = false
	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
	assert.Equal(t, 1, bl.calls)
	assert.Equal(t, 1, ur.calls)
	assert.Equal(t, 2, cleaner.calls, "sessions are dropped before and after the permanent revocations")
	_, gerr = fs.Store.Users().GetByID(ctx, uid)
	assert.ErrorIs(t, gerr, storage.ErrNotFound)
	_, ierr := fs.Store.WalletInstances().GetByID(ctx, "inst-1")
	assert.ErrorIs(t, ierr, storage.ErrNotFound)
}

func TestDeleteUser_CleanerFailingBeforeRevocationIsRetryable(t *testing.T) {
	ctx := context.Background()
	svc, fs, uid, bl, ur := newDeleteFixture(t)
	cleaner := &scriptedCleaner{failOn: map[int]bool{1: true}}
	svc.SetSessionCleaner(cleaner)

	require.ErrorIs(t, svc.DeleteUser(ctx, uid, uid.String()), ErrDeletionIncomplete)
	assert.Zero(t, bl.calls)
	assert.Zero(t, ur.calls)

	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()), "the same request succeeds once the cleaner recovers")
	_, gerr := fs.Store.Users().GetByID(ctx, uid)
	assert.ErrorIs(t, gerr, storage.ErrNotFound)
}

// The one failure that cannot be retried by the user: the cleaner recovers
// for the first pass and fails after the permanent revocations. The record is
// kept and the error is reported, not swallowed.
func TestDeleteUser_CleanerFailingAfterRevocationKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	svc, fs, uid, bl, ur := newDeleteFixture(t)
	svc.SetSessionCleaner(&scriptedCleaner{failOn: map[int]bool{2: true}})

	require.ErrorIs(t, svc.DeleteUser(ctx, uid, uid.String()), ErrDeletionIncomplete)
	assert.Equal(t, 1, bl.calls)
	assert.Equal(t, 1, ur.calls)
	_, gerr := fs.Store.Users().GetByID(ctx, uid)
	assert.NoError(t, gerr, "the record is kept")
}
