package service

import (
	"context"
	"errors"
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

func (s *flakyInstances) DeleteIfUnchanged(ctx context.Context, id string, _ domain.TenantID, _ domain.InstanceBinding) error {
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

// The token blacklist and engine revoke a user id for good, so they must not
// fire until the sweep is known complete, or the retry ErrDeletionIncomplete
// promises is refused.
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

// The unretryable failure: the cleaner fails after the blacklist revoked the
// user. The record is kept and the error is ErrDeletionOperatorRequired.
func TestDeleteUser_CleanerFailingAfterRevocationKeepsTheRecord(t *testing.T) {
	ctx := context.Background()
	svc, fs, uid, bl, ur := newDeleteFixture(t)
	svc.SetSessionCleaner(&scriptedCleaner{failOn: map[int]bool{2: true}})

	err := svc.DeleteUser(ctx, uid, uid.String())
	require.ErrorIs(t, err, ErrDeletionOperatorRequired)
	assert.NotErrorIs(t, err, ErrDeletionIncomplete, "repeating cannot get past the revoked token gate")
	assert.Equal(t, 1, bl.calls)
	assert.Equal(t, 1, ur.calls)
	_, gerr := fs.Store.Users().GetByID(ctx, uid)
	assert.NoError(t, gerr, "the record is kept")
}

// failingCutoffUsers fails InvalidateAuthBefore while set.
type failingCutoffStore struct {
	storage.Store
	fail bool
}

type failingCutoffUsers struct {
	storage.UserStore
	f *failingCutoffStore
}

func (s *failingCutoffStore) Users() storage.UserStore {
	return &failingCutoffUsers{s.Store.Users(), s}
}

func (u *failingCutoffUsers) InvalidateAuthBefore(ctx context.Context, id domain.UserID, t time.Time) error {
	if u.f.fail {
		return errors.New("user store is down")
	}
	return u.UserStore.InvalidateAuthBefore(ctx, id, t)
}

func (u *failingCutoffUsers) InvalidateAuthBeforeForToken(ctx context.Context, id domain.UserID, t, iat time.Time) error {
	if u.f.fail {
		return errors.New("user store is down")
	}
	return u.UserStore.InvalidateAuthBeforeForToken(ctx, id, t, iat)
}

// With the blacklist disabled the cut-off alone refuses old tokens after an
// incomplete deletion, while a fresh login can repeat it.
func TestDeleteUser_IncompleteAfterRevocationRefusesOldTokensWithoutBlacklist(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), zap.NewNop())
	base := time.Now().UTC().Truncate(time.Second)
	clock := base
	svc.now = func() time.Time { return clock }
	svc.SetSessionCleaner(&scriptedCleaner{failOn: map[int]bool{2: true}})
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}))
	gate := tokengate.New(store.Users())

	oldIat := base.Add(-time.Minute)
	require.NoError(t, gate.Check(ctx, uid.String(), oldIat), "token is valid before the deletion")

	require.ErrorIs(t, svc.DeleteUser(tokengate.WithIssuedAt(ctx, oldIat), uid, uid.String()), ErrDeletionIncomplete)
	_, gerr := store.Users().GetByID(ctx, uid)
	require.NoError(t, gerr, "the record is kept")
	assert.ErrorIs(t, gate.Check(ctx, uid.String(), oldIat), tokengate.ErrRevoked, "old token refused with no blacklist")

	// A fresh login after the cut-off passes the gate and can retry.
	clock = base.Add(5 * time.Second)
	freshIat := clock
	require.NoError(t, gate.Check(ctx, uid.String(), freshIat))
	svc.SetSessionCleaner(&scriptedCleaner{})
	require.NoError(t, svc.DeleteUser(tokengate.WithIssuedAt(ctx, freshIat), uid, uid.String()))
	_, gerr = store.Users().GetByID(ctx, uid)
	assert.ErrorIs(t, gerr, storage.ErrNotFound)
	assert.ErrorIs(t, gate.Check(ctx, uid.String(), freshIat), tokengate.ErrAccountDeleted, "the tombstone takes over once the record is gone")
}

// A cut-off that cannot be stored stops the deletion before anything
// irreversible, leaving the caller's token usable for the retry.
func TestDeleteUser_CutoffAdvanceFailureIsRetryableAndIrreversibleFree(t *testing.T) {
	ctx := context.Background()
	fs := &failingCutoffStore{Store: memory.NewStore(), fail: true}
	svc := NewUserService(fs, testConfig(), zap.NewNop())
	bl, ur := &countingRevoker{}, &countingUserRevoker{}
	svc.SetTokenBlacklist(bl)
	svc.AddUserRevoker(ur)
	cleaner := &scriptedCleaner{}
	svc.SetSessionCleaner(cleaner)
	uid := domain.NewUserID()
	require.NoError(t, fs.Store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}))

	require.ErrorIs(t, svc.DeleteUser(ctx, uid, uid.String()), ErrDeletionIncomplete)
	assert.Zero(t, bl.calls)
	assert.Zero(t, ur.calls)
	assert.Equal(t, 1, cleaner.calls, "only the pre-revocation cleaner run happened")
	cutoff, err := fs.Store.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, err)
	assert.True(t, cutoff.IsZero(), "no cut-off, so the caller's token still works")

	fs.fail = false
	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
}

// A blacklist that did not take effect (RevokeUser failed) leaves a fresh
// login able to pass the gate, so the second-cleaner failure stays retryable.
type failingRevoker struct{}

func (failingRevoker) RevokeUser(context.Context, string) error { return errors.New("redis down") }

func TestDeleteUser_CleanerFailingAfterFailedBlacklistRevocationStaysRetryable(t *testing.T) {
	ctx := context.Background()
	svc, fs, uid, _, _ := newDeleteFixture(t)
	svc.SetTokenBlacklist(failingRevoker{})
	svc.SetSessionCleaner(&scriptedCleaner{failOn: map[int]bool{2: true}})

	err := svc.DeleteUser(ctx, uid, uid.String())
	require.ErrorIs(t, err, ErrDeletionIncomplete)
	assert.NotErrorIs(t, err, ErrDeletionOperatorRequired)
	_, gerr := fs.Store.Users().GetByID(ctx, uid)
	assert.NoError(t, gerr)
}

// countingHolderStore fails GetAllByHolder from the n-th call on, so only the
// final sweep (after the permanent revocation) fails.
type countingHolderStore struct {
	storage.Store
	calls, failFrom int
}

type countingHolderCreds struct {
	storage.CredentialStore
	s *countingHolderStore
}

func (s *countingHolderStore) Credentials() storage.CredentialStore {
	return &countingHolderCreds{s.Store.Credentials(), s}
}

func (c *countingHolderCreds) GetAllByHolder(ctx context.Context, tid domain.TenantID, did string) ([]*domain.VerifiableCredential, error) {
	c.s.calls++
	if c.s.calls >= c.s.failFrom {
		return nil, errors.New("db down")
	}
	return c.CredentialStore.GetAllByHolder(ctx, tid, did)
}

func TestDeleteUser_FinalSweepFailureAfterBlacklistIsOperatorOnly(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		blacklist TokenRevoker
		want      error
		notWant   error
	}{
		{"blacklist in force", &countingRevoker{}, ErrDeletionOperatorRequired, ErrDeletionIncomplete},
		{"no blacklist: a fresh login can retry", nil, ErrDeletionIncomplete, ErrDeletionOperatorRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := &countingHolderStore{Store: memory.NewStore(), failFrom: 2}
			svc := NewUserService(fs, testConfig(), zap.NewNop())
			if tc.blacklist != nil {
				svc.SetTokenBlacklist(tc.blacklist)
			}
			uid := domain.NewUserID()
			require.NoError(t, fs.Store.Users().Create(ctx, &domain.User{UUID: uid, DID: "did:key:" + uid.String()}))

			err := svc.DeleteUser(ctx, uid, uid.String())
			require.ErrorIs(t, err, tc.want)
			assert.NotErrorIs(t, err, tc.notWant)
			_, gerr := fs.Store.Users().GetByID(ctx, uid)
			assert.NoError(t, gerr, "the record is kept")
		})
	}
}
