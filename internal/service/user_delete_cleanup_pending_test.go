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
	// onlyTenant, when set, limits the failure to that tenant's holder data.
	onlyTenant domain.TenantID
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
	if c.s.removed.Load() && (c.s.onlyTenant == "" || c.s.onlyTenant == tid) {
		return nil, errors.New("db down")
	}
	return c.CredentialStore.GetAllByHolder(ctx, tid, did)
}

// The sweep after the user's removal cannot hold the record back, so its
// failure must not surface as ErrDeletionIncomplete ("account still exists").
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

// A failed sweep after the record's removal leaves the tombstone as the only
// memory of the account: the memberships, instances and the user's canonical
// holder DID are gone with the record. The operator's repeat can name only the
// bare uuid, so it must sweep the tenants and the DID the tombstone remembers,
// or it reports success while data remains.
func TestDeleteUser_RetryAfterPostRemovalSweepFailureSweepsTombstoneTenantsAndDID(t *testing.T) {
	ctx := context.Background()
	inner := memory.NewStore()
	fs := &failAfterRemovalStore{Store: inner, onlyTenant: "acme"}
	svc := NewUserService(fs, testConfig(), zap.NewNop())
	uid := domain.NewUserID()
	did := "did:example:canonical-" + uid.String() // differs from the bare uuid
	require.NoError(t, inner.Users().Create(ctx, &domain.User{UUID: uid, DID: did}))
	require.NoError(t, inner.UserTenants().AddMembership(ctx, &domain.UserTenantMembership{UserID: uid, TenantID: "acme", Role: "user"}))

	require.ErrorIs(t, svc.DeleteUser(ctx, uid, uid.String()), ErrDeletionCleanupPending)
	ts, err := inner.Users().GetDeletionTombstone(ctx, uid.String())
	require.NoError(t, err)
	assert.Equal(t, did, ts.HolderDID, "the DID is kept while cleanup is pending")

	// Data that persisted under the canonical DID in the tenant during the deletion.
	require.NoError(t, inner.Credentials().Create(ctx, &domain.VerifiableCredential{
		TenantID: "acme", HolderDID: did, CredentialIdentifier: "late", Credential: "jwt", Format: domain.CredentialFormat("jwt_vc"),
	}))
	require.NoError(t, inner.Presentations().Create(ctx, &domain.VerifiablePresentation{
		TenantID: "acme", HolderDID: did, PresentationIdentifier: "late-p", Presentation: "jwt",
	}))
	fs.removed.Store(false) // the database recovered

	// The caller names only the uuid, as the handler does.
	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))
	creds, cerr := inner.Credentials().GetAllByHolder(ctx, "acme", did)
	if cerr != nil {
		require.ErrorIs(t, cerr, storage.ErrNotFound)
	}
	assert.Empty(t, creds, "the retry must sweep the DID-keyed credentials in the tombstone's tenant")
	pres, perr := inner.Presentations().GetAllByHolder(ctx, "acme", did)
	if perr != nil {
		require.ErrorIs(t, perr, storage.ErrNotFound)
	}
	assert.Empty(t, pres)

	ts, err = inner.Users().GetDeletionTombstone(ctx, uid.String())
	require.NoError(t, err, "the tombstone itself stays")
	assert.Empty(t, ts.HolderDID, "the DID is cleared once the final sweep completed")
}
