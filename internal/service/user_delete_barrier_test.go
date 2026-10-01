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
)

// fenceHookStore runs afterFence once the user's token cut-off has been advanced,
// which is the instant a request admitted before the cut-off can still land a
// write that the first holder-data sweep has already missed.
type fenceHookStore struct {
	storage.Store
	afterFence func(ctx context.Context)
}

type fenceHookUsers struct {
	storage.UserStore
	h *fenceHookStore
}

func (s *fenceHookStore) Users() storage.UserStore { return &fenceHookUsers{s.Store.Users(), s} }

func (u *fenceHookUsers) InvalidateAuthBefore(ctx context.Context, id domain.UserID, t time.Time) error {
	if err := u.UserStore.InvalidateAuthBefore(ctx, id, t); err != nil {
		return err
	}
	if u.h.afterFence != nil {
		u.h.afterFence(ctx)
	}
	return nil
}

// A write admitted before the cut-off lands after the first sweep and before
// the cut-off is advanced. Account deletion must still leave no holder data.
func TestDeleteUser_RemovesHolderDataWrittenByAnAlreadyAdmittedRequest(t *testing.T) {
	ctx := context.Background()
	hs := &fenceHookStore{Store: memory.NewStore()}
	svc := NewUserService(hs, testConfig(), zap.NewNop())
	uid := domain.NewUserID()
	did := "did:key:" + uid.String()
	require.NoError(t, hs.Store.Users().Create(ctx, &domain.User{UUID: uid, DID: did}))
	require.NoError(t, hs.Store.Credentials().Create(ctx, &domain.VerifiableCredential{
		TenantID: domain.DefaultTenantID, HolderDID: did, CredentialIdentifier: "early", Credential: "x", Format: "vc+sd-jwt",
	}))

	hs.afterFence = func(ctx context.Context) {
		assert.NoError(t, hs.Store.Credentials().Create(ctx, &domain.VerifiableCredential{
			TenantID: domain.DefaultTenantID, HolderDID: did, CredentialIdentifier: "late", Credential: "y", Format: "vc+sd-jwt",
		}))
		assert.NoError(t, hs.Store.Presentations().Create(ctx, &domain.VerifiablePresentation{
			TenantID: domain.DefaultTenantID, HolderDID: did, PresentationIdentifier: "late-p", Presentation: "z",
		}))
	}

	require.NoError(t, svc.DeleteUser(ctx, uid, uid.String()))

	creds, err := hs.Store.Credentials().GetAllByHolder(ctx, domain.DefaultTenantID, did)
	if err != nil {
		require.ErrorIs(t, err, storage.ErrNotFound)
	}
	assert.Empty(t, creds, "a credential written after the first sweep must not survive")
	pres, err := hs.Store.Presentations().GetAllByHolder(ctx, domain.DefaultTenantID, did)
	if err != nil {
		require.ErrorIs(t, err, storage.ErrNotFound)
	}
	assert.Empty(t, pres, "a presentation written after the first sweep must not survive")
	_, err = hs.Store.Users().GetByID(ctx, uid)
	assert.True(t, errors.Is(err, storage.ErrNotFound))
}
