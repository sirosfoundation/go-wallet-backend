package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func TestUserService_UpdatePrivateData_NotFound(t *testing.T) {
	svc := NewUserService(newModifyTestStore(), testConfig(), testLogger())
	_, err := svc.UpdatePrivateData(context.Background(), domain.NewUserID(), []byte("x"), "")
	assert.ErrorIs(t, err, errNotFoundForTest)
}

func TestUserService_UpdateSettings(t *testing.T) {
	ctx := context.Background()
	store := newModifyTestStore()
	svc := NewUserService(store, testConfig(), testLogger())

	userID := domain.NewUserID()
	require.NoError(t, store.Users().Create(ctx, &domain.User{
		UUID:                     userID,
		PrivateData:              []byte("keep-me"),
		OpenIDRefreshTokenMaxAge: 10,
	}))

	t.Run("sets the value and leaves private data alone", func(t *testing.T) {
		v := int64(3600)
		got, err := svc.UpdateSettings(ctx, userID, &v)
		require.NoError(t, err)
		assert.Equal(t, int64(3600), got.OpenIDRefreshTokenMaxAge)
		assert.Equal(t, []byte("keep-me"), got.PrivateData)

		stored, err := store.Users().GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, int64(3600), stored.OpenIDRefreshTokenMaxAge)
		assert.Equal(t, []byte("keep-me"), stored.PrivateData)
	})

	t.Run("nil leaves the value unchanged", func(t *testing.T) {
		got, err := svc.UpdateSettings(ctx, userID, nil)
		require.NoError(t, err)
		assert.Equal(t, int64(3600), got.OpenIDRefreshTokenMaxAge)
	})

	t.Run("unknown user is not found", func(t *testing.T) {
		v := int64(1)
		_, err := svc.UpdateSettings(ctx, domain.NewUserID(), &v)
		assert.ErrorIs(t, err, errNotFoundForTest)
	})
}

func TestFinishAddCredential_PrivateDataAtomicWithAppend(t *testing.T) {
	setup := newTestVirtualWebAuthnSetup(t)
	ctx := setup.ctx

	userID := domain.NewUserID()
	existing := domain.WebauthnCredential{ID: "existing-cred", CredentialID: []byte("existing-cred")}
	require.NoError(t, setup.store.Users().Create(ctx, &domain.User{
		UUID:                userID,
		CreatedAt:           time.Now(),
		WebauthnCredentials: []domain.WebauthnCredential{existing},
		PrivateData:         []byte("old"),
	}))

	finish := func(t *testing.T, privateData []byte, ifMatch string) (*FinishAddCredentialResponse, error) {
		t.Helper()
		begin, err := setup.service.BeginAddCredential(ctx, userID)
		require.NoError(t, err)
		raw, err := json.Marshal(begin.CreateOptions)
		require.NoError(t, err)
		opts, err := virtualwebauthn.ParseAttestationOptions(string(convertOptionsToPlainBase64(raw)))
		require.NoError(t, err)
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		resp := virtualwebauthn.CreateAttestationResponse(setup.rp, setup.authenticator, cred, *opts)
		return setup.service.FinishAddCredential(ctx, userID, &FinishAddCredentialRequest{
			ChallengeID: begin.ChallengeID,
			Credential:  json.RawMessage(resp),
			PrivateData: privateData,
		}, ifMatch)
	}

	t.Run("stale If-Match with private data is a conflict and appends nothing", func(t *testing.T) {
		_, err := finish(t, []byte("new"), `"stale"`)
		require.ErrorIs(t, err, ErrPrivateDataConflict)

		u, err := setup.store.Users().GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, u.WebauthnCredentials, 1)
		assert.Equal(t, []byte("old"), u.PrivateData)
	})

	t.Run("without private data the credential is appended and data kept", func(t *testing.T) {
		resp, err := finish(t, nil, `"ignored-without-private-data"`)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.CredentialID)

		u, err := setup.store.Users().GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, u.WebauthnCredentials, 2)
		assert.Equal(t, []byte("old"), u.PrivateData)
		assert.Equal(t, u.EffectivePrivateDataETag(), resp.PrivateDataETag)
	})

	t.Run("matching If-Match replaces private data with the credential", func(t *testing.T) {
		u, err := setup.store.Users().GetByID(ctx, userID)
		require.NoError(t, err)

		resp, err := finish(t, []byte("new"), u.EffectivePrivateDataETag())
		require.NoError(t, err)

		u, err = setup.store.Users().GetByID(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, u.WebauthnCredentials, 3)
		assert.Equal(t, []byte("new"), u.PrivateData)
		assert.Equal(t, domain.ComputePrivateDataETag([]byte("new")), resp.PrivateDataETag)
	})

}

// newModifyTestStore and errNotFoundForTest keep these tests independent of
// the helpers in other test files.
func newModifyTestStore() *memory.Store { return memory.NewStore() }

var errNotFoundForTest = storage.ErrNotFound
