package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
)

// A request admitted by the token middleware just before a revocation can
// reach a write after the revocation has erased the wallet. The record it then
// loads is fresh, so the store's fence accepts it; the write itself has to
// judge the request's token against the cut-off on that record.
func TestUserWrites_RefuseATokenTheLoadedRecordCutsOff(t *testing.T) {
	store := memory.NewStore()
	svc := NewUserService(store, testConfig(), testLogger())
	uid := domain.NewUserID()
	cutoff := time.Now().Truncate(time.Second)
	base := context.Background()
	require.NoError(t, store.Users().Create(base, &domain.User{
		UUID:                uid,
		PrivateData:         []byte("vault"),
		WebauthnCredentials: []domain.WebauthnCredential{{ID: "a"}, {ID: "b"}},
	}))
	require.NoError(t, store.Users().InvalidateAuthBefore(base, uid, cutoff))

	before := tokengate.WithIssuedAt(base, cutoff.Add(-time.Minute))
	after := tokengate.WithIssuedAt(base, cutoff.Add(time.Minute))

	t.Run("UpdatePrivateData", func(t *testing.T) {
		_, err := svc.UpdatePrivateData(before, uid, []byte("resurrected"), "")
		assert.ErrorIs(t, err, tokengate.ErrRevoked)
		got, err := store.Users().GetByID(base, uid)
		require.NoError(t, err)
		assert.Equal(t, []byte("vault"), got.PrivateData, "the refused write must not land")

		_, err = svc.UpdatePrivateData(after, uid, []byte("fresh"), "")
		assert.NoError(t, err, "a token issued after the cut-off writes normally")
		_, err = svc.UpdatePrivateData(base, uid, []byte("internal"), "")
		assert.NoError(t, err, "a context without a token iat is not judged")
	})
	t.Run("DeleteWebAuthnCredential", func(t *testing.T) {
		_, err := svc.DeleteWebAuthnCredential(before, uid, "a", nil, "")
		assert.ErrorIs(t, err, tokengate.ErrRevoked)
	})
	t.Run("RenameWebAuthnCredential", func(t *testing.T) {
		err := svc.RenameWebAuthnCredential(before, uid, "a", "renamed")
		assert.ErrorIs(t, err, tokengate.ErrRevoked)
		assert.NoError(t, svc.RenameWebAuthnCredential(after, uid, "a", "renamed"))
	})
	t.Run("FinishAddCredential", func(t *testing.T) {
		w, _ := setupWebAuthnService(t)
		w.store = store
		_, err := w.FinishAddCredential(before, uid, &FinishAddCredentialRequest{}, "")
		assert.True(t, errors.Is(err, tokengate.ErrRevoked), "got %v", err)
	})
}
