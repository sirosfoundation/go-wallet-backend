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

// Every token-authenticated write that changes wallet state judges the token
// at the mutation: settings (UpdateUser) and stored credentials and
// presentations (which load no user record, so read the cut-off themselves).
func TestOtherWrites_RefuseATokenTheCutoffPredates(t *testing.T) {
	store := memory.NewStore()
	base := context.Background()
	uid := domain.NewUserID()
	require.NoError(t, store.Users().Create(base, &domain.User{UUID: uid, DID: "did:x"}))
	cutoff := time.Now().Truncate(time.Second)
	require.NoError(t, store.Users().InvalidateAuthBefore(base, uid, cutoff))
	before := tokengate.WithSubject(base, uid.String(), cutoff.Add(-time.Minute))
	after := tokengate.WithSubject(base, uid.String(), cutoff.Add(time.Minute))

	t.Run("UpdateUser", func(t *testing.T) {
		svc := NewUserService(store, testConfig(), testLogger())
		u, err := store.Users().GetByID(base, uid)
		require.NoError(t, err)
		assert.ErrorIs(t, svc.UpdateUser(before, u), tokengate.ErrRevoked)
		assert.NoError(t, svc.UpdateUser(after, u))
	})
	t.Run("credential store and update", func(t *testing.T) {
		svc := NewCredentialService(store, testConfig(), testLogger())
		req := &domain.StoreCredentialRequest{HolderDID: "did:x", CredentialIdentifier: "c1", Credential: "jwt", Format: "jwt_vc"}
		_, err := svc.Store(before, domain.DefaultTenantID, req)
		assert.ErrorIs(t, err, tokengate.ErrRevoked)
		_, err = svc.Store(after, domain.DefaultTenantID, req)
		require.NoError(t, err)
		_, err = svc.Update(before, domain.DefaultTenantID, "did:x", &domain.UpdateCredentialRequest{CredentialIdentifier: "c1"})
		assert.ErrorIs(t, err, tokengate.ErrRevoked)
		_, err = svc.Update(after, domain.DefaultTenantID, "did:x", &domain.UpdateCredentialRequest{CredentialIdentifier: "c1"})
		assert.NoError(t, err)
	})
	t.Run("presentation store", func(t *testing.T) {
		svc := NewPresentationService(store, testLogger())
		p := &domain.VerifiablePresentation{HolderDID: "did:x", PresentationIdentifier: "p1", Presentation: "jwt"}
		assert.ErrorIs(t, svc.Store(before, domain.DefaultTenantID, p), tokengate.ErrRevoked)
		assert.NoError(t, svc.Store(after, domain.DefaultTenantID, p))
	})
	t.Run("credential delete", func(t *testing.T) {
		svc := NewCredentialService(store, testConfig(), testLogger())
		assert.ErrorIs(t, svc.Delete(before, domain.DefaultTenantID, "did:x", "c1"), tokengate.ErrRevoked)
		_, err := svc.GetByIdentifier(base, domain.DefaultTenantID, "did:x", "c1")
		require.NoError(t, err, "the refused delete must not land")
		assert.NoError(t, svc.Delete(after, domain.DefaultTenantID, "did:x", "c1"))
	})
	t.Run("presentation delete", func(t *testing.T) {
		svc := NewPresentationService(store, testLogger())
		assert.ErrorIs(t, svc.Delete(before, domain.DefaultTenantID, "did:x", "p1"), tokengate.ErrRevoked)
		_, err := svc.Get(base, domain.DefaultTenantID, "did:x", "p1")
		require.NoError(t, err, "the refused delete must not land")
		assert.NoError(t, svc.Delete(after, domain.DefaultTenantID, "did:x", "p1"))
	})
	t.Run("presentation delete by credential", func(t *testing.T) {
		svc := NewPresentationService(store, testLogger())
		p := &domain.VerifiablePresentation{HolderDID: "did:x", PresentationIdentifier: "p2", Presentation: "jwt"}
		require.NoError(t, svc.Store(after, domain.DefaultTenantID, p))
		assert.ErrorIs(t, svc.DeleteByCredentialID(before, domain.DefaultTenantID, "did:x", "c1"), tokengate.ErrRevoked)
		_, err := svc.Get(base, domain.DefaultTenantID, "did:x", "p2")
		require.NoError(t, err)
		assert.NoError(t, svc.DeleteByCredentialID(after, domain.DefaultTenantID, "did:x", "c1"))
	})
}
