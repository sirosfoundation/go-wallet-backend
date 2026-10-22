package mongodb

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

func newMongoCred(id string) *domain.VerifiableCredential {
	return &domain.VerifiableCredential{TenantID: domain.DefaultTenantID, HolderDID: "did:h", CredentialIdentifier: id, Credential: "x", Format: domain.FormatJWTVC}
}

func TestCredentialStore_ConditionalRollback(t *testing.T) {
	ctx := context.Background()
	store := skipIfNoMongo(t)
	s := store.Credentials()

	t.Run("DeleteIfUnchanged deletes the record it was issued for", func(t *testing.T) {
		c := newMongoCred("a")
		require.NoError(t, s.Create(ctx, c))
		require.NotEmpty(t, c.WriteToken)
		require.NoError(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, c.WriteToken))
		_, err := s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "a")
		assert.ErrorIs(t, err, storage.ErrNotFound)
	})
	t.Run("a recreated record under the same identifier is not deleted", func(t *testing.T) {
		stale := newMongoCred("b")
		require.NoError(t, s.Create(ctx, stale))
		staleID, staleToken := stale.ID, stale.WriteToken
		require.NoError(t, s.Delete(ctx, domain.DefaultTenantID, "did:h", "b"))
		fresh := newMongoCred("b")
		require.NoError(t, s.Create(ctx, fresh))

		assert.ErrorIs(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, staleID, staleToken), storage.ErrNotFound)
		_, err := s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "b")
		assert.NoError(t, err)
	})
	t.Run("a record written since is not deleted, wrong tenant neither", func(t *testing.T) {
		c := newMongoCred("c")
		require.NoError(t, s.Create(ctx, c))
		oldToken := c.WriteToken
		require.NoError(t, s.Update(ctx, c))
		assert.NotEqual(t, oldToken, c.WriteToken)
		assert.ErrorIs(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, oldToken), storage.ErrNotFound)
		assert.ErrorIs(t, s.DeleteIfUnchanged(ctx, "other", c.ID, c.WriteToken), storage.ErrNotFound)
		assert.ErrorIs(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, ""), storage.ErrNotFound)
	})
	t.Run("RestoreIfUnchanged restores only the write it undoes", func(t *testing.T) {
		c := newMongoCred("d")
		require.NoError(t, s.Create(ctx, c))
		previous := *c
		c.SigCount = 5
		require.NoError(t, s.Update(ctx, c))
		written := *c

		// A later write makes the restore a no-op.
		later := *c
		later.SigCount = 9
		require.NoError(t, s.Update(ctx, &later))
		assert.ErrorIs(t, s.RestoreIfUnchanged(ctx, &written, &previous), storage.ErrNotFound)
		got, err := s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "d")
		require.NoError(t, err)
		assert.Equal(t, 9, got.SigCount)

		// Without a later write it restores.
		require.NoError(t, s.RestoreIfUnchanged(ctx, &later, &previous))
		got, err = s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "d")
		require.NoError(t, err)
		assert.Equal(t, 0, got.SigCount)
	})
}

func TestPresentationStore_DeleteByID(t *testing.T) {
	ctx := context.Background()
	store := skipIfNoMongo(t)
	s := store.Presentations()
	p := &domain.VerifiablePresentation{TenantID: domain.DefaultTenantID, HolderDID: "did:h", PresentationIdentifier: "p", Presentation: "x"}
	require.NoError(t, s.Create(ctx, p))
	staleID := p.ID
	require.NoError(t, s.Delete(ctx, domain.DefaultTenantID, "did:h", "p"))
	fresh := &domain.VerifiablePresentation{TenantID: domain.DefaultTenantID, HolderDID: "did:h", PresentationIdentifier: "p", Presentation: "y"}
	require.NoError(t, s.Create(ctx, fresh))

	assert.ErrorIs(t, s.DeleteByID(ctx, domain.DefaultTenantID, staleID), storage.ErrNotFound)
	_, err := s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "p")
	require.NoError(t, err, "the replacement survives")
	assert.ErrorIs(t, s.DeleteByID(ctx, "other", fresh.ID), storage.ErrNotFound)
	assert.NoError(t, s.DeleteByID(ctx, domain.DefaultTenantID, fresh.ID))
}
