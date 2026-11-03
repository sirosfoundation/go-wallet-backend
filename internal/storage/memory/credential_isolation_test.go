package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// The store must not share pointers with callers: a caller's captured write
// token has to stay its own, or its fence rollback could delete or overwrite a
// newer write (go-wallet-backend#319 review).
func TestCredentialStore_DoesNotAliasCallerRecords(t *testing.T) {
	ctx := context.Background()
	s := NewStore().Credentials()

	c := newCred("alias")
	require.NoError(t, s.Create(ctx, c))
	createdToken := c.WriteToken

	// A later authorised update replaces the record's token.
	got, err := s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "alias")
	require.NoError(t, err)
	got.SigCount = 7
	require.NoError(t, s.Update(ctx, got))

	assert.Equal(t, createdToken, c.WriteToken, "caller's record must not see a later write's token")
	assert.Equal(t, 0, c.SigCount)

	// The Create's rollback must now be a no-op: the newer write survives.
	assert.Error(t, s.DeleteIfUnchanged(ctx, domain.DefaultTenantID, c.ID, createdToken))
	cur, err := s.GetByIdentifier(ctx, domain.DefaultTenantID, "did:h", "alias")
	require.NoError(t, err)
	assert.Equal(t, 7, cur.SigCount)

	// Mutating a returned record must not change the stored one.
	cur.SigCount = 99
	again, err := s.GetByID(ctx, domain.DefaultTenantID, c.ID)
	require.NoError(t, err)
	assert.Equal(t, 7, again.SigCount)
	all, err := s.GetAllByHolder(ctx, domain.DefaultTenantID, "did:h")
	require.NoError(t, err)
	all[0].SigCount = 55
	again, _ = s.GetByID(ctx, domain.DefaultTenantID, c.ID)
	assert.Equal(t, 7, again.SigCount)
}
