package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

func TestWalletInstanceStore_ListUsersWithRevokedInstances(t *testing.T) {
	ctx := context.Background()
	wis := NewStore().WalletInstances()
	seed := func(id, tenant, owner string, revoke bool) {
		inst := &domain.WalletInstance{ID: id, TenantID: domain.TenantID(tenant), Status: domain.InstanceStatusActive}
		if owner != "" {
			u := domain.UserIDFromString(owner)
			inst.UserID = &u
		}
		require.NoError(t, wis.Upsert(ctx, inst))
		if revoke {
			require.NoError(t, wis.UpdateStatus(ctx, id, domain.TenantID(tenant), domain.InstanceStatusRevoked, "t"))
		}
	}
	seed("a1", "t1", "u1", true)
	seed("a2", "t2", "u1", true) // same owner twice: listed once
	seed("b1", "t1", "u2", false)
	seed("c1", "t1", "u3", true)
	seed("d1", "t1", "", true) // unowned
	seed("e1", "t1", "u4", true)
	// A legacy suspended instance is not revoked.
	seed("f1", "t1", "u5", false)
	s := wis.(*WalletInstanceStore)
	s.data["f1"].Status = domain.InstanceStatusLegacySuspended

	ids := func(after string, limit int) []string {
		got, err := wis.ListUsersWithRevokedInstances(ctx, domain.UserIDFromString(after), limit)
		require.NoError(t, err)
		var out []string
		for _, id := range got {
			out = append(out, id.ID)
		}
		return out
	}
	require.Equal(t, []string{"u1", "u3", "u4"}, ids("", 10))
	require.Equal(t, []string{"u1", "u3"}, ids("", 2), "limit bounds the page")
	require.Equal(t, []string{"u4"}, ids("u3", 2), "the cursor is exclusive")
	require.Empty(t, ids("u4", 2))
	require.Empty(t, ids("", 0))
}
