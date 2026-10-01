package mongodb

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// The revocation filter must name the legal source states explicitly; a
// "$ne revoked" filter would let an unknown or corrupted status be revoked.
func TestRevocableSourceFilter(t *testing.T) {
	f := revocableSourceFilter()
	in, ok := f["$in"].([]domain.InstanceStatus)
	require.True(t, ok, "filter must use $in, got %v", f)
	require.ElementsMatch(t, []domain.InstanceStatus{
		domain.InstanceStatusActive, domain.InstanceStatusLegacySuspended,
	}, in)
	require.NotContains(t, f, "$ne")
	_ = bson.M(f)
}

// The owner bind and the passkey link of Upsert are separate statements after
// the upsert; both must carry the generation the upsert wrote, or a record
// deleted and re-created in between would be bound to the old caller.
func TestUpsertBindAndLinkFiltersAreGenerationScoped(t *testing.T) {
	u := domain.UserIDFromString("u1")
	inst := &domain.WalletInstance{ID: "x", TenantID: "t", UserID: &u, Generation: "gen-1", CredentialID: "c"}
	for name, f := range map[string]bson.M{"bind": upsertBindFilter(inst), "link": upsertLinkFilter(inst)} {
		conds, ok := f["$and"].([]bson.M)
		require.True(t, ok, name)
		require.Contains(t, conds, bson.M{"generation": "gen-1"}, name)
		require.Contains(t, conds, bson.M{"tenant_id": domain.TenantID("t")}, name)
	}
	require.Contains(t, upsertLinkFilter(inst)["$and"], bson.M{"user_id": u})

	// A record that predates generations is matched by "no generation" only.
	legacy := &domain.WalletInstance{ID: "x", TenantID: "t"}
	require.Contains(t, upsertBindFilter(legacy)["$and"], generationCond(""))
	require.NotContains(t, upsertBindFilter(legacy)["$and"], bson.M{"generation": ""})
}
