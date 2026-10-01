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
