package service

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// skipIfNoMongo connects to a MongoDB instance for testing, or skips the
// test if none is configured — same convention as
// internal/storage/mongodb's tests (MONGODB_TEST_URI / TEST_MONGODB=1).
func skipIfNoMongo(t *testing.T) *mongo.Database {
	t.Helper()
	if os.Getenv("MONGODB_TEST_URI") == "" && os.Getenv("TEST_MONGODB") == "" {
		t.Skip("Skipping MongoDB test: set MONGODB_TEST_URI or TEST_MONGODB=1 to enable")
	}
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		uri = "mongodb://localhost:27017"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		t.Skipf("MongoDB not available: %v", err)
	}

	db := client.Database("wallet_backend_test_wia_challenges")
	t.Cleanup(func() {
		ctx := context.Background()
		_ = db.Drop(ctx)
		_ = client.Disconnect(ctx)
	})
	return db
}

func TestMongoWIAChallengeStore_PutAndConsume(t *testing.T) {
	db := skipIfNoMongo(t)
	ctx := context.Background()
	store, err := NewMongoWIAChallengeStore(ctx, db, 100, 100)
	require.NoError(t, err)

	ok, err := store.Put(ctx, domain.DefaultTenantID, "challenge-1", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = store.Consume(ctx, "challenge-1")
	require.NoError(t, err)
	require.True(t, ok, "first consume should succeed")

	ok, err = store.Consume(ctx, "challenge-1")
	require.NoError(t, err)
	require.False(t, ok, "second consume should fail (single-use)")
}

func TestMongoWIAChallengeStore_GlobalCapacity(t *testing.T) {
	db := skipIfNoMongo(t)
	ctx := context.Background()
	store, err := NewMongoWIAChallengeStore(ctx, db, 2, 100)
	require.NoError(t, err)

	ok, err := store.Put(ctx, domain.TenantID("t1"), "c1", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = store.Put(ctx, domain.TenantID("t2"), "c2", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = store.Put(ctx, domain.TenantID("t3"), "c3", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	require.False(t, ok, "should reject once the global cap is reached")
}

// TestMongoWIAChallengeStore_PerTenantCapacity is a regression test for
// issue #224's "bounded capacity per tenant to prevent abuse" acceptance
// criterion: one tenant filling its own per-tenant cap must not be able to
// consume the entire global pool, and must not block a different tenant.
func TestMongoWIAChallengeStore_PerTenantCapacity(t *testing.T) {
	db := skipIfNoMongo(t)
	ctx := context.Background()
	store, err := NewMongoWIAChallengeStore(ctx, db, 100, 2)
	require.NoError(t, err)

	tenantA := domain.TenantID("tenant-a")
	tenantB := domain.TenantID("tenant-b")

	ok, err := store.Put(ctx, tenantA, "a1", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = store.Put(ctx, tenantA, "a2", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	require.True(t, ok)

	// Tenant A is at its own per-tenant cap now — rejected even though the
	// global pool (100) is nowhere near full.
	ok, err = store.Put(ctx, tenantA, "a3", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	require.False(t, ok, "tenant A should be rejected once at its own per-tenant cap")

	// Tenant B must be unaffected by tenant A's usage.
	ok, err = store.Put(ctx, tenantB, "b1", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	require.True(t, ok, "a different tenant must not be blocked by tenant A's cap")
}
