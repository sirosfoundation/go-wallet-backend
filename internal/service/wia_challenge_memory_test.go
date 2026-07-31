package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

func TestMemoryWIAChallengeStore_PutAndConsume(t *testing.T) {
	store := newMemoryWIAChallengeStore(100, 100)
	ctx := context.Background()

	ok, err := store.Put(ctx, domain.DefaultTenantID, "challenge-1", time.Now().Add(5*time.Minute))
	require.NoError(t, err)
	assert.True(t, ok)

	// Consume succeeds once
	ok, err = store.Consume(ctx, "challenge-1")
	require.NoError(t, err)
	assert.True(t, ok)

	// Second consume fails (single-use)
	ok, err = store.Consume(ctx, "challenge-1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestMemoryWIAChallengeStore_ConsumeNonexistent(t *testing.T) {
	store := newMemoryWIAChallengeStore(100, 100)
	ctx := context.Background()

	ok, err := store.Consume(ctx, "does-not-exist")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestMemoryWIAChallengeStore_Len(t *testing.T) {
	store := newMemoryWIAChallengeStore(100, 100)
	ctx := context.Background()

	n, err := store.Len(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	_, _ = store.Put(ctx, domain.DefaultTenantID, "c1", time.Now().Add(5*time.Minute))
	_, _ = store.Put(ctx, domain.DefaultTenantID, "c2", time.Now().Add(5*time.Minute))

	n, err = store.Len(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestMemoryWIAChallengeStore_Capacity(t *testing.T) {
	store := newMemoryWIAChallengeStore(2, 2)
	ctx := context.Background()

	ok, _ := store.Put(ctx, domain.DefaultTenantID, "c1", time.Now().Add(5*time.Minute))
	assert.True(t, ok)
	ok, _ = store.Put(ctx, domain.DefaultTenantID, "c2", time.Now().Add(5*time.Minute))
	assert.True(t, ok)
	// Third should fail (at capacity)
	ok, _ = store.Put(ctx, domain.DefaultTenantID, "c3", time.Now().Add(5*time.Minute))
	assert.False(t, ok)
}

// TestMemoryWIAChallengeStore_PerTenantCapacity is a regression test for issue
// #224's "bounded capacity per tenant to prevent abuse" acceptance criterion:
// one tenant filling its own per-tenant cap must not be able to consume the
// entire global pool, and must not block a different tenant from creating
// challenges.
func TestMemoryWIAChallengeStore_PerTenantCapacity(t *testing.T) {
	store := newMemoryWIAChallengeStore(100, 2) // global room for far more than any one tenant may use
	ctx := context.Background()
	tenantA := domain.TenantID("tenant-a")
	tenantB := domain.TenantID("tenant-b")

	ok, _ := store.Put(ctx, tenantA, "a1", time.Now().Add(5*time.Minute))
	assert.True(t, ok)
	ok, _ = store.Put(ctx, tenantA, "a2", time.Now().Add(5*time.Minute))
	assert.True(t, ok)
	// Tenant A is at its own per-tenant cap now — further creates must fail
	// even though the global pool (100) is nowhere near full.
	ok, _ = store.Put(ctx, tenantA, "a3", time.Now().Add(5*time.Minute))
	assert.False(t, ok, "tenant A should be rejected once at its own per-tenant cap")

	// Tenant B must be unaffected by tenant A's usage.
	ok, _ = store.Put(ctx, tenantB, "b1", time.Now().Add(5*time.Minute))
	assert.True(t, ok, "a different tenant must not be blocked by tenant A's cap")

	// Consuming one of tenant A's challenges frees a slot for tenant A again.
	consumed, _ := store.Consume(ctx, "a1")
	assert.True(t, consumed)
	ok, _ = store.Put(ctx, tenantA, "a4", time.Now().Add(5*time.Minute))
	assert.True(t, ok, "consuming a challenge should free tenant A's per-tenant slot")
}
