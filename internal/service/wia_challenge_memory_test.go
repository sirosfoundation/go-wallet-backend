package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryWIAChallengeStore_PutAndConsume(t *testing.T) {
	store := newMemoryWIAChallengeStore(100)
	ctx := context.Background()

	ok, err := store.Put(ctx, "challenge-1", time.Now().Add(5*time.Minute))
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
	store := newMemoryWIAChallengeStore(100)
	ctx := context.Background()

	ok, err := store.Consume(ctx, "does-not-exist")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestMemoryWIAChallengeStore_Len(t *testing.T) {
	store := newMemoryWIAChallengeStore(100)
	ctx := context.Background()

	n, err := store.Len(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	_, _ = store.Put(ctx, "c1", time.Now().Add(5*time.Minute))
	_, _ = store.Put(ctx, "c2", time.Now().Add(5*time.Minute))

	n, err = store.Len(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestMemoryWIAChallengeStore_Capacity(t *testing.T) {
	store := newMemoryWIAChallengeStore(2)
	ctx := context.Background()

	ok, _ := store.Put(ctx, "c1", time.Now().Add(5*time.Minute))
	assert.True(t, ok)
	ok, _ = store.Put(ctx, "c2", time.Now().Add(5*time.Minute))
	assert.True(t, ok)
	// Third should fail (at capacity)
	ok, _ = store.Put(ctx, "c3", time.Now().Add(5*time.Minute))
	assert.False(t, ok)
}
