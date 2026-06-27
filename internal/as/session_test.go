package as

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSession_IsExpired(t *testing.T) {
	s := &Session{ExpiresAt: time.Now().Add(-time.Minute)}
	assert.True(t, s.IsExpired())

	s2 := &Session{ExpiresAt: time.Now().Add(time.Minute)}
	assert.False(t, s2.IsExpired())
}

func TestSession_IsValid(t *testing.T) {
	// Valid session
	s := &Session{ExpiresAt: time.Now().Add(time.Hour)}
	assert.True(t, s.IsValid())

	// Expired
	s.ExpiresAt = time.Now().Add(-time.Minute)
	assert.False(t, s.IsValid())

	// Revoked but not expired
	s.ExpiresAt = time.Now().Add(time.Hour)
	s.Revoked = true
	assert.False(t, s.IsValid())
}

func TestMemorySessionStore_CreateAndGet(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()

	session := &Session{
		JTI:       "test-jti-1",
		UserID:    "user-42",
		TenantID:  "tenant-1",
		ACR:       "urn:siros:acr:passkey",
		MaxTAC:    TAC("rwl"),
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := store.Create(ctx, session)
	require.NoError(t, err)

	got, err := store.Get(ctx, "test-jti-1")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "user-42", got.UserID)
	assert.Equal(t, "tenant-1", got.TenantID)
	assert.Equal(t, "urn:siros:acr:passkey", got.ACR)
}

func TestMemorySessionStore_CreateDuplicate(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()

	session := &Session{JTI: "dup", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.Create(ctx, session))

	err := store.Create(ctx, session)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestMemorySessionStore_GetNotFound(t *testing.T) {
	store := NewMemorySessionStore()
	got, err := store.Get(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestMemorySessionStore_Revoke(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()

	session := &Session{JTI: "rev-1", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.Create(ctx, session))

	err := store.Revoke(ctx, "rev-1")
	require.NoError(t, err)

	got, err := store.Get(ctx, "rev-1")
	require.NoError(t, err)
	assert.True(t, got.Revoked)
	assert.False(t, got.IsValid())
}

func TestMemorySessionStore_RevokeNotFound(t *testing.T) {
	store := NewMemorySessionStore()
	err := store.Revoke(context.Background(), "nope")
	require.Error(t, err)
}

func TestMemorySessionStore_Delete(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()

	session := &Session{JTI: "del-1", ExpiresAt: time.Now().Add(time.Hour)}
	require.NoError(t, store.Create(ctx, session))

	err := store.Delete(ctx, "del-1")
	require.NoError(t, err)

	got, err := store.Get(ctx, "del-1")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestMemorySessionStore_Cleanup(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()

	// Active session
	require.NoError(t, store.Create(ctx, &Session{
		JTI:       "active",
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	// Expired session
	require.NoError(t, store.Create(ctx, &Session{
		JTI:       "expired",
		ExpiresAt: time.Now().Add(-time.Minute),
	}))

	removed := store.Cleanup()
	assert.Equal(t, 1, removed)

	// Active remains
	got, _ := store.Get(ctx, "active")
	assert.NotNil(t, got)

	// Expired is gone
	got, _ = store.Get(ctx, "expired")
	assert.Nil(t, got)
}

func TestGenerateSessionID(t *testing.T) {
	id1, err := GenerateSessionID()
	require.NoError(t, err)
	assert.Len(t, id1, 43) // 32 bytes → 43 base64url chars (no padding)

	id2, err := GenerateSessionID()
	require.NoError(t, err)
	assert.NotEqual(t, id1, id2) // Unique
}
