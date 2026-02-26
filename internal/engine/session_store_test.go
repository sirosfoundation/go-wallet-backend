package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	require.NotNil(t, store)
	assert.NotNil(t, store.sessions)
	assert.NotNil(t, store.userIndex)
}

func TestMemorySessionStore_PutAndGet(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	session := &SessionData{
		ID:        "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := store.Put(ctx, session)
	require.NoError(t, err)

	// Get by ID
	got, err := store.Get(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.UserID, got.UserID)
	assert.Equal(t, session.TenantID, got.TenantID)
}

func TestMemorySessionStore_GetByUser(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	session := &SessionData{
		ID:        "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := store.Put(ctx, session)
	require.NoError(t, err)

	got, err := store.GetByUser(ctx, "user-1")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
}

func TestMemorySessionStore_GetNotFound(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	_, err := store.Get(ctx, "non-existent")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_GetExpired(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	session := &SessionData{
		ID:        "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
	}

	err := store.Put(ctx, session)
	require.NoError(t, err)

	_, err = store.Get(ctx, "sess-1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_PutDuplicate(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	session := &SessionData{
		ID:        "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := store.Put(ctx, session)
	require.NoError(t, err)

	err = store.Put(ctx, session)
	assert.ErrorIs(t, err, ErrSessionExists)
}

func TestMemorySessionStore_Update(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	session := &SessionData{
		ID:        "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := store.Put(ctx, session)
	require.NoError(t, err)

	// Update
	session.Metadata = map[string]string{"key": "value"}
	err = store.Update(ctx, session)
	require.NoError(t, err)

	// Verify update
	got, err := store.Get(ctx, "sess-1")
	require.NoError(t, err)
	assert.Equal(t, "value", got.Metadata["key"])
}

func TestMemorySessionStore_UpdateNotFound(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	session := &SessionData{
		ID:        "non-existent",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := store.Update(ctx, session)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_Delete(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	session := &SessionData{
		ID:        "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := store.Put(ctx, session)
	require.NoError(t, err)

	err = store.Delete(ctx, "sess-1")
	require.NoError(t, err)

	_, err = store.Get(ctx, "sess-1")
	assert.ErrorIs(t, err, ErrSessionNotFound)

	// User index should also be cleaned
	_, err = store.GetByUser(ctx, "user-1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_DeleteIdempotent(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	// Delete non-existent should not error
	err := store.Delete(ctx, "non-existent")
	require.NoError(t, err)
}

func TestMemorySessionStore_DeleteByUser(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	session := &SessionData{
		ID:        "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := store.Put(ctx, session)
	require.NoError(t, err)

	err = store.DeleteByUser(ctx, "user-1")
	require.NoError(t, err)

	_, err = store.Get(ctx, "sess-1")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestMemorySessionStore_List(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	// Add sessions for different tenants
	sessions := []*SessionData{
		{ID: "sess-1", UserID: "user-1", TenantID: "tenant-1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: "sess-2", UserID: "user-2", TenantID: "tenant-1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: "sess-3", UserID: "user-3", TenantID: "tenant-2", ExpiresAt: time.Now().Add(1 * time.Hour)},
	}

	for _, s := range sessions {
		err := store.Put(ctx, s)
		require.NoError(t, err)
	}

	// List tenant-1
	result, err := store.List(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, result, 2)

	// List tenant-2
	result, err = store.List(ctx, "tenant-2")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestMemorySessionStore_ListExcludesExpired(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	sessions := []*SessionData{
		{ID: "sess-1", UserID: "user-1", TenantID: "tenant-1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: "sess-2", UserID: "user-2", TenantID: "tenant-1", ExpiresAt: time.Now().Add(-1 * time.Hour)}, // Expired
	}

	for _, s := range sessions {
		err := store.Put(ctx, s)
		require.NoError(t, err)
	}

	result, err := store.List(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "sess-1", result[0].ID)
}

func TestMemorySessionStore_Cleanup(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	sessions := []*SessionData{
		{ID: "sess-1", UserID: "user-1", TenantID: "tenant-1", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: "sess-2", UserID: "user-2", TenantID: "tenant-1", ExpiresAt: time.Now().Add(-1 * time.Hour)},
		{ID: "sess-3", UserID: "user-3", TenantID: "tenant-1", ExpiresAt: time.Now().Add(-2 * time.Hour)},
	}

	for _, s := range sessions {
		err := store.Put(ctx, s)
		require.NoError(t, err)
	}

	count, err := store.Cleanup(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Verify only active session remains
	result, err := store.List(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "sess-1", result[0].ID)
}

func TestMemorySessionStore_ConcurrentAccess(t *testing.T) {
	store := NewMemorySessionStore(zap.NewNop())
	ctx := context.Background()

	// Start multiple goroutines doing concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			session := &SessionData{
				ID:        "sess-" + string(rune('A'+id)),
				UserID:    "user-" + string(rune('A'+id)),
				TenantID:  "tenant-1",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			}
			_ = store.Put(ctx, session)
			_, _ = store.Get(ctx, session.ID)
			_, _ = store.List(ctx, "tenant-1")
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestSessionData_JSONRoundtrip(t *testing.T) {
	original := &SessionData{
		ID:        "sess-1",
		UserID:    "user-1",
		TenantID:  "tenant-1",
		CreatedAt: time.Now().Round(time.Second),
		ExpiresAt: time.Now().Add(1 * time.Hour).Round(time.Second),
		Metadata:  map[string]string{"key": "value"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded SessionData
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.UserID, decoded.UserID)
	assert.Equal(t, original.TenantID, decoded.TenantID)
	assert.Equal(t, original.Metadata["key"], decoded.Metadata["key"])
}
