package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	store := NewStore("test-cache.json")
	require.NotNil(t, store)
	assert.NotNil(t, store.entries)
	assert.Equal(t, "test-cache.json", store.cachePath)
}

func TestStore_PutAndGet(t *testing.T) {
	store := NewStore("")

	entry := &VCTMEntry{
		VCT:          "https://example.com/credential/v1",
		Name:         "Test Credential",
		Description:  "A test credential",
		Organization: "Test Org",
		FetchedAt:    time.Now(),
	}

	// Put entry
	store.Put(entry)

	// Get should return the entry
	retrieved, found := store.Get("https://example.com/credential/v1")
	require.True(t, found)
	assert.Equal(t, entry.VCT, retrieved.VCT)
	assert.Equal(t, entry.Name, retrieved.Name)
	assert.Equal(t, entry.Description, retrieved.Description)
	assert.Equal(t, entry.Organization, retrieved.Organization)

	// Get non-existent entry
	_, found = store.Get("https://example.com/nonexistent")
	assert.False(t, found)
}

func TestStore_Delete(t *testing.T) {
	store := NewStore("")

	entry := &VCTMEntry{
		VCT:  "https://example.com/credential/v1",
		Name: "Test Credential",
	}

	store.Put(entry)

	// Verify it exists
	_, found := store.Get(entry.VCT)
	require.True(t, found)

	// Delete
	store.Delete(entry.VCT)

	// Should no longer exist
	_, found = store.Get(entry.VCT)
	assert.False(t, found)

	// Deleting non-existent entry should not panic
	store.Delete("https://example.com/nonexistent")
}

func TestStore_Update(t *testing.T) {
	store := NewStore("")

	// Add initial entry
	store.Put(&VCTMEntry{VCT: "https://old.com/credential", Name: "Old"})

	// Update with new entries
	newEntries := map[string]*VCTMEntry{
		"https://new1.com/credential": {VCT: "https://new1.com/credential", Name: "New1"},
		"https://new2.com/credential": {VCT: "https://new2.com/credential", Name: "New2"},
	}

	beforeUpdate := time.Now()
	store.Update(newEntries, "https://source.example.com")
	afterUpdate := time.Now()

	// Old entry should be gone
	_, found := store.Get("https://old.com/credential")
	assert.False(t, found)

	// New entries should exist
	entry1, found := store.Get("https://new1.com/credential")
	require.True(t, found)
	assert.Equal(t, "New1", entry1.Name)

	entry2, found := store.Get("https://new2.com/credential")
	require.True(t, found)
	assert.Equal(t, "New2", entry2.Name)

	// Source URL should be updated
	assert.Equal(t, "https://source.example.com", store.SourceURL())

	// Last updated should be set
	assert.True(t, store.LastUpdated().After(beforeUpdate) || store.LastUpdated().Equal(beforeUpdate))
	assert.True(t, store.LastUpdated().Before(afterUpdate) || store.LastUpdated().Equal(afterUpdate))
}

func TestStore_List(t *testing.T) {
	store := NewStore("")

	// Empty store
	list := store.List()
	assert.Empty(t, list)

	// Add entries
	store.Put(&VCTMEntry{VCT: "https://a.com/credential", Name: "A"})
	store.Put(&VCTMEntry{VCT: "https://b.com/credential", Name: "B"})
	store.Put(&VCTMEntry{VCT: "https://c.com/credential", Name: "C"})

	list = store.List()
	assert.Len(t, list, 3)
}

func TestStore_Count(t *testing.T) {
	store := NewStore("")

	assert.Equal(t, 0, store.Count())

	store.Put(&VCTMEntry{VCT: "https://a.com/credential"})
	assert.Equal(t, 1, store.Count())

	store.Put(&VCTMEntry{VCT: "https://b.com/credential"})
	assert.Equal(t, 2, store.Count())

	store.Delete("https://a.com/credential")
	assert.Equal(t, 1, store.Count())
}

func TestStore_VCTIDs(t *testing.T) {
	store := NewStore("")

	// Empty store
	ids := store.VCTIDs()
	assert.Empty(t, ids)

	// Add entries
	store.Put(&VCTMEntry{VCT: "https://a.com/credential"})
	store.Put(&VCTMEntry{VCT: "https://b.com/credential"})

	ids = store.VCTIDs()
	assert.Len(t, ids, 2)
	assert.Contains(t, ids, "https://a.com/credential")
	assert.Contains(t, ids, "https://b.com/credential")
}

func TestStore_SaveAndLoad(t *testing.T) {
	// Create a temp directory for the cache file
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "subdir", "cache.json")

	// Create store and add entries
	store1 := NewStore(cachePath)
	store1.Put(&VCTMEntry{
		VCT:          "https://example.com/credential",
		Name:         "Test Credential",
		Description:  "A test credential",
		Organization: "Test Org",
		Metadata:     json.RawMessage(`{"key": "value"}`),
		FetchedAt:    time.Now(),
	})
	store1.Update(store1.entries, "https://source.example.com")

	// Save
	err := store1.Save()
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(cachePath)
	require.NoError(t, err)

	// Load into new store
	store2 := NewStore(cachePath)
	err = store2.Load()
	require.NoError(t, err)

	// Verify data was loaded
	assert.Equal(t, store1.Count(), store2.Count())
	assert.Equal(t, store1.SourceURL(), store2.SourceURL())

	entry, found := store2.Get("https://example.com/credential")
	require.True(t, found)
	assert.Equal(t, "Test Credential", entry.Name)
	assert.Equal(t, "A test credential", entry.Description)
	assert.Equal(t, "Test Org", entry.Organization)
	assert.JSONEq(t, `{"key": "value"}`, string(entry.Metadata))
}

func TestStore_Load_NonExistentFile(t *testing.T) {
	store := NewStore("/nonexistent/path/cache.json")
	err := store.Load()
	require.NoError(t, err) // Should not error for non-existent file
	assert.Equal(t, 0, store.Count())
}

func TestStore_Load_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "cache.json")

	// Write invalid JSON
	err := os.WriteFile(cachePath, []byte("not valid json"), 0644)
	require.NoError(t, err)

	store := NewStore(cachePath)
	err = store.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestStore_Load_InvalidVersion(t *testing.T) {
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "cache.json")

	// Write cache with wrong version
	cache := CacheData{
		Version:     "99",
		LastUpdated: time.Now(),
		Entries:     make(map[string]*VCTMEntry),
	}
	data, _ := json.Marshal(cache)
	err := os.WriteFile(cachePath, data, 0644)
	require.NoError(t, err)

	store := NewStore(cachePath)
	err = store.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported cache version")
}

func TestStore_Save_CreatesDirectory(t *testing.T) {
	tempDir := t.TempDir()
	cachePath := filepath.Join(tempDir, "deep", "nested", "dir", "cache.json")

	store := NewStore(cachePath)
	store.Put(&VCTMEntry{VCT: "https://example.com/credential", Name: "Test"})

	err := store.Save()
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(cachePath)
	require.NoError(t, err)
}

func TestStore_ConcurrentAccess(t *testing.T) {
	store := NewStore("")

	// Run concurrent operations
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			store.Put(&VCTMEntry{VCT: "https://concurrent.com/credential", Name: "Test"})
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			store.Get("https://concurrent.com/credential")
		}
		done <- true
	}()

	// List goroutine
	go func() {
		for i := 0; i < 100; i++ {
			store.List()
		}
		done <- true
	}()

	// Count goroutine
	go func() {
		for i := 0; i < 100; i++ {
			store.Count()
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 4; i++ {
		<-done
	}
}

func TestCacheData_JSONRoundtrip(t *testing.T) {
	now := time.Now().Round(time.Second)
	original := CacheData{
		Version:     "1",
		LastUpdated: now,
		SourceURL:   "https://source.example.com",
		Entries: map[string]*VCTMEntry{
			"https://example.com/credential": {
				VCT:          "https://example.com/credential",
				Name:         "Test",
				Description:  "Description",
				Organization: "Org",
				Metadata:     json.RawMessage(`{"test": true}`),
				Source: &VCTMSource{
					Repository: "https://github.com/example/repo",
					Branch:     "main",
				},
				FetchedAt: now,
			},
		},
	}

	// Marshal
	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal
	var loaded CacheData
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)

	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.SourceURL, loaded.SourceURL)
	assert.Len(t, loaded.Entries, 1)

	entry, ok := loaded.Entries["https://example.com/credential"]
	require.True(t, ok)
	assert.Equal(t, "Test", entry.Name)
	assert.Equal(t, "Description", entry.Description)
	assert.Equal(t, "Org", entry.Organization)
	assert.JSONEq(t, `{"test": true}`, string(entry.Metadata))
	assert.Equal(t, "https://github.com/example/repo", entry.Source.Repository)
	assert.Equal(t, "main", entry.Source.Branch)
}
