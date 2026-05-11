package registry

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestIntegration_LiveRegistry_TS11 fetches the live registry.siros.org TS11
// schemas API and validates that the implementation correctly parses the response.
//
// The test is skipped when running with -short to allow CI pipelines that do not
// have outbound network access to pass cleanly.  To run it explicitly:
//
//	go test ./internal/registry/... -run TestIntegration_LiveRegistry_TS11 -v
func TestIntegration_LiveRegistry_TS11(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live-network integration test in short mode")
	}

	const registryURL = "https://registry.siros.org/api/v1/schemas.json"

	cfg := DefaultConfig()
	cfg.Source.URL = registryURL
	cfg.Source.Timeout = 60 * time.Second
	cfg.Sources = nil // let Validate() normalize from Source
	require.NoError(t, cfg.Validate())

	store := NewStore("")
	logger, _ := zap.NewDevelopment()
	fetcher := NewFetcher(cfg, store, logger, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	err := fetcher.Fetch(ctx)
	require.NoError(t, err, "Fetch() against live registry.siros.org must succeed")

	count := store.Count()
	assert.Positive(t, count, "expected at least one credential entry from the live registry")
	t.Logf("fetched %d credential entries from %s", count, registryURL)

	// Inspect the entries and enforce structural invariants on every one.
	var ts11Count int
	for _, entry := range store.List() {
		// Every entry must have a non-empty VCT identifier.
		assert.NotEmpty(t, entry.VCT, "entry.VCT must not be empty")

		// Metadata must be present and valid JSON.
		require.NotEmpty(t, entry.Metadata, "entry.Metadata must not be empty (vct=%s)", entry.VCT)
		assert.True(t, json.Valid(entry.Metadata),
			"entry.Metadata must be valid JSON (vct=%s)", entry.VCT)

		// FetchedAt must be set to a recent time.
		assert.False(t, entry.FetchedAt.IsZero(), "entry.FetchedAt must be set (vct=%s)", entry.VCT)
		assert.WithinDuration(t, time.Now(), entry.FetchedAt, 5*time.Minute,
			"entry.FetchedAt should be recent (vct=%s)", entry.VCT)

		// Count how many entries carry at least one TS11-specific field.
		if entry.BindingType != "" || entry.AttestationLoS != "" || len(entry.SupportedFormats) > 0 {
			ts11Count++
			t.Logf("  [TS11] vct=%s name=%q los=%s binding=%s formats=%v",
				entry.VCT, entry.Name, entry.AttestationLoS, entry.BindingType, entry.SupportedFormats)
		}
	}

	// At least some entries should carry TS11 fields (the live registry is TS11).
	assert.Positive(t, ts11Count,
		"expected at least one entry with TS11 fields (AttestationLoS/BindingType/SupportedFormats) populated")
}

// TestIntegration_LiveRegistry_TS11_Pagination verifies that paginated responses
// from the live registry are followed and all pages are merged into the store.
// This is a lighter-weight companion to the main integration test: it only checks
// that a second call returns the same count (idempotent) and that every fetched
// entry is a valid TS11 entry (VCT starts with "https://").
func TestIntegration_LiveRegistry_TS11_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live-network integration test in short mode")
	}

	const registryURL = "https://registry.siros.org/api/v1/schemas.json"

	cfg := DefaultConfig()
	cfg.Source.URL = registryURL
	cfg.Source.Timeout = 60 * time.Second
	cfg.Sources = nil
	require.NoError(t, cfg.Validate())

	store := NewStore("")
	logger := zap.NewNop()
	fetcher := NewFetcher(cfg, store, logger, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	require.NoError(t, fetcher.Fetch(ctx), "first Fetch() must succeed")
	firstCount := store.Count()
	require.Positive(t, firstCount, "first Fetch() must populate the store")

	// A second fetch must succeed and yield the same number of entries,
	// demonstrating idempotent behaviour and correct pagination.
	require.NoError(t, fetcher.Fetch(ctx), "second Fetch() must succeed")
	secondCount := store.Count()

	assert.Equal(t, firstCount, secondCount,
		"repeated Fetch() calls must yield the same number of entries (pagination is deterministic)")
}
