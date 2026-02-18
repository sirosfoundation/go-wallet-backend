package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func TestNewFetcher(t *testing.T) {
	config := DefaultConfig()
	store := NewStore("")
	logger := testLogger()

	fetcher := NewFetcher(config, store, logger)

	require.NotNil(t, fetcher)
	assert.Equal(t, config, fetcher.config)
	assert.Equal(t, store, fetcher.store)
	assert.NotNil(t, fetcher.client)
	assert.NotNil(t, fetcher.stopCh)
}

func TestFetcher_FetchIndex(t *testing.T) {
	// Create test server with registry index
	index := RegistryIndex{
		Schema:      "https://siros.org/schema/vctm-registry-index.json",
		Name:        "Test Registry",
		Description: "A test registry",
		URL:         "https://registry.example.com",
		Version:     "1.0.0",
		Credentials: []RegistryCredential{
			{
				VCT:          "https://example.com/credential/v1",
				Name:         "Test Credential",
				Description:  "A test credential",
				Organization: "Test Org",
				Formats: map[string]CredentialFormat{
					"vctm": {
						URL:  "https://example.com/vctm.json",
						Type: "application/json",
					},
				},
				Metadata: CredentialMetadata{
					HTML: "https://example.com/docs.html",
					JSON: "https://example.com/metadata.json",
				},
				Source: CredentialSource{
					Repository: "https://github.com/example/repo",
					Branch:     "main",
				},
			},
		},
		BuildTime: "2024-01-01T00:00:00Z",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "go-wallet-registry/1.0", r.Header.Get("User-Agent"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Source.URL = server.URL
	store := NewStore("")
	logger := testLogger()

	fetcher := NewFetcher(config, store, logger)

	result, err := fetcher.fetchIndex(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Test Registry", result.Name)
	assert.Len(t, result.Credentials, 1)
	assert.Equal(t, "https://example.com/credential/v1", result.Credentials[0].VCT)
}

func TestFetcher_FetchIndex_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Source.URL = server.URL
	store := NewStore("")
	logger := testLogger()

	fetcher := NewFetcher(config, store, logger)

	_, err := fetcher.fetchIndex(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code")
}

func TestFetcher_FetchIndex_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Source.URL = server.URL
	store := NewStore("")
	logger := testLogger()

	fetcher := NewFetcher(config, store, logger)

	_, err := fetcher.fetchIndex(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestFetcher_FetchVCTM(t *testing.T) {
	vctmContent := `{"vct": "https://example.com/credential/v1", "name": "Test", "claims": {}}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vctmContent))
	}))
	defer server.Close()

	config := DefaultConfig()
	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	cred := &RegistryCredential{
		VCT:          "https://example.com/credential/v1",
		Name:         "Test Credential",
		Description:  "A test credential",
		Organization: "Test Org",
		Formats: map[string]CredentialFormat{
			"vctm": {
				URL:  server.URL,
				Type: "application/json",
			},
		},
		Source: CredentialSource{
			Repository: "https://github.com/example/repo",
			Branch:     "main",
		},
	}

	entry, err := fetcher.fetchVCTM(context.Background(), cred)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, "https://example.com/credential/v1", entry.VCT)
	assert.Equal(t, "Test Credential", entry.Name)
	assert.Equal(t, "A test credential", entry.Description)
	assert.Equal(t, "Test Org", entry.Organization)
	assert.JSONEq(t, vctmContent, string(entry.Metadata))
	assert.Equal(t, "https://github.com/example/repo", entry.Source.Repository)
	assert.Equal(t, "main", entry.Source.Branch)
	assert.False(t, entry.FetchedAt.IsZero())
}

func TestFetcher_FetchVCTM_NoURL(t *testing.T) {
	config := DefaultConfig()
	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	cred := &RegistryCredential{
		VCT:          "https://example.com/credential/v1",
		Name:         "Test Credential",
		Description:  "A test credential",
		Organization: "Test Org",
		Formats:      map[string]CredentialFormat{}, // No VCTM format
		Metadata:     CredentialMetadata{},          // No metadata URLs
		Source: CredentialSource{
			Repository: "https://github.com/example/repo",
			Branch:     "main",
		},
	}

	entry, err := fetcher.fetchVCTM(context.Background(), cred)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, "https://example.com/credential/v1", entry.VCT)
	assert.Equal(t, "Test Credential", entry.Name)
	assert.Nil(t, entry.Metadata) // No metadata fetched
}

func TestFetcher_FetchVCTM_FallbackToMetadataJSON(t *testing.T) {
	vctmContent := `{"vct": "https://example.com/credential/v1"}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vctmContent))
	}))
	defer server.Close()

	config := DefaultConfig()
	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	cred := &RegistryCredential{
		VCT:     "https://example.com/credential/v1",
		Name:    "Test Credential",
		Formats: map[string]CredentialFormat{}, // No VCTM format
		Metadata: CredentialMetadata{
			JSON: server.URL, // Fall back to metadata JSON
		},
	}

	entry, err := fetcher.fetchVCTM(context.Background(), cred)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.JSONEq(t, vctmContent, string(entry.Metadata))
}

func TestFetcher_FetchVCTM_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := DefaultConfig()
	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	cred := &RegistryCredential{
		VCT: "https://example.com/credential/v1",
		Formats: map[string]CredentialFormat{
			"vctm": {URL: server.URL, Type: "application/json"},
		},
	}

	_, err := fetcher.fetchVCTM(context.Background(), cred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code")
}

func TestFetcher_FetchVCTM_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json {"))
	}))
	defer server.Close()

	config := DefaultConfig()
	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	cred := &RegistryCredential{
		VCT: "https://example.com/credential/v1",
		Formats: map[string]CredentialFormat{
			"vctm": {URL: server.URL, Type: "application/json"},
		},
	}

	_, err := fetcher.fetchVCTM(context.Background(), cred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid JSON")
}

func TestFetcher_Fetch_WithFilter(t *testing.T) {
	index := RegistryIndex{
		Name: "Test Registry",
		Credentials: []RegistryCredential{
			{
				VCT:     "https://example.com/included/v1",
				Name:    "Included Credential",
				Formats: map[string]CredentialFormat{},
			},
			{
				VCT:     "https://excluded.com/credential/v1",
				Name:    "Excluded Credential",
				Formats: map[string]CredentialFormat{},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Source.URL = server.URL
	config.Filter.IncludePatterns = []string{"^https://example\\.com/"}
	require.NoError(t, config.Validate()) // Compiles filter patterns

	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	err := fetcher.Fetch(context.Background())
	require.NoError(t, err)

	// Only included credential should be in store
	assert.Equal(t, 1, store.Count())
	_, found := store.Get("https://example.com/included/v1")
	assert.True(t, found)
	_, found = store.Get("https://excluded.com/credential/v1")
	assert.False(t, found)
}

func TestFetcher_Fetch_UpdatesStore(t *testing.T) {
	index := RegistryIndex{
		Name: "Test Registry",
		Credentials: []RegistryCredential{
			{VCT: "https://example.com/cred1", Name: "Cred 1", Formats: map[string]CredentialFormat{}},
			{VCT: "https://example.com/cred2", Name: "Cred 2", Formats: map[string]CredentialFormat{}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Source.URL = server.URL
	require.NoError(t, config.Validate())

	tempDir := t.TempDir()
	store := NewStore(tempDir + "/cache.json")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	err := fetcher.Fetch(context.Background())
	require.NoError(t, err)

	assert.Equal(t, 2, store.Count())
	assert.Equal(t, server.URL, store.SourceURL())
	assert.False(t, store.LastUpdated().IsZero())
}

func TestFetcher_StartAndStop(t *testing.T) {
	index := RegistryIndex{
		Name:        "Test Registry",
		Credentials: []RegistryCredential{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Source.URL = server.URL
	config.Source.PollInterval = 1 * time.Second
	require.NoError(t, config.Validate())

	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := fetcher.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for initial fetch
	time.Sleep(50 * time.Millisecond)

	// Stop should not panic
	fetcher.Stop()
}

func TestFetcher_ContextCancellation(t *testing.T) {
	index := RegistryIndex{
		Name:        "Test Registry",
		Credentials: []RegistryCredential{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Source.URL = server.URL
	config.Source.PollInterval = 1 * time.Second
	require.NoError(t, config.Validate())

	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger)

	ctx, cancel := context.WithCancel(context.Background())

	err := fetcher.Start(ctx)
	require.NoError(t, err)

	// Cancel context to stop polling
	cancel()

	// Wait a bit to ensure goroutine exits cleanly
	time.Sleep(50 * time.Millisecond)
}

func TestRegistryIndex_JSONRoundtrip(t *testing.T) {
	original := RegistryIndex{
		Schema:      "https://siros.org/schema/vctm-registry-index.json",
		Name:        "Test Registry",
		Description: "A test registry",
		URL:         "https://registry.example.com",
		Version:     "1.0.0",
		Credentials: []RegistryCredential{
			{
				VCT:          "https://example.com/credential/v1",
				Name:         "Test Credential",
				Description:  "Description",
				Organization: "Org",
				Formats: map[string]CredentialFormat{
					"vctm": {URL: "https://example.com/vctm.json", Type: "application/json"},
				},
				Metadata: CredentialMetadata{
					HTML: "https://example.com/docs.html",
					JSON: "https://example.com/metadata.json",
				},
				Source: CredentialSource{
					Repository: "https://github.com/example/repo",
					Branch:     "main",
				},
			},
		},
		BuildTime: "2024-01-01T00:00:00Z",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var loaded RegistryIndex
	err = json.Unmarshal(data, &loaded)
	require.NoError(t, err)

	assert.Equal(t, original.Schema, loaded.Schema)
	assert.Equal(t, original.Name, loaded.Name)
	assert.Equal(t, original.Description, loaded.Description)
	assert.Equal(t, original.URL, loaded.URL)
	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.BuildTime, loaded.BuildTime)
	assert.Len(t, loaded.Credentials, 1)
	assert.Equal(t, original.Credentials[0].VCT, loaded.Credentials[0].VCT)
}
