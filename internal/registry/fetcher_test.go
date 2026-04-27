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

	fetcher := NewFetcher(config, store, logger, nil)

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

	fetcher := NewFetcher(config, store, logger, nil)

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

	fetcher := NewFetcher(config, store, logger, nil)

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

	fetcher := NewFetcher(config, store, logger, nil)

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
	fetcher := NewFetcher(config, store, logger, nil)

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
	fetcher := NewFetcher(config, store, logger, nil)

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
	fetcher := NewFetcher(config, store, logger, nil)

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
	fetcher := NewFetcher(config, store, logger, nil)

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
	fetcher := NewFetcher(config, store, logger, nil)

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

// ---- TS11 format tests ----

func TestFetcher_FetchFromSource_TS11Format(t *testing.T) {
	vctmContent := `{"vct":"https://registry.example.org/cred.vctm.json","name":"Demo Credential","description":"A demo credential"}`

	vctmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vctmContent))
	}))
	defer vctmServer.Close()

	schemas := TS11SchemasResponse{
		Schemas: []TS11SchemaMeta{
			{
				ID:               "c48100f6-f19d-5f79-9bf5-819c293a08a4",
				Version:          "0.1.0",
				AttestationLoS:   "iso_18045_basic",
				BindingType:      "key",
				SupportedFormats: []string{"dc+sd-jwt"},
				SchemaURIs: []TS11SchemaURI{
					{FormatIdentifier: "dc+sd-jwt", URI: vctmServer.URL + "/cred.vctm.json"},
				},
				RulebookURI: "https://registry.example.org/rulebook.html",
			},
		},
	}

	indexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(schemas)
	}))
	defer indexServer.Close()

	config := DefaultConfig()
	store := NewStore("")
	logger := testLogger()
	fetcher := NewFetcher(config, store, logger, nil)

	src := RemoteSourceConfig{URL: indexServer.URL, Timeout: 5 * time.Second}
	entries, err := fetcher.fetchFromSource(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	vct := vctmServer.URL + "/cred.vctm.json"
	entry, ok := entries[vct]
	require.True(t, ok)

	assert.Equal(t, vct, entry.VCT)
	assert.Equal(t, "Demo Credential", entry.Name)
	assert.Equal(t, "A demo credential", entry.Description)
	assert.Equal(t, "iso_18045_basic", entry.AttestationLoS)
	assert.Equal(t, "key", entry.BindingType)
	assert.Equal(t, "https://registry.example.org/rulebook.html", entry.RulebookURI)
	assert.Equal(t, []string{"dc+sd-jwt"}, entry.SupportedFormats)
	assert.JSONEq(t, vctmContent, string(entry.Metadata))
	assert.False(t, entry.FetchedAt.IsZero())
}

func TestFetcher_FetchFromSource_TS11_FallbackToFirstSchemaURI(t *testing.T) {
	vctmContent := `{"vct":"https://example.org/cred.json","name":"Test"}`

	vctmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vctmContent))
	}))
	defer vctmServer.Close()

	// Schema has no dc+sd-jwt entry; the first URI should be used as fallback VCT
	schemas := TS11SchemasResponse{
		Schemas: []TS11SchemaMeta{
			{
				ID:      "some-id",
				Version: "1.0.0",
				SchemaURIs: []TS11SchemaURI{
					{FormatIdentifier: "jwt_vc", URI: vctmServer.URL + "/cred.json"},
				},
			},
		},
	}

	indexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(schemas)
	}))
	defer indexServer.Close()

	config := DefaultConfig()
	fetcher := NewFetcher(config, NewStore(""), testLogger(), nil)

	src := RemoteSourceConfig{URL: indexServer.URL}
	entries, err := fetcher.fetchFromSource(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestFetcher_FetchFromSource_TS11_SkipsSchemaWithNoURIs(t *testing.T) {
	schemas := TS11SchemasResponse{
		Schemas: []TS11SchemaMeta{
			{ID: "no-uris", Version: "1.0.0", SchemaURIs: nil},
		},
	}

	indexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(schemas)
	}))
	defer indexServer.Close()

	config := DefaultConfig()
	fetcher := NewFetcher(config, NewStore(""), testLogger(), nil)

	src := RemoteSourceConfig{URL: indexServer.URL}
	entries, err := fetcher.fetchFromSource(context.Background(), src)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFetcher_FetchFromSource_TS11_Pagination(t *testing.T) {
	vctmContent := `{"vct":"https://example.org/cred.json","name":"Cred"}`

	vctmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vctmContent))
	}))
	defer vctmServer.Close()

	// We need to know the index server URL ahead of time for the "next" field.
	// Use a shared handler that serves page1 or page2 based on the path.
	var indexServerURL string
	indexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/page2" {
			page2 := TS11SchemasResponse{
				Schemas: []TS11SchemaMeta{
					{
						ID: "id-2", Version: "1.0",
						SchemaURIs: []TS11SchemaURI{
							{FormatIdentifier: "dc+sd-jwt", URI: vctmServer.URL + "/cred2.json"},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(page2)
			return
		}
		page1 := TS11SchemasResponse{
			Schemas: []TS11SchemaMeta{
				{
					ID: "id-1", Version: "1.0",
					SchemaURIs: []TS11SchemaURI{
						{FormatIdentifier: "dc+sd-jwt", URI: vctmServer.URL + "/cred1.json"},
					},
				},
			},
			Next: indexServerURL + "/page2",
		}
		_ = json.NewEncoder(w).Encode(page1)
	}))
	defer indexServer.Close()
	indexServerURL = indexServer.URL

	config := DefaultConfig()
	fetcher := NewFetcher(config, NewStore(""), testLogger(), nil)

	src := RemoteSourceConfig{URL: indexServer.URL}
	entries, err := fetcher.fetchFromSource(context.Background(), src)
	require.NoError(t, err)
	// Both pages should be collected
	assert.Len(t, entries, 2)
}

func TestFetcher_FetchFromSource_LegacyFormat(t *testing.T) {
	vctmContent := `{"vct":"https://example.com/cred/v1","name":"Legacy Cred"}`

	vctmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vctmContent))
	}))
	defer vctmServer.Close()

	index := RegistryIndex{
		Name: "Legacy Registry",
		Credentials: []RegistryCredential{
			{
				VCT:  "https://example.com/cred/v1",
				Name: "Legacy Cred",
				Formats: map[string]CredentialFormat{
					"vctm": {URL: vctmServer.URL, Type: "application/json"},
				},
			},
		},
	}

	indexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer indexServer.Close()

	config := DefaultConfig()
	fetcher := NewFetcher(config, NewStore(""), testLogger(), nil)

	src := RemoteSourceConfig{URL: indexServer.URL}
	entries, err := fetcher.fetchFromSource(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Contains(t, entries, "https://example.com/cred/v1")
}

// ---- Multi-source tests ----

func TestFetcher_Fetch_MultipleSources_LaterOverwritesEarlier(t *testing.T) {
	vctmContent1 := `{"vct":"https://example.com/cred/v1","name":"Source1 Name"}`
	vctmContent2 := `{"vct":"https://example.com/cred/v1","name":"Source2 Name"}`

	vctmServer1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vctmContent1))
	}))
	defer vctmServer1.Close()

	vctmServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(vctmContent2))
	}))
	defer vctmServer2.Close()

	// Both TS11 sources publish the same VCT; source2 should win.
	makeSchemas := func(vctmURL string) TS11SchemasResponse {
		return TS11SchemasResponse{
			Schemas: []TS11SchemaMeta{
				{
					ID: "some-id", Version: "1.0",
					SchemaURIs: []TS11SchemaURI{
						{FormatIdentifier: "dc+sd-jwt", URI: vctmURL},
					},
				},
			},
		}
	}

	source1Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(makeSchemas(vctmServer1.URL + "/cred.vctm.json"))
	}))
	defer source1Server.Close()

	source2Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(makeSchemas(vctmServer2.URL + "/cred.vctm.json"))
	}))
	defer source2Server.Close()

	config := DefaultConfig()
	// The two sources use the same VCTM URL path so they resolve to the same VCT key.
	// To make a deterministic duplicate-key test, override the VCT to be identical.
	// We test this via the legacy format which lets us set VCT directly.
	legacyIndex1 := RegistryIndex{
		Credentials: []RegistryCredential{
			{VCT: "https://example.com/cred/v1", Name: "S1",
				Formats: map[string]CredentialFormat{"vctm": {URL: vctmServer1.URL}}},
		},
	}
	legacyIndex2 := RegistryIndex{
		Credentials: []RegistryCredential{
			{VCT: "https://example.com/cred/v1", Name: "S2",
				Formats: map[string]CredentialFormat{"vctm": {URL: vctmServer2.URL}}},
		},
	}

	srv1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(legacyIndex1)
	}))
	defer srv1.Close()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(legacyIndex2)
	}))
	defer srv2.Close()

	config.Sources = []RemoteSourceConfig{
		{URL: srv1.URL, Timeout: 5 * time.Second},
		{URL: srv2.URL, Timeout: 5 * time.Second},
	}
	require.NoError(t, config.Validate())

	store := NewStore("")
	fetcher := NewFetcher(config, store, testLogger(), nil)

	err := fetcher.Fetch(context.Background())
	require.NoError(t, err)

	// Source2 should overwrite Source1 for the same VCT.
	require.Equal(t, 1, store.Count())
	entry, ok := store.Get("https://example.com/cred/v1")
	require.True(t, ok)
	assert.Equal(t, "S2", entry.Name)
}

func TestFetcher_Fetch_MultipleSources_PartialFailure(t *testing.T) {
	// Source1 will return an error (500)
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errorServer.Close()

	// Source2 will return a valid legacy index
	index := RegistryIndex{
		Credentials: []RegistryCredential{
			{VCT: "https://example.com/cred/v1", Name: "Cred", Formats: map[string]CredentialFormat{}},
		},
	}
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(index)
	}))
	defer okServer.Close()

	config := DefaultConfig()
	config.Sources = []RemoteSourceConfig{
		{URL: errorServer.URL, Timeout: 5 * time.Second},
		{URL: okServer.URL, Timeout: 5 * time.Second},
	}
	require.NoError(t, config.Validate())

	store := NewStore("")
	fetcher := NewFetcher(config, store, testLogger(), nil)

	// Should succeed (partial failure is tolerated)
	err := fetcher.Fetch(context.Background())
	require.NoError(t, err)

	// Entries from the successful source should still be in the store
	assert.Equal(t, 1, store.Count())
}

func TestFetcher_Fetch_AllSourcesFail_ReturnsError(t *testing.T) {
	// Both sources will return 500 errors
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errorServer.Close()

	config := DefaultConfig()
	config.Sources = []RemoteSourceConfig{
		{URL: errorServer.URL, Timeout: 5 * time.Second},
		{URL: errorServer.URL + "/other", Timeout: 5 * time.Second},
	}
	require.NoError(t, config.Validate())

	store := NewStore("")
	// Pre-populate the store with an entry to verify it is preserved on failure
	store.Put(&VCTMEntry{VCT: "https://example.com/existing", Name: "Existing"})

	fetcher := NewFetcher(config, store, testLogger(), nil)

	err := fetcher.Fetch(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all")
	assert.Contains(t, err.Error(), "failed")

	// Existing store contents must be preserved
	assert.Equal(t, 1, store.Count())
	entry, ok := store.Get("https://example.com/existing")
	require.True(t, ok)
	assert.Equal(t, "Existing", entry.Name)
}

func TestConfig_Validate_NormalizesSourcesToSingleSource(t *testing.T) {
	config := DefaultConfig()
	// Sources is empty; Validate should populate it from Source
	config.Sources = nil
	require.NoError(t, config.Validate())
	require.Len(t, config.Sources, 1)
	assert.Equal(t, "https://registry.siros.org/api/v1/schemas.json", config.Sources[0].URL)
}

func TestConfig_Validate_MultiSources(t *testing.T) {
	config := DefaultConfig()
	config.Sources = []RemoteSourceConfig{
		{URL: "https://registry1.example.org/api/v1/schemas.json"},
		{URL: "https://registry2.example.org/api/v1/schemas.json"},
	}
	require.NoError(t, config.Validate())
	assert.Len(t, config.Sources, 2)
}

func TestConfig_Validate_SourcesEmptyURLIsRejected(t *testing.T) {
	config := DefaultConfig()
	config.Sources = []RemoteSourceConfig{
		{URL: "https://registry.example.org/api/v1/schemas.json"},
		{URL: ""}, // empty URL should fail
	}
	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sources[1].url is required")
}

func TestConfig_Validate_BothSourceEmptyAndSourcesEmpty(t *testing.T) {
	config := DefaultConfig()
	config.Source.URL = ""
	config.Sources = nil
	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source URL is required")
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
	fetcher := NewFetcher(config, store, logger, nil)

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
	fetcher := NewFetcher(config, store, logger, nil)

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
	fetcher := NewFetcher(config, store, logger, nil)

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
	fetcher := NewFetcher(config, store, logger, nil)

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
