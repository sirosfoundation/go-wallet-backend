package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func testLogger() *zap.Logger {
	return zap.NewNop()
}

func testConfig() *config.Config {
	return &config.Config{}
}

func TestNewTrustService(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()

	ts := NewTrustService(cfg, logger)
	require.NotNil(t, ts)
	assert.NotNil(t, ts.evaluators)
	assert.Equal(t, cfg, ts.cfg)
}

func TestTrustService_GetEvaluator_NoEndpoint(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()
	ts := NewTrustService(cfg, logger)

	// No default endpoint configured
	eval, err := ts.GetEvaluator("")
	require.NoError(t, err)
	assert.Nil(t, eval, "should return nil when no endpoint configured")
}

func TestTrustService_GetEvaluator_WithEndpoint(t *testing.T) {
	// Start a mock AuthZEN server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"decision": true})
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Trust.DefaultEndpoint = server.URL
	logger := testLogger()
	ts := NewTrustService(cfg, logger)

	eval, err := ts.GetEvaluator("")
	require.NoError(t, err)
	assert.NotNil(t, eval, "should return evaluator when endpoint configured")
}

func TestTrustService_GetEvaluator_CachesEvaluators(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"decision": true})
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Trust.DefaultEndpoint = server.URL
	logger := testLogger()
	ts := NewTrustService(cfg, logger)

	eval1, err := ts.GetEvaluator("")
	require.NoError(t, err)

	eval2, err := ts.GetEvaluator("")
	require.NoError(t, err)

	assert.Same(t, eval1, eval2, "should return cached evaluator")
}

func TestNewRegistryClient(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()

	rc := NewRegistryClient(cfg, logger)
	require.NotNil(t, rc)
	assert.NotNil(t, rc.httpClient)
	assert.Equal(t, cfg, rc.cfg)
}

func TestRegistryClient_FetchTypeMetadata_EmptyVCT(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()
	rc := NewRegistryClient(cfg, logger)

	vctm, err := rc.FetchTypeMetadata(context.Background(), "")
	require.NoError(t, err)
	assert.Nil(t, vctm, "should return nil for empty VCT")
}

func TestRegistryClient_FetchTypeMetadata_Success(t *testing.T) {
	metadata := &VCTMetadata{
		VCT:         "urn:example:credential",
		Name:        "Example Credential",
		Description: "Test credential type",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/type-metadata", r.URL.Path)
		assert.Equal(t, "urn:example:credential", r.URL.Query().Get("vct"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Trust.RegistryURL = server.URL
	logger := testLogger()
	rc := NewRegistryClient(cfg, logger)

	result, err := rc.FetchTypeMetadata(context.Background(), "urn:example:credential")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "urn:example:credential", result.VCT)
	assert.Equal(t, "Example Credential", result.Name)
	assert.Equal(t, "Test credential type", result.Description)
}

func TestRegistryClient_FetchTypeMetadata_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Trust.RegistryURL = server.URL
	logger := testLogger()
	rc := NewRegistryClient(cfg, logger)

	result, err := rc.FetchTypeMetadata(context.Background(), "urn:unknown:credential")
	require.NoError(t, err)
	assert.Nil(t, result, "should return nil for not found VCT")
}

func TestRegistryClient_FetchTypeMetadata_ServerUnavailable(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.RegistryURL = "http://localhost:12345" // Non-existent server
	logger := testLogger()
	rc := NewRegistryClient(cfg, logger)

	// Should not return error, just nil result
	result, err := rc.FetchTypeMetadata(context.Background(), "urn:example:credential")
	require.NoError(t, err, "should not fail when registry unavailable")
	assert.Nil(t, result)
}

func TestRegistryClient_FetchTypeMetadataJSON_Success(t *testing.T) {
	metadata := map[string]any{
		"vct":         "urn:example:credential",
		"name":        "Example Credential",
		"description": "Test credential type",
		"display": map[string]any{
			"locale": "en",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	cfg := testConfig()
	cfg.Trust.RegistryURL = server.URL
	logger := testLogger()
	rc := NewRegistryClient(cfg, logger)

	result := rc.FetchTypeMetadataJSON(context.Background(), "urn:example:credential")
	require.NotNil(t, result)

	// Verify it can be parsed
	var parsed map[string]any
	err := json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "urn:example:credential", parsed["vct"])
}

func TestRegistryClient_registryURL_Default(t *testing.T) {
	cfg := testConfig()
	logger := testLogger()
	rc := NewRegistryClient(cfg, logger)

	assert.Equal(t, "http://localhost:8082", rc.registryURL())
}

func TestRegistryClient_registryURL_Configured(t *testing.T) {
	cfg := testConfig()
	cfg.Trust.RegistryURL = "https://registry.example.com"
	logger := testLogger()
	rc := NewRegistryClient(cfg, logger)

	assert.Equal(t, "https://registry.example.com", rc.registryURL())
}
