package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testHandlerLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func setupTestRouter(store *Store) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewHandler(store, nil, nil, testHandlerLogger())
	handler.RegisterRoutes(router)
	return router
}

func TestNewHandler(t *testing.T) {
	store := NewStore("")
	logger := testHandlerLogger()

	handler := NewHandler(store, nil, nil, logger)

	require.NotNil(t, handler)
	assert.Equal(t, store, handler.store)
	assert.Equal(t, logger, handler.logger)
}

func TestHandler_GetTypeMetadata_Success(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:          "https://example.com/credential/v1",
		Name:         "Test Credential",
		Description:  "A test credential",
		Organization: "Test Org",
		Metadata:     json.RawMessage(`{"vct": "https://example.com/credential/v1", "claims": {"name": {"display": [{"name": "Name"}]}}}`),
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata?vct=https://example.com/credential/v1", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	// Should return the raw metadata
	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/credential/v1", result["vct"])
}

func TestHandler_GetTypeMetadata_NoMetadata(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:          "https://example.com/credential/v1",
		Name:         "Test Credential",
		Description:  "A test credential",
		Organization: "Test Org",
		Metadata:     nil, // No metadata
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata?vct=https://example.com/credential/v1", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Should return basic info
	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/credential/v1", result["vct"])
	assert.Equal(t, "Test Credential", result["name"])
	assert.Equal(t, "A test credential", result["description"])
	assert.Equal(t, "Test Org", result["organization"])
}

func TestHandler_GetTypeMetadata_AttestationLoS_WithMetadata(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:            "https://example.com/credential/v1",
		Name:           "Test Credential",
		Description:    "A test credential",
		Organization:   "Test Org",
		AttestationLoS: "iso_18045_high",
		Metadata:       json.RawMessage(`{"vct": "https://example.com/credential/v1", "claims": {"name": {"display": [{"name": "Name"}]}}}`),
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata?vct=https://example.com/credential/v1", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	// The raw document's own fields must be preserved.
	assert.Equal(t, "https://example.com/credential/v1", result["vct"])
	assert.Contains(t, result, "claims")
	// attestation_los must be merged in alongside them.
	assert.Equal(t, "iso_18045_high", result["attestation_los"])
}

func TestHandler_GetTypeMetadata_AttestationLoS_NoMetadata(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:            "https://example.com/credential/v1",
		Name:           "Test Credential",
		Description:    "A test credential",
		Organization:   "Test Org",
		AttestationLoS: "iso_18045_moderate",
		Metadata:       nil,
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata?vct=https://example.com/credential/v1", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "Test Credential", result["name"])
	assert.Equal(t, "iso_18045_moderate", result["attestation_los"])
}

func TestHandler_GetTypeMetadata_AttestationLoS_MdocDoctype(t *testing.T) {
	store := NewStore("")
	// mdoc doctype identifiers (not a "vct" URN) go through the exact same
	// serveEntry code path as sd-jwt VCTs.
	store.Put(&VCTMEntry{
		VCT:            "org.iso.18013.5.1.mDL",
		Name:           "Mobile Driving Licence",
		AttestationLoS: "iso_18045_basic",
		Metadata:       json.RawMessage(`{"doctype": "org.iso.18013.5.1.mDL", "namespaces": {}}`),
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata?vct=org.iso.18013.5.1.mDL", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "org.iso.18013.5.1.mDL", result["doctype"])
	assert.Equal(t, "iso_18045_basic", result["attestation_los"])
}

func TestHandler_GetTypeMetadata_AttestationLoS_Empty(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:            "https://example.com/credential/v1",
		Name:           "Test Credential",
		AttestationLoS: "", // not populated upstream
		Metadata:       json.RawMessage(`{"vct": "https://example.com/credential/v1"}`),
	})
	store.Put(&VCTMEntry{
		VCT:            "https://example.com/credential/v2",
		Name:           "Test Credential 2",
		AttestationLoS: "",
		Metadata:       nil,
	})

	router := setupTestRouter(store)

	for _, vct := range []string{"https://example.com/credential/v1", "https://example.com/credential/v2"} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/type-metadata?vct="+vct, nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &result)
		require.NoError(t, err)
		assert.NotContains(t, result, "attestation_los", "attestation_los must be omitted, not emitted empty, for vct=%s", vct)
	}
}

func TestHandler_GetTypeMetadata_AttestationLoS_MergeError(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:            "https://example.com/credential/v1",
		Name:           "Test Credential",
		AttestationLoS: "iso_18045_high",
		// Malformed upstream metadata: mergeAttestationLoS will fail to
		// decode it, so serveEntry must log a warning and fall back to
		// returning the original (unmodified) bytes rather than erroring
		// out the whole request.
		Metadata: json.RawMessage(`not-valid-json`),
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata?vct=https://example.com/credential/v1", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "not-valid-json", w.Body.String(), "on merge failure the original raw bytes must pass through unchanged")
}

func TestMergeAttestationLoS(t *testing.T) {
	t.Run("preserves nested fields and types exactly", func(t *testing.T) {
		// A JSON number that would change representation if round-tripped
		// through map[string]interface{} (float64) is the regression case:
		// it must come back byte-for-byte identical.
		input := json.RawMessage(`{"vct":"urn:example","claims":{"age":{"min":18}},"weight":1.50}`)

		merged, err := mergeAttestationLoS(input, "iso_18045_high")
		require.NoError(t, err)

		var result map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(merged, &result))
		assert.JSONEq(t, `"urn:example"`, string(result["vct"]))
		assert.JSONEq(t, `{"age":{"min":18}}`, string(result["claims"]))
		// Preserved exactly as the original bytes, not renormalized to "1.5".
		assert.Equal(t, "1.50", string(result["weight"]))
		assert.JSONEq(t, `"iso_18045_high"`, string(result["attestation_los"]))
	})

	t.Run("returns error on malformed input", func(t *testing.T) {
		_, err := mergeAttestationLoS(json.RawMessage(`not-valid-json`), "iso_18045_high")
		require.Error(t, err)
	})
}

func TestHandler_ListCredentials_AttestationLoS(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:            "https://example.com/credential1",
		Name:           "Credential 1",
		AttestationLoS: "iso_18045_high",
	})
	store.Put(&VCTMEntry{
		VCT:  "https://example.com/credential2",
		Name: "Credential 2",
		// AttestationLoS empty - omitted
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/credentials", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)

	credentialsAny, ok := result["credentials"]
	require.True(t, ok, "response must contain a credentials field")
	credentials, ok := credentialsAny.([]interface{})
	require.True(t, ok, "credentials field must be a JSON array")
	require.Len(t, credentials, 2)

	var withLoS, withoutLoS map[string]interface{}
	for _, cred := range credentials {
		c, ok := cred.(map[string]interface{})
		require.True(t, ok, "each credential entry must be a JSON object")
		if c["vct"] == "https://example.com/credential1" {
			withLoS = c
		} else {
			withoutLoS = c
		}
	}
	require.NotNil(t, withLoS)
	require.NotNil(t, withoutLoS)
	assert.Equal(t, "iso_18045_high", withLoS["attestation_los"])
	assert.NotContains(t, withoutLoS, "attestation_los")
}

func TestHandler_GetTypeMetadata_NotFound(t *testing.T) {
	store := NewStore("")
	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata?vct=https://example.com/nonexistent", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "not_found", result["error"])
	assert.Equal(t, "https://example.com/nonexistent", result["vct"])
}

func TestHandler_GetTypeMetadata_MissingParameter(t *testing.T) {
	store := NewStore("")
	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "missing_parameter", result["error"])
}

func TestHandler_GetTypeMetadata_EmptyParameter(t *testing.T) {
	store := NewStore("")
	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/type-metadata?vct=", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_ListCredentials_Empty(t *testing.T) {
	store := NewStore("")
	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/credentials", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, float64(0), result["total"])
	assert.Empty(t, result["credentials"])
}

func TestHandler_ListCredentials_WithEntries(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:          "https://example.com/credential1",
		Name:         "Credential 1",
		Description:  "First credential",
		Organization: "Org 1",
	})
	store.Put(&VCTMEntry{
		VCT:          "https://example.com/credential2",
		Name:         "Credential 2",
		Description:  "Second credential",
		Organization: "Org 2",
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/credentials", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, float64(2), result["total"])

	credentials := result["credentials"].([]interface{})
	assert.Len(t, credentials, 2)

	// Check that each credential has the expected fields
	for _, cred := range credentials {
		c := cred.(map[string]interface{})
		assert.Contains(t, c, "vct")
		assert.Contains(t, c, "name")
		assert.Contains(t, c, "description")
		assert.Contains(t, c, "organization")
	}
}

func TestHandler_GetStatus_Empty(t *testing.T) {
	store := NewStore("")
	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/status", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
	assert.Equal(t, float64(0), result["credentials"])
}

func TestHandler_GetStatus_WithData(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{VCT: "https://example.com/cred1"})
	store.Put(&VCTMEntry{VCT: "https://example.com/cred2"})
	store.Update(store.entries, "https://registry.example.com")

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/status", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "ok", result["status"])
	assert.Equal(t, float64(2), result["credentials"])
	assert.Equal(t, "https://registry.example.com", result["source_url"])
	assert.Contains(t, result, "last_updated")
}

func TestHandler_RegisterRoutes(t *testing.T) {
	store := NewStore("")
	router := setupTestRouter(store)

	// Test that all routes are registered
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/type-metadata"},
		{"GET", "/credentials"},
		{"GET", "/status"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(route.method, route.path, nil)
			router.ServeHTTP(w, req)

			// Should not return 404
			assert.NotEqual(t, http.StatusNotFound, w.Code, "route %s %s should exist", route.method, route.path)
		})
	}
}

func TestHandler_GetTypeMetadata_URLEncoding(t *testing.T) {
	store := NewStore("")
	// VCT with URL-like value (note: query params in query values get complex)
	vct := "https://example.com/credential/v1"
	store.Put(&VCTMEntry{
		VCT:      vct,
		Name:     "Test Credential",
		Metadata: json.RawMessage(`{"vct": "test"}`),
	})

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	// Use URL encoding for the vct parameter
	req, _ := http.NewRequest("GET", "/type-metadata?vct=https%3A%2F%2Fexample.com%2Fcredential%2Fv1", nil)
	router.ServeHTTP(w, req)

	// Should find the credential (URL params are decoded by Go)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_Concurrent(t *testing.T) {
	store := NewStore("")
	store.Put(&VCTMEntry{
		VCT:      "https://example.com/credential/v1",
		Name:     "Test Credential",
		Metadata: json.RawMessage(`{"vct": "test"}`),
	})

	router := setupTestRouter(store)

	// Make concurrent requests
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/type-metadata?vct=https://example.com/credential/v1", nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/credentials", nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		go func() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/status", nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 30; i++ {
		<-done
	}
}

func TestHandler_GetStatus_LastUpdatedFormat(t *testing.T) {
	store := NewStore("")
	// Update to set a known time
	entries := map[string]*VCTMEntry{
		"https://example.com/cred": {VCT: "https://example.com/cred"},
	}
	store.Update(entries, "https://source.example.com")

	router := setupTestRouter(store)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/status", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)

	// Verify the last_updated is a valid HTTP time format
	lastUpdated, ok := result["last_updated"].(string)
	require.True(t, ok)

	_, err = time.Parse(http.TimeFormat, lastUpdated)
	require.NoError(t, err, "last_updated should be in HTTP time format")
}
