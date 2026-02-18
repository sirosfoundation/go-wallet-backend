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
	handler := NewHandler(store, nil, testHandlerLogger())
	handler.RegisterRoutes(router)
	return router
}

func TestNewHandler(t *testing.T) {
	store := NewStore("")
	logger := testHandlerLogger()

	handler := NewHandler(store, nil, logger)

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
