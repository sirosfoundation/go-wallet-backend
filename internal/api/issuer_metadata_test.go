package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/metadata"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func setupIssuerMetadataTest(t *testing.T) (*Handlers, *gin.Engine, *memory.Store) {
	t.Helper()
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			RPName:   "Test Wallet",
		},
		JWT: config.JWTConfig{
			Secret:      "test-secret",
			ExpiryHours: 24,
			Issuer:      "test-wallet",
		},
		// Allow loopback so tests using httptest.NewServer can reach mock
		// servers. InsecureSkipVerify because embed.IsImageURL only accepts
		// https:// image URLs, so image fixtures must be httptest.NewTLSServer
		// with its self-signed certificate.
		HTTPClient: config.HTTPClientConfig{AllowPrivateIPs: true, InsecureSkipVerify: true},
	}

	store := memory.NewStore()
	services := service.NewServices(store, cfg, logger)
	handlers := NewHandlers(services, cfg, logger, []string{"test"})

	router := gin.New()
	// Mock auth middleware
	router.Use(func(c *gin.Context) {
		c.Set("tenant_id", "default")
		c.Set("user_id", "test-user")
		c.Next()
	})
	router.GET("/issuer/:id/metadata", handlers.GetIssuerMetadata)

	return handlers, router, store
}

func TestGetIssuerMetadata_InvalidID(t *testing.T) {
	_, router, _ := setupIssuerMetadataTest(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuer/abc/metadata", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestGetIssuerMetadata_NotFound(t *testing.T) {
	_, router, _ := setupIssuerMetadataTest(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/issuer/999/metadata", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestGetIssuerMetadata_Success(t *testing.T) {
	// Start a mock issuer metadata server
	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-credential-issuer" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"credential_issuer":   "https://issuer.example.com",
				"credential_endpoint": "https://issuer.example.com/credential",
				"credential_configurations_supported": map[string]interface{}{
					"UniversityDegree": map[string]interface{}{
						"format": "jwt_vc_json",
					},
				},
			})
		} else {
			http.NotFound(w, r)
		}
	}))
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)

	// Create a tenant and issuer pointing to our mock server
	ctx := context.Background()
	store.Tenants().Create(ctx, &domain.Tenant{
		ID:      "default",
		Name:    "Default",
		Enabled: true,
	})
	issuer := &domain.CredentialIssuer{
		TenantID:                   "default",
		CredentialIssuerIdentifier: mockIssuer.URL,
		Visible:                    true,
	}
	if err := store.Issuers().Create(ctx, issuer); err != nil {
		t.Fatal(err)
	}
	issuerID := issuer.ID

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// The response should be the IssuerMetadata directly with proper JSON keys
	if result["credential_issuer"] != "https://issuer.example.com" {
		t.Errorf("Expected credential_issuer, got %v", result["credential_issuer"])
	}
}

// mockIssuerWithVct starts a mock .well-known server whose single
// credential_configurations_supported entry (key "ehic") has both a top-level
// "vct" (SD-JWT VC configs carry this directly per OpenID4VCI) and its own
// credential_metadata.display, so tests can tell apart "the issuer's own
// value" from "the registry's value".
func mockIssuerWithVct(t *testing.T, vct string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":   "https://issuer.example.com",
			"credential_endpoint": "https://issuer.example.com/credential",
			"credential_configurations_supported": map[string]interface{}{
				"ehic": map[string]interface{}{
					"format": "dc+sd-jwt",
					"vct":    vct,
					"credential_metadata": map[string]interface{}{
						"display": []interface{}{
							map[string]interface{}{"name": "Issuer's own EHIC"},
						},
					},
				},
			},
		})
	}))
}

func createTestIssuer(t *testing.T, store *memory.Store, issuerURL string) int64 {
	t.Helper()
	ctx := context.Background()
	// memory.NewStore() already seeds the "default" tenant, so this
	// consistently returns ErrAlreadyExists - expected, not a real failure.
	if err := store.Tenants().Create(ctx, &domain.Tenant{ID: "default", Name: "Default", Enabled: true}); err != nil && !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatal(err)
	}
	issuer := &domain.CredentialIssuer{
		TenantID:                   "default",
		CredentialIssuerIdentifier: issuerURL,
		Visible:                    true,
	}
	if err := store.Issuers().Create(ctx, issuer); err != nil {
		t.Fatal(err)
	}
	return issuer.ID
}

// mockIssuerWithLogo serves issuer metadata whose display references a logo
// at logoURL, plus a second display entry with no image at all.
func mockIssuerWithLogo(t *testing.T, logoURL string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":   "https://issuer.example.com",
			"credential_endpoint": "https://issuer.example.com/credential",
			"credential_configurations_supported": map[string]interface{}{
				"ehic": map[string]interface{}{
					"format": "dc+sd-jwt",
					"vct":    "urn:eudi:ehic:1",
					"credential_metadata": map[string]interface{}{
						"display": []interface{}{
							map[string]interface{}{
								"name":   "Issuer's own EHIC",
								"locale": "en-US",
								"logo": map[string]interface{}{
									"uri":           logoURL,
									"uri#integrity": "sha256-whatever",
									"alt_text":      "EHIC logo",
								},
							},
							map[string]interface{}{"name": "Ingen bild", "locale": "sv-SE"},
						},
					},
				},
			},
		})
	}))
}

// imageServer serves a single 1x1 PNG and counts how many times it is hit.
func imageServer(t *testing.T, hits *int) *httptest.Server {
	t.Helper()
	png := []byte{
		0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
		0, 0, 0, 0x0d, 'I', 'H', 'D', 'R',
	}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	}))
}

// configsOf pulls credential_configurations_supported out of a response body.
func configsOf(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var resp struct {
		Configs map[string]interface{} `json:"credential_configurations_supported"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp.Configs
}

// ehicDisplay returns the display array of the "ehic" configuration.
func ehicDisplay(t *testing.T, body []byte) []interface{} {
	t.Helper()
	ehic, ok := configsOf(t, body)["ehic"].(map[string]interface{})
	if !ok {
		t.Fatalf("no ehic configuration in response: %s", body)
	}
	cm, ok := ehic["credential_metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("no credential_metadata in ehic configuration: %s", body)
	}
	display, ok := cm["display"].([]interface{})
	if !ok {
		t.Fatalf("no display array in credential_metadata: %s", body)
	}
	return display
}

// A logo hosted somewhere that sends no Access-Control-Allow-Origin is
// unusable by a browser wallet, which fetches the SVG to substitute claim
// values into it. Embedding it as a data: URI removes the cross-origin fetch.
func TestGetIssuerMetadata_EmbedsRemoteImagesAsDataURIs(t *testing.T) {
	hits := 0
	img := imageServer(t, &hits)
	defer img.Close()
	logoURL := img.URL + "/logo.png"

	mockIssuer := mockIssuerWithLogo(t, logoURL)
	defer mockIssuer.Close()

	handlers, router, store := setupIssuerMetadataTest(t)
	id := createTestIssuer(t, store, mockIssuer.URL)
	_ = handlers

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", id), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	logo := ehicDisplay(t, w.Body.Bytes())[0].(map[string]interface{})["logo"].(map[string]interface{})
	uri, _ := logo["uri"].(string)
	if !strings.HasPrefix(uri, "data:image/") {
		t.Fatalf("logo uri was not embedded as a data URI: %q", uri)
	}
	if hits == 0 {
		t.Fatal("image was never fetched")
	}
	// A data URI is self-contained, so an integrity hash over the old remote
	// bytes would be meaningless (and wrong) if left behind.
	if _, ok := logo["uri#integrity"]; ok {
		t.Errorf("uri#integrity should be dropped alongside an embedded uri, got %v", logo)
	}
}

// The whole point of the review feedback on #284: the response is the
// issuer's own content. Embedding changes how an asset is delivered and
// nothing else - no field is added, dropped, reworded or reordered.
func TestGetIssuerMetadata_EmbeddingPreservesIssuerContentVerbatim(t *testing.T) {
	hits := 0
	img := imageServer(t, &hits)
	defer img.Close()

	mockIssuer := mockIssuerWithLogo(t, img.URL+"/logo.png")
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)
	id := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", id), nil))

	display := ehicDisplay(t, w.Body.Bytes())
	if len(display) != 2 {
		t.Fatalf("display entries = %d, want 2 (the issuer's own two)", len(display))
	}
	first := display[0].(map[string]interface{})
	if first["name"] != "Issuer's own EHIC" || first["locale"] != "en-US" {
		t.Errorf("issuer's own display content was altered: %v", first)
	}
	if logo := first["logo"].(map[string]interface{}); logo["alt_text"] != "EHIC logo" {
		t.Errorf("sibling fields of an embedded uri must survive: %v", logo)
	}
	second := display[1].(map[string]interface{})
	if second["name"] != "Ingen bild" || second["locale"] != "sv-SE" {
		t.Errorf("display entry without an image was altered: %v", second)
	}

	ehic := configsOf(t, w.Body.Bytes())["ehic"].(map[string]interface{})
	if ehic["format"] != "dc+sd-jwt" || ehic["vct"] != "urn:eudi:ehic:1" {
		t.Errorf("configuration fields outside credential_metadata were altered: %v", ehic)
	}
}

// Soft failure is the contract: an unreachable, oversized or slow image
// leaves the issuer's original URL in place, which is exactly the behaviour
// before embedding existed. It must never fail the request.
func TestGetIssuerMetadata_UnreachableImageLeavesURLIntact(t *testing.T) {
	dead := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	logoURL := dead.URL + "/logo.png"
	dead.Close() // nothing is listening now

	mockIssuer := mockIssuerWithLogo(t, logoURL)
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)
	id := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", id), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("an unfetchable image must not fail the request: status = %d", w.Code)
	}

	logo := ehicDisplay(t, w.Body.Bytes())[0].(map[string]interface{})["logo"].(map[string]interface{})
	if logo["uri"] != logoURL {
		t.Errorf("uri = %v, want the issuer's original URL left untouched", logo["uri"])
	}
	if logo["uri#integrity"] != "sha256-whatever" {
		t.Errorf("uri#integrity must survive when the uri was not replaced, got %v", logo["uri#integrity"])
	}
}

// Regression guard for the reshape: embedding is identifier-agnostic. The
// previous registry-backed version could only act on a configuration whose
// vct/doctype the registry carried, so a configuration with neither was
// skipped entirely. Asset delivery has nothing to do with credential type.
func TestGetIssuerMetadata_EmbedsImagesWithoutVctOrDoctype(t *testing.T) {
	hits := 0
	img := imageServer(t, &hits)
	defer img.Close()
	logoURL := img.URL + "/logo.png"

	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":   "https://issuer.example.com",
			"credential_endpoint": "https://issuer.example.com/credential",
			"credential_configurations_supported": map[string]interface{}{
				"mystery": map[string]interface{}{
					"format": "dc+sd-jwt",
					"credential_metadata": map[string]interface{}{
						"display": []interface{}{
							map[string]interface{}{
								"name": "No vct, no doctype",
								"logo": map[string]interface{}{"uri": logoURL},
							},
						},
					},
				},
			},
		})
	}))
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)
	id := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", id), nil))

	cfg := configsOf(t, w.Body.Bytes())["mystery"].(map[string]interface{})
	cm := cfg["credential_metadata"].(map[string]interface{})
	logo := cm["display"].([]interface{})[0].(map[string]interface{})["logo"].(map[string]interface{})
	if uri, _ := logo["uri"].(string); !strings.HasPrefix(uri, "data:image/") {
		t.Fatalf("a configuration without vct/doctype must still get its images embedded, got %q", uri)
	}
}

// Metadata with no images at all must come back byte-identical, and must not
// cost an outbound request.
func TestGetIssuerMetadata_NoImagesIsANoOp(t *testing.T) {
	mockIssuer := mockIssuerWithVct(t, "urn:eudi:ehic:1")
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)
	id := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", id), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	display := ehicDisplay(t, w.Body.Bytes())
	if len(display) != 1 || display[0].(map[string]interface{})["name"] != "Issuer's own EHIC" {
		t.Errorf("issuer metadata without images must pass through unmodified, got %v", display)
	}
}

func TestGetIssuerMetadata_CachesResponses(t *testing.T) {
	callCount := 0
	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":   "https://issuer.example.com",
			"credential_endpoint": "https://issuer.example.com/credential",
		})
	}))
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)

	ctx := context.Background()
	store.Tenants().Create(ctx, &domain.Tenant{
		ID:      "default",
		Name:    "Default",
		Enabled: true,
	})
	issuer := &domain.CredentialIssuer{
		TenantID:                   "default",
		CredentialIssuerIdentifier: mockIssuer.URL,
		Visible:                    true,
	}
	store.Issuers().Create(ctx, issuer)

	path := fmt.Sprintf("/issuer/%d/metadata", issuer.ID)

	// First request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("First request: expected %d, got %d", http.StatusOK, w.Code)
	}

	// Second request — should be cached
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, path, nil)
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("Second request: expected %d, got %d", http.StatusOK, w2.Code)
	}

	if callCount != 1 {
		t.Errorf("Expected 1 upstream call (cached), got %d", callCount)
	}
}

func TestGetIssuerMetadata_UpstreamError(t *testing.T) {
	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer mockIssuer.Close()

	_, router, store := setupIssuerMetadataTest(t)

	ctx := context.Background()
	store.Tenants().Create(ctx, &domain.Tenant{
		ID:      "default",
		Name:    "Default",
		Enabled: true,
	})
	issuer := &domain.CredentialIssuer{
		TenantID:                   "default",
		CredentialIssuerIdentifier: mockIssuer.URL,
		Visible:                    true,
	}
	store.Issuers().Create(ctx, issuer)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuer.ID), nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}
}

func TestGetIssuerMetadata_CrossTenantBlocked(t *testing.T) {
	_, router, store := setupIssuerMetadataTest(t)

	ctx := context.Background()
	// Create two tenants
	store.Tenants().Create(ctx, &domain.Tenant{
		ID: "default", Name: "Default", Enabled: true,
	})
	store.Tenants().Create(ctx, &domain.Tenant{
		ID: "other-tenant", Name: "Other", Enabled: true,
	})

	// Create issuer under "other-tenant" (not "default")
	issuer := &domain.CredentialIssuer{
		TenantID:                   "other-tenant",
		CredentialIssuerIdentifier: "https://issuer.example.com",
		Visible:                    true,
	}
	store.Issuers().Create(ctx, issuer)

	// Auth middleware sets tenant_id="default", so this issuer should not be found
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuer.ID), nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d (cross-tenant), got %d: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestIssuerMetadataCache(t *testing.T) {
	cache := newIssuerMetadataCache()

	// Miss on empty cache
	_, ok := cache.get("https://example.com")
	if ok {
		t.Error("Expected cache miss")
	}

	// Put and hit
	m := &metadata.IssuerMetadata{
		CredentialIssuer: "https://example.com",
	}
	cache.put("https://example.com", m)

	cached, ok := cache.get("https://example.com")
	if !ok {
		t.Fatal("Expected cache hit")
	}
	if cached != m {
		t.Error("Cached result does not match")
	}
}
