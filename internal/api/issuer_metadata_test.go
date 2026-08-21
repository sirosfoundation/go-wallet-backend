package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/metadata"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
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
		// Allow loopback so tests using httptest.NewServer can reach mock servers.
		HTTPClient: config.HTTPClientConfig{AllowPrivateIPs: true},
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
	store.Tenants().Create(ctx, &domain.Tenant{ID: "default", Name: "Default", Enabled: true})
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

func TestGetIssuerMetadata_RegistryOverridesCredentialMetadata(t *testing.T) {
	const vct = "urn:eudi:ehic:1"
	mockIssuer := mockIssuerWithVct(t, vct)
	defer mockIssuer.Close()

	handlers, router, store := setupIssuerMetadataTest(t)
	registryStore := registry.NewStore("")
	registryStore.Put(&registry.VCTMEntry{
		VCT:      vct,
		Metadata: json.RawMessage(`{"vct":"` + vct + `","display":[{"name":"Registry's EHIC"}]}`),
	})
	handlers.SetRegistryStore(registryStore)

	issuerID := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var result metadata.IssuerMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	var configs map[string]struct {
		CredentialMetadata struct {
			Display []struct {
				Name string `json:"name"`
			} `json:"display"`
		} `json:"credential_metadata"`
	}
	if err := json.Unmarshal(result.CredentialConfigurationsSupported, &configs); err != nil {
		t.Fatalf("Failed to parse credential_configurations_supported: %v", err)
	}
	name := configs["ehic"].CredentialMetadata.Display[0].Name
	if name != "Registry's EHIC" {
		t.Errorf("Expected registry-sourced credential_metadata to win, got display name %q", name)
	}
}

func TestGetIssuerMetadata_ExpiredRegistryEntryFallsBackToIssuer(t *testing.T) {
	const vct = "urn:eudi:ehic:1"
	mockIssuer := mockIssuerWithVct(t, vct)
	defer mockIssuer.Close()

	handlers, router, store := setupIssuerMetadataTest(t)
	registryStore := registry.NewStore("")
	registryStore.Put(&registry.VCTMEntry{
		VCT:       vct,
		Metadata:  json.RawMessage(`{"vct":"` + vct + `","display":[{"name":"Registry's EHIC"}]}`),
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	handlers.SetRegistryStore(registryStore)

	issuerID := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	var result metadata.IssuerMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	var configs map[string]struct {
		CredentialMetadata struct {
			Display []struct {
				Name string `json:"name"`
			} `json:"display"`
		} `json:"credential_metadata"`
	}
	if err := json.Unmarshal(result.CredentialConfigurationsSupported, &configs); err != nil {
		t.Fatalf("Failed to parse credential_configurations_supported: %v", err)
	}
	name := configs["ehic"].CredentialMetadata.Display[0].Name
	if name != "Issuer's own EHIC" {
		t.Errorf("Expected an expired registry entry to be ignored, got display name %q", name)
	}
}

func TestGetIssuerMetadata_NoRegistryStoreLeavesMetadataUnmodified(t *testing.T) {
	const vct = "urn:eudi:ehic:1"
	mockIssuer := mockIssuerWithVct(t, vct)
	defer mockIssuer.Close()

	// setupIssuerMetadataTest's handlers never has SetRegistryStore called -
	// this is the "registry role disabled on this server" case.
	_, router, store := setupIssuerMetadataTest(t)
	issuerID := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	var result metadata.IssuerMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	var configs map[string]struct {
		CredentialMetadata struct {
			Display []struct {
				Name string `json:"name"`
			} `json:"display"`
		} `json:"credential_metadata"`
	}
	if err := json.Unmarshal(result.CredentialConfigurationsSupported, &configs); err != nil {
		t.Fatalf("Failed to parse credential_configurations_supported: %v", err)
	}
	name := configs["ehic"].CredentialMetadata.Display[0].Name
	if name != "Issuer's own EHIC" {
		t.Errorf("Expected no registry store to leave credential_metadata untouched, got display name %q", name)
	}
}

// mockIssuerWithDoctype mirrors mockIssuerWithVct but for an ISO 18013-5 mdoc
// config, which identifies itself via "doctype" rather than "vct" -
// enrichCredentialMetadataFromRegistry falls back to doctype when vct is
// absent, and this exercises that path directly rather than only vct.
func mockIssuerWithDoctype(t *testing.T, doctype string) *httptest.Server {
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
				"mdl": map[string]interface{}{
					"format":  "mso_mdoc",
					"doctype": doctype,
					"credential_metadata": map[string]interface{}{
						"display": []interface{}{
							map[string]interface{}{"name": "Issuer's own mDL"},
						},
					},
				},
			},
		})
	}))
}

func TestGetIssuerMetadata_RegistryOverridesCredentialMetadataForMdocDoctype(t *testing.T) {
	const doctype = "org.iso.18013.5.1.mDL"
	mockIssuer := mockIssuerWithDoctype(t, doctype)
	defer mockIssuer.Close()

	handlers, router, store := setupIssuerMetadataTest(t)
	registryStore := registry.NewStore("")
	registryStore.Put(&registry.VCTMEntry{
		VCT:      doctype,
		Metadata: json.RawMessage(`{"doctype":"` + doctype + `","display":[{"name":"Registry's mDL"}]}`),
	})
	handlers.SetRegistryStore(registryStore)

	issuerID := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	var result metadata.IssuerMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	var configs map[string]struct {
		CredentialMetadata struct {
			Display []struct {
				Name string `json:"name"`
			} `json:"display"`
		} `json:"credential_metadata"`
	}
	if err := json.Unmarshal(result.CredentialConfigurationsSupported, &configs); err != nil {
		t.Fatalf("Failed to parse credential_configurations_supported: %v", err)
	}
	name := configs["mdl"].CredentialMetadata.Display[0].Name
	if name != "Registry's mDL" {
		t.Errorf("Expected registry-sourced credential_metadata to win for a doctype-identified config, got display name %q", name)
	}
}

func TestGetIssuerMetadata_RegistryMissEntryLeavesIssuerMetadataUnmodified(t *testing.T) {
	const vct = "urn:eudi:ehic:1"
	mockIssuer := mockIssuerWithVct(t, vct)
	defer mockIssuer.Close()

	handlers, router, store := setupIssuerMetadataTest(t)
	// A registry store IS wired up, but it never learned about this vct -
	// distinct from the expired-entry case: here Get itself returns found=false.
	registryStore := registry.NewStore("")
	handlers.SetRegistryStore(registryStore)

	issuerID := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	var result metadata.IssuerMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	var configs map[string]struct {
		CredentialMetadata struct {
			Display []struct {
				Name string `json:"name"`
			} `json:"display"`
		} `json:"credential_metadata"`
	}
	if err := json.Unmarshal(result.CredentialConfigurationsSupported, &configs); err != nil {
		t.Fatalf("Failed to parse credential_configurations_supported: %v", err)
	}
	name := configs["ehic"].CredentialMetadata.Display[0].Name
	if name != "Issuer's own EHIC" {
		t.Errorf("Expected a registry miss (no entry for this vct) to leave credential_metadata untouched, got display name %q", name)
	}
}

func TestGetIssuerMetadata_ConfigWithoutVctOrDoctypeIsSkipped(t *testing.T) {
	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// A config with neither "vct" nor "doctype" - e.g. a jwt_vc_json
		// format that identifies itself some other way. There's nothing for
		// enrichCredentialMetadataFromRegistry to look up, so this whole
		// config (and, since it's the only one, the whole enrichment pass)
		// must be a no-op.
		json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":   "https://issuer.example.com",
			"credential_endpoint": "https://issuer.example.com/credential",
			"credential_configurations_supported": map[string]interface{}{
				"other": map[string]interface{}{
					"format": "jwt_vc_json",
					"credential_metadata": map[string]interface{}{
						"display": []interface{}{
							map[string]interface{}{"name": "Issuer's own credential"},
						},
					},
				},
			},
		})
	}))
	defer mockIssuer.Close()

	handlers, router, store := setupIssuerMetadataTest(t)
	registryStore := registry.NewStore("")
	handlers.SetRegistryStore(registryStore)

	issuerID := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	var result metadata.IssuerMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	var configs map[string]struct {
		CredentialMetadata struct {
			Display []struct {
				Name string `json:"name"`
			} `json:"display"`
		} `json:"credential_metadata"`
	}
	if err := json.Unmarshal(result.CredentialConfigurationsSupported, &configs); err != nil {
		t.Fatalf("Failed to parse credential_configurations_supported: %v", err)
	}
	name := configs["other"].CredentialMetadata.Display[0].Name
	if name != "Issuer's own credential" {
		t.Errorf("Expected a config with no vct/doctype to be left untouched, got display name %q", name)
	}
}

func TestGetIssuerMetadata_MalformedCredentialConfigurationsSupportedIsIgnored(t *testing.T) {
	mockIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-credential-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// credential_configurations_supported is required to be a JSON
		// object keyed by config ID (OpenID4VCI ยง10.2.3) - a malformed
		// issuer sending an array here must not crash enrichment, just skip
		// it and return whatever DiscoverIssuer already parsed.
		json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":                   "https://issuer.example.com",
			"credential_endpoint":                 "https://issuer.example.com/credential",
			"credential_configurations_supported": []string{"not", "an", "object"},
		})
	}))
	defer mockIssuer.Close()

	handlers, router, store := setupIssuerMetadataTest(t)
	registryStore := registry.NewStore("")
	handlers.SetRegistryStore(registryStore)

	issuerID := createTestIssuer(t, store, mockIssuer.URL)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/issuer/%d/metadata", issuerID), nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected malformed credential_configurations_supported to still return %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
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
