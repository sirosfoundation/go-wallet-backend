package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/metadata"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// issuerMetadataCache provides a simple TTL cache for issuer metadata keyed by
// credential_issuer_identifier. This avoids hammering upstream well-known
// endpoints on every frontend page load.
type issuerMetadataCache struct {
	mu      sync.Mutex
	entries map[string]*metadataCacheEntry
	ttl     time.Duration
}

type metadataCacheEntry struct {
	metadata  *metadata.IssuerMetadata
	fetchedAt time.Time
}

const defaultMetadataCacheTTL = 5 * time.Minute

func newIssuerMetadataCache() *issuerMetadataCache {
	return &issuerMetadataCache{
		entries: make(map[string]*metadataCacheEntry),
		ttl:     defaultMetadataCacheTTL,
	}
}

func (c *issuerMetadataCache) get(issuerURL string) (*metadata.IssuerMetadata, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[issuerURL]
	if !ok {
		return nil, false
	}
	if time.Since(entry.fetchedAt) > c.ttl {
		delete(c.entries, issuerURL)
		return nil, false
	}
	return entry.metadata, true
}

func (c *issuerMetadataCache) put(issuerURL string, m *metadata.IssuerMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict expired entries on write to keep the map bounded
	now := time.Now()
	for url, entry := range c.entries {
		if now.Sub(entry.fetchedAt) > c.ttl {
			delete(c.entries, url)
		}
	}

	c.entries[issuerURL] = &metadataCacheEntry{
		metadata:  m,
		fetchedAt: now,
	}
}

// GetIssuerMetadata handles GET /issuer/:id/metadata.
// It looks up the pre-registered issuer by ID (scoped to the authenticated
// tenant), fetches the issuer's .well-known/openid-credential-issuer metadata
// server-side, and returns it to the caller. Results are cached with a TTL.
func (h *Handlers) GetIssuerMetadata(c *gin.Context) {
	issuerID := c.Param("id")
	if issuerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Issuer ID required"})
		return
	}

	id, err := strconv.ParseInt(issuerID, 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid issuer ID"})
		return
	}

	tenantID, _ := h.getTenantID(c)

	// Look up the issuer and validate it belongs to this tenant
	issuer, err := h.services.Issuer.GetByID(c.Request.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Issuer not found"})
			return
		}
		h.logger.Error("Failed to get issuer", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get issuer"})
		return
	}

	issuerURL := issuer.CredentialIssuerIdentifier
	if issuerURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Issuer has no credential issuer identifier"})
		return
	}

	// Check cache
	if cached, ok := h.metadataCache.get(issuerURL); ok {
		c.JSON(http.StatusOK, cached)
		return
	}

	// Fetch metadata server-side
	result := metadata.DiscoverIssuer(c.Request.Context(), issuerURL, h.httpClient)
	if result.Error != nil && result.Metadata == nil {
		h.logger.Error("Failed to fetch issuer metadata",
			zap.String("issuer_url", issuerURL),
			zap.Error(result.Error))
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to fetch issuer metadata"})
		return
	}

	h.enrichCredentialMetadataFromRegistry(result.Metadata)

	h.metadataCache.put(issuerURL, result.Metadata)

	c.JSON(http.StatusOK, result.Metadata)
}

// enrichCredentialMetadataFromRegistry replaces each credential
// configuration's credential_metadata.display with the registry's published
// VCTM's own display array, for any configuration whose vct/doctype the
// local registry (registry.siros.org mirror, see Handlers.SetRegistryStore)
// carries a non-expired entry for.
//
// Deliberately extracts just the display array rather than substituting the
// registry's entire VCTM document (vct/claims/schema/display) for
// credential_metadata - a review comment on the PR that introduced this
// (sirosfoundation/go-wallet-backend#284) correctly pointed out that the
// endpoint's credential_metadata field is meant to hold this endpoint's
// condensed display info, not a full VCTM; the one genuine benefit over an
// issuer's own local vctm_file_path fixture is that go-trust/registry-cli's
// TS11 VCTM documents already have their images embedded as data: URIs (see
// internal/registry's ImageEmbedder) rather than pointing at a live,
// possibly-stale third-party URL, and only the display array carries that
// benefit. No-op (leaves credential_metadata exactly as the issuer returned
// it) if no registryStore is wired up, if the registry has no non-expired
// entry for a configuration, or if the registry's entry has no display
// array to extract.
func (h *Handlers) enrichCredentialMetadataFromRegistry(m *metadata.IssuerMetadata) {
	if h.registryStore == nil || m == nil || len(m.CredentialConfigurationsSupported) == 0 {
		return
	}

	var configs map[string]json.RawMessage
	if err := json.Unmarshal(m.CredentialConfigurationsSupported, &configs); err != nil {
		h.logger.Warn("Failed to parse credential_configurations_supported for registry enrichment", zap.Error(err))
		return
	}

	var identifier struct {
		Vct     string `json:"vct"`
		Doctype string `json:"doctype"`
	}
	var vctm struct {
		Display json.RawMessage `json:"display"`
	}
	changed := false
	for key, raw := range configs {
		identifier.Vct = ""
		identifier.Doctype = ""
		if err := json.Unmarshal(raw, &identifier); err != nil {
			continue
		}
		vctID := identifier.Vct
		if vctID == "" {
			vctID = identifier.Doctype
		}
		if vctID == "" {
			continue
		}

		entry, found := h.registryStore.Get(vctID)
		if !found || entry.IsExpired() || len(entry.Metadata) == 0 {
			continue
		}

		vctm.Display = nil
		if err := json.Unmarshal(entry.Metadata, &vctm); err != nil || len(vctm.Display) == 0 {
			continue
		}
		credentialMetadata, err := json.Marshal(struct {
			Display json.RawMessage `json:"display"`
		}{Display: vctm.Display})
		if err != nil {
			continue
		}

		var config map[string]json.RawMessage
		if err := json.Unmarshal(raw, &config); err != nil {
			continue
		}
		config["credential_metadata"] = credentialMetadata
		merged, err := json.Marshal(config)
		if err != nil {
			continue
		}
		configs[key] = merged
		changed = true
	}

	if !changed {
		return
	}
	updated, err := json.Marshal(configs)
	if err != nil {
		h.logger.Warn("Failed to re-marshal registry-enriched credential_configurations_supported", zap.Error(err))
		return
	}
	m.CredentialConfigurationsSupported = updated
}
