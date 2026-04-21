package api

import (
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

	h.metadataCache.put(issuerURL, result.Metadata)

	c.JSON(http.StatusOK, result.Metadata)
}
