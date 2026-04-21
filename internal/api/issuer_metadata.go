package api

import (
	"errors"
	"fmt"
	"net/http"
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
	mu      sync.RWMutex
	entries map[string]*metadataCacheEntry
	ttl     time.Duration
}

type metadataCacheEntry struct {
	result    *metadata.IssuerDiscoveryResult
	fetchedAt time.Time
}

const defaultMetadataCacheTTL = 5 * time.Minute

func newIssuerMetadataCache() *issuerMetadataCache {
	return &issuerMetadataCache{
		entries: make(map[string]*metadataCacheEntry),
		ttl:     defaultMetadataCacheTTL,
	}
}

func (c *issuerMetadataCache) get(issuerURL string) (*metadata.IssuerDiscoveryResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[issuerURL]
	if !ok || time.Since(entry.fetchedAt) > c.ttl {
		return nil, false
	}
	return entry.result, true
}

func (c *issuerMetadataCache) put(issuerURL string, result *metadata.IssuerDiscoveryResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[issuerURL] = &metadataCacheEntry{
		result:    result,
		fetchedAt: time.Now(),
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

	var id int64
	if _, err := fmt.Sscanf(issuerID, "%d", &id); err != nil {
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
	httpClient := h.cfg.HTTPClient.NewHTTPClient(0)
	result := metadata.DiscoverIssuer(c.Request.Context(), issuerURL, httpClient)
	if result.Error != nil && result.Metadata == nil {
		h.logger.Error("Failed to fetch issuer metadata",
			zap.String("issuer_url", issuerURL),
			zap.Error(result.Error))
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to fetch issuer metadata"})
		return
	}

	// Cache even partial results (metadata OK, IACA failed)
	h.metadataCache.put(issuerURL, result)

	c.JSON(http.StatusOK, result)
}
