package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/embed"
	"github.com/sirosfoundation/go-wallet-backend/internal/metadata"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
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

	h.embedIssuerMetadataImages(c.Request.Context(), result.Metadata)

	h.metadataCache.put(issuerURL, result.Metadata)

	c.JSON(http.StatusOK, result.Metadata)
}

// newIssuerMetadataImageEmbedder builds the embedder GetIssuerMetadata uses.
// Separate from the registry role's own embedder: this one runs against
// issuer-supplied documents on the request path, so it reuses the shared
// outbound HTTP client (proxy/TLS settings) rather than a bare default one.
func newIssuerMetadataImageEmbedder(cfg *config.Config, logger *zap.Logger) *embed.ImageEmbedder {
	embedCfg := embed.DefaultConfig()
	return embed.NewImageEmbedder(&embedCfg, logger.Named("issuer-metadata-embed"),
		embed.WithHTTPClient(cfg.HTTPClient.NewHTTPClient(embedCfg.Timeout)))
}

// embedIssuerMetadataImages inlines the images an issuer's own metadata
// points at as data: URIs, leaving every other byte of the issuer's
// .well-known response untouched.
//
// This deliberately does NOT substitute anything from the VCTM registry. An
// issuer is authoritative for what it says about the credentials it issues,
// and mixing a registry-published display array into a response otherwise
// assembled from the issuer's .well-known produces a document that is
// neither one thing nor the other - the point made in review on
// sirosfoundation/go-wallet-backend#284. The one benefit that motivated
// reaching for the registry in the first place is asset delivery, and that
// is obtainable directly: a logo or SVG template hosted somewhere that sends
// no Access-Control-Allow-Origin is unusable by a browser wallet, which
// fetches the SVG to substitute claim values into it, so it renders as a
// broken image. Embedding removes the cross-origin fetch entirely.
//
// Doing it here rather than via the registry also means it applies in every
// deployment: the registry-backed version could only ever act when the
// registry role happened to run in the same process (--mode=all).
//
// Failure is soft by construction. embed.ImageEmbedder leaves any individual
// URL alone when it is too large (MaxImageSize), too slow (Timeout), or
// unreachable, so the worst case is exactly the behaviour before this
// existed: the client receives the issuer's original URL.
//
// One boundary worth knowing: embed.IsImageURL accepts https:// only, so an
// issuer serving its logos over plain HTTP gets no embedding at all. That is
// deliberate on the embedder's side and not worked around here - it means the
// benefit lands in real deployments but not in an all-HTTP local dev stack,
// where the assets are same-origin and reachable anyway.
//
// Only credential_configurations_supported is processed - that is where
// display/logo/background_image/svg_templates live, and it is already held
// as a raw JSON message, so nothing else in the document is re-serialized.
func (h *Handlers) embedIssuerMetadataImages(ctx context.Context, m *metadata.IssuerMetadata) {
	if h.imageEmbedder == nil || m == nil || len(m.CredentialConfigurationsSupported) == 0 {
		return
	}

	embedded, err := h.imageEmbedder.EmbedImages(ctx, m.CredentialConfigurationsSupported)
	if err != nil {
		// EmbedImages returns the input unchanged alongside its error, so the
		// issuer's own metadata still reaches the client.
		h.logger.Warn("Failed to embed images in issuer credential metadata", zap.Error(err))
		return
	}
	m.CredentialConfigurationsSupported = embedded
}
