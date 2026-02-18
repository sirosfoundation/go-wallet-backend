package registry

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler handles HTTP requests for the registry
type Handler struct {
	store          *Store
	dynamicFetcher *DynamicFetcher
	config         *DynamicCacheConfig
	logger         *zap.Logger
}

// NewHandler creates a new registry handler
func NewHandler(store *Store, config *DynamicCacheConfig, logger *zap.Logger) *Handler {
	var dynamicFetcher *DynamicFetcher
	if config != nil && config.Enabled {
		dynamicFetcher = NewDynamicFetcher(config, logger)
	}
	return &Handler{
		store:          store,
		dynamicFetcher: dynamicFetcher,
		config:         config,
		logger:         logger,
	}
}

// GetTypeMetadata handles GET /type-metadata?vct=<vct-id>
// Returns the VCTM for the specified credential type
// If the VCT is not in the local store but is a valid URL, attempts dynamic fetch
func (h *Handler) GetTypeMetadata(c *gin.Context) {
	vctID := c.Query("vct")
	if vctID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "missing_parameter",
			"message": "vct query parameter is required",
		})
		return
	}

	entry, found := h.store.Get(vctID)

	// Check if we have a valid, non-expired entry
	if found && !entry.IsExpired() {
		h.serveEntry(c, entry)
		return
	}

	// If entry exists but is expired, or not found, try dynamic fetch
	if h.dynamicFetcher != nil && IsURL(vctID) {
		h.logger.Debug("attempting dynamic fetch",
			zap.String("vct", vctID),
			zap.Bool("existing_expired", found && entry.IsExpired()),
		)

		// Use existing entry for conditional request if available
		var existingEntry *VCTMEntry
		if found {
			existingEntry = entry
		}

		result, err := h.dynamicFetcher.Fetch(c.Request.Context(), vctID, existingEntry)
		if err != nil {
			h.logger.Warn("dynamic fetch failed",
				zap.String("vct", vctID),
				zap.Error(err),
			)
			// If we have an expired entry, serve it with a warning header
			if found {
				c.Header("X-Cache-Status", "stale")
				h.serveEntry(c, entry)
				return
			}
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "not_found",
				"message": "Credential type not found and could not be fetched",
				"vct":     vctID,
				"detail":  err.Error(),
			})
			return
		}

		// Handle 304 Not Modified
		if result.NotModified && existingEntry != nil {
			// Refresh the expiration time
			existingEntry.ExpiresAt = h.dynamicFetcher.calculateExpiresAt(nil)
			existingEntry.FetchedAt = existingEntry.ExpiresAt.Add(-h.config.DefaultTTL) // Approximate
			h.store.Set(vctID, existingEntry)
			c.Header("X-Cache-Status", "revalidated")
			h.serveEntry(c, existingEntry)
			return
		}

		// Store the new entry
		if result.Entry != nil {
			h.store.Set(vctID, result.Entry)
			// Save to disk asynchronously
			go func() {
				if err := h.store.Save(); err != nil {
					h.logger.Error("failed to save store after dynamic fetch", zap.Error(err))
				}
			}()
			c.Header("X-Cache-Status", "fetched")
			h.serveEntry(c, result.Entry)
			return
		}
	}

	// No entry found and dynamic fetch not applicable
	if !found {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Credential type not found",
			"vct":     vctID,
		})
		return
	}

	// Serve expired entry as last resort
	c.Header("X-Cache-Status", "stale")
	h.serveEntry(c, entry)
}

// serveEntry serves a VCTMEntry to the client
func (h *Handler) serveEntry(c *gin.Context, entry *VCTMEntry) {
	// Return the full VCTM metadata document if available
	if entry.Metadata != nil {
		c.Data(http.StatusOK, "application/json", entry.Metadata)
		return
	}

	// No metadata available, return basic info
	c.JSON(http.StatusOK, gin.H{
		"vct":          entry.VCT,
		"name":         entry.Name,
		"description":  entry.Description,
		"organization": entry.Organization,
	})
}

// ListCredentials handles GET /credentials
// Returns a list of all available credential types
func (h *Handler) ListCredentials(c *gin.Context) {
	entries := h.store.List()

	credentials := make([]gin.H, 0, len(entries))
	for _, entry := range entries {
		credentials = append(credentials, gin.H{
			"vct":          entry.VCT,
			"name":         entry.Name,
			"description":  entry.Description,
			"organization": entry.Organization,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"credentials": credentials,
		"total":       len(credentials),
	})
}

// GetStatus handles GET /status
// Returns the health and status of the registry
func (h *Handler) GetStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":       "ok",
		"credentials":  h.store.Count(),
		"source_url":   h.store.SourceURL(),
		"last_updated": h.store.LastUpdated().Format(http.TimeFormat),
	})
}

// RegisterRoutes registers all handler routes on the router
func (h *Handler) RegisterRoutes(r gin.IRouter) {
	r.GET("/type-metadata", h.GetTypeMetadata)
	r.GET("/credentials", h.ListCredentials)
	r.GET("/status", h.GetStatus)
}
