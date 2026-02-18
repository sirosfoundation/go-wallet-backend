package registry

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// Handler handles HTTP requests for the registry
type Handler struct {
	store          *Store
	dynamicFetcher *DynamicFetcher
	imageEmbedder  *ImageEmbedder
	config         *DynamicCacheConfig
	logger         *zap.Logger

	// Debounced save mechanism
	saveCh chan struct{}
}

// NewHandler creates a new registry handler
func NewHandler(store *Store, config *DynamicCacheConfig, imageEmbedConfig *ImageEmbedConfig, logger *zap.Logger) *Handler {
	var dynamicFetcher *DynamicFetcher
	if config != nil && config.Enabled {
		dynamicFetcher = NewDynamicFetcher(config, logger)
	}
	var imageEmbedder *ImageEmbedder
	if imageEmbedConfig == nil || imageEmbedConfig.Enabled {
		imageEmbedder = NewImageEmbedder(imageEmbedConfig, logger)
	}
	h := &Handler{
		store:          store,
		dynamicFetcher: dynamicFetcher,
		imageEmbedder:  imageEmbedder,
		config:         config,
		logger:         logger,
		saveCh:         make(chan struct{}, 1),
	}
	// Start the debounced save worker
	go h.saveWorker()
	return h
}

// saveWorker runs in the background and coalesces save requests
func (h *Handler) saveWorker() {
	debounceDelay := 5 * time.Second
	timer := time.NewTimer(debounceDelay)
	timer.Stop() // Start with a stopped timer
	pendingSave := false

	for {
		select {
		case _, ok := <-h.saveCh:
			if !ok {
				// Channel closed, perform final save if pending
				timer.Stop()
				if pendingSave {
					if err := h.store.Save(); err != nil {
						h.logger.Error("failed to save store", zap.Error(err))
					}
				}
				return
			}
			// Request save, start/reset debounce timer
			if !pendingSave {
				pendingSave = true
				timer.Reset(debounceDelay)
			}
		case <-timer.C:
			if pendingSave {
				if err := h.store.Save(); err != nil {
					h.logger.Error("failed to save store after dynamic fetch", zap.Error(err))
				}
				pendingSave = false
			}
		}
	}
}

// requestSave signals that the store should be saved (debounced)
func (h *Handler) requestSave() {
	select {
	case h.saveCh <- struct{}{}:
	default:
		// Channel full, save already pending
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
				"detail":  "dynamic fetch failed",
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
			// Request debounced save to disk
			h.requestSave()
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
		data := entry.Metadata

		// Embed images if enabled
		if h.imageEmbedder != nil {
			embedded, err := h.imageEmbedder.EmbedImages(c.Request.Context(), data)
			if err != nil {
				h.logger.Warn("failed to embed images",
					zap.String("vct", entry.VCT),
					zap.Error(err),
				)
				// Continue with original data
			} else {
				data = embedded
			}
		}

		c.Data(http.StatusOK, "application/json", data)
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
