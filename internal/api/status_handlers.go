package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

// maxStatusRequestBytes bounds the request body.
const maxStatusRequestBytes = 128 << 10

// StatusListsRequest is the request body of POST /status/v1/lists.
type StatusListsRequest struct {
	Lists []service.StatusListRequest `json:"lists"`
}

// StatusListsResponse is the response body of POST /status/v1/lists.
type StatusListsResponse struct {
	Results []service.StatusListResult `json:"results"`
}

// StatusLists handles POST /status/v1/lists: it returns the verified Token
// Status Lists the caller names (see service.StatusService and docs/API.md).
//
// Privacy: URIs reveal what the caller holds, so nothing here logs one or
// stores anything per user; the body is POSTed to keep URIs out of access logs.
func (h *Handlers) StatusLists(c *gin.Context) {
	if h.services.Status == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "STATUS_NOT_SUPPORTED",
			"message": "Status list verification is not configured",
		})
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxStatusRequestBytes)
	var req StatusListsRequest
	dec := json.NewDecoder(c.Request.Body)
	err := dec.Decode(&req)
	if err == nil && dec.More() {
		// Exactly one JSON value is allowed.
		err = errors.New("trailing data")
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "REQUEST_TOO_LARGE",
				"message": "Request body is too large",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "INVALID_REQUEST",
			"message": "Request body must be a JSON object with a 'lists' array of {uri, etag?} items",
		})
		return
	}

	// Only the tenant is passed on, never the user.
	tenantID, _ := h.getTenantID(c)
	results, err := h.services.Status.Lists(c.Request.Context(), string(tenantID), req.Lists)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrStatusTooManyLists):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "TOO_MANY_URIS",
				"message": "Too many lists in one request; ask for one to three at a time",
				"max":     h.services.Status.MaxLists(),
			})
		case errors.Is(err, service.ErrStatusInvalidRequest):
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "INVALID_REQUEST",
				"message": "Each item needs a uri; at least one list is required",
			})
		default:
			// Not logged: the error may carry a uri.
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "STATUS_CHECK_FAILED",
				"message": "Failed to process the status list request",
			})
		}
		return
	}

	setStatusCacheHeaders(c, results, time.Now())
	c.JSON(http.StatusOK, StatusListsResponse{Results: results})
}

// setStatusCacheHeaders sets private Cache-Control (max-age is the shortest
// remaining freshness, capped by ttl; no-store if any list is undetermined)
// and, for a single list, ETag.
func setStatusCacheHeaders(c *gin.Context, results []service.StatusListResult, now time.Time) {
	c.Header("Vary", "Authorization")
	maxAge := int64(-1)
	for _, r := range results {
		if r.State == service.StatusStateUndetermined || r.FreshUntil == nil {
			c.Header("Cache-Control", "private, no-store")
			return
		}
		remaining := *r.FreshUntil - now.Unix()
		if r.TTL != nil && *r.TTL < remaining {
			remaining = *r.TTL
		}
		if remaining < 0 {
			remaining = 0
		}
		if maxAge < 0 || remaining < maxAge {
			maxAge = remaining
		}
	}
	c.Header("Cache-Control", "private, max-age="+strconv.FormatInt(maxAge, 10))
	if len(results) == 1 && results[0].ETag != "" {
		c.Header("ETag", results[0].ETag)
	}
}
