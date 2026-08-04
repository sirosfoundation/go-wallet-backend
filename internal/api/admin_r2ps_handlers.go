package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-siros-set/set"
)

// R2PSListKeys lists all WSCD public keys, optionally filtered by client_id.
// GET /admin/r2ps/keys?client_id=...
func (h *AdminHandlers) R2PSListKeys(c *gin.Context) {
	clientID := c.Query("client_id")

	keys, err := h.r2psClient.ListKeys(c.Request.Context(), clientID)
	if err != nil {
		h.logger.Error("failed to list R2PS keys", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to query R2PS service"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"count": len(keys), "keys": keys})
}

// R2PSGetKey returns a single WSCD public key by kid.
// GET /admin/r2ps/keys/:kid
func (h *AdminHandlers) R2PSGetKey(c *gin.Context) {
	kid := c.Param("kid")

	key, err := h.r2psClient.GetKey(c.Request.Context(), kid)
	if err != nil {
		h.logger.Error("failed to get R2PS key", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to query R2PS service"})
		return
	}
	if key == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}
	c.JSON(http.StatusOK, key)
}

// R2PSListStatuses lists all status entries for a given category.
// GET /admin/r2ps/statuses/:category
func (h *AdminHandlers) R2PSListStatuses(c *gin.Context) {
	category := c.Param("category")

	entries, err := h.r2psClient.ListStatuses(c.Request.Context(), category)
	if err != nil {
		h.logger.Error("failed to list R2PS statuses", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to query R2PS service"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"category": category,
		"count":    len(entries),
		"entries":  entries,
	})
}

// R2PSGetStatus returns the status for a specific index in a category.
// GET /admin/r2ps/status/:category/:idx
func (h *AdminHandlers) R2PSGetStatus(c *gin.Context) {
	category := c.Param("category")
	idx, err := strconv.Atoi(c.Param("idx"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid index"})
		return
	}

	entry, err := h.r2psClient.GetStatus(c.Request.Context(), category, idx)
	if err != nil {
		h.logger.Error("failed to get R2PS status", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to query R2PS service"})
		return
	}
	if entry == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "status entry not found"})
		return
	}
	c.JSON(http.StatusOK, entry)
}

// R2PSSetStatus updates the status for a specific index (revoke/suspend/reactivate).
// PUT /admin/r2ps/status/:category/:idx
func (h *AdminHandlers) R2PSSetStatus(c *gin.Context) {
	category := c.Param("category")
	idx, err := strconv.Atoi(c.Param("idx"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid index"})
		return
	}

	var req struct {
		Status *int   `json:"status" binding:"required"` // 0=valid, 1=revoked, 2=suspended
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be 0 (valid), 1 (revoked), or 2 (suspended)"})
		return
	}
	if req.Status == nil || *req.Status < 0 || *req.Status > 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status must be 0 (valid), 1 (revoked), or 2 (suspended)"})
		return
	}

	if err := h.r2psClient.SetStatus(c.Request.Context(), category, idx, *req.Status); err != nil {
		h.logger.Error("failed to set R2PS status", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to update R2PS status"})
		return
	}

	h.emitAudit(set.EventR2PSStatusChange, fmt.Sprintf("%s/%d", category, idx), map[string]any{
		"status": *req.Status,
		"reason": req.Reason,
	})

	c.JSON(http.StatusOK, gin.H{
		"category": category,
		"idx":      idx,
		"status":   *req.Status,
	})
}
