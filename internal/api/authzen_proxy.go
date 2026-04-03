// Package api provides HTTP handlers for the wallet backend.
package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/authz"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"go.uber.org/zap"
)

// AuthZENProxyHandler handles AuthZEN evaluation requests by proxying to a PDP.
// It provides an authenticated endpoint for the frontend to make trust decisions.
type AuthZENProxyHandler struct {
	cfg        *config.AuthZENProxyConfig
	authorizer authz.Authorizer
	clients    map[string]*authzenclient.Client
	clientsMu  sync.RWMutex
	httpClient *http.Client
	logger     *zap.Logger
}

// NewAuthZENProxyHandler creates a new AuthZEN proxy handler.
func NewAuthZENProxyHandler(cfg *config.AuthZENProxyConfig, authorizer authz.Authorizer, httpClient *http.Client, logger *zap.Logger) *AuthZENProxyHandler {
	return &AuthZENProxyHandler{
		cfg:        cfg,
		authorizer: authorizer,
		clients:    make(map[string]*authzenclient.Client),
		httpClient: httpClient,
		logger:     logger.Named("authzen-proxy"),
	}
}

// getClient returns a cached AuthZEN client for the given PDP URL, or creates one.
// Thread-safe: uses RWMutex for concurrent access protection.
func (h *AuthZENProxyHandler) getClient(pdpURL string) (*authzenclient.Client, error) {
	// Fast path: read lock to check cache
	h.clientsMu.RLock()
	if client, ok := h.clients[pdpURL]; ok {
		h.clientsMu.RUnlock()
		return client, nil
	}
	h.clientsMu.RUnlock()

	// Slow path: write lock to create client
	h.clientsMu.Lock()
	defer h.clientsMu.Unlock()

	// Double-check after acquiring write lock
	if client, ok := h.clients[pdpURL]; ok {
		return client, nil
	}

	client := authzenclient.New(pdpURL, authzenclient.WithHTTPClient(h.httpClient))
	h.clients[pdpURL] = client
	return client, nil
}

// Evaluate handles POST /v1/evaluate
//
// This endpoint proxies AuthZEN evaluation requests to the configured PDP after:
// 1. Validating the JWT token (via middleware)
// 2. Authorizing the query using spocp policies
// 3. Forwarding to the tenant's configured PDP
//
// Request body: gotrust.EvaluationRequest
// Response: gotrust.EvaluationResponse
func (h *AuthZENProxyHandler) Evaluate(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.Timeout)*time.Second)
	defer cancel()

	// Get tenant from context (set by AuthMiddleware from JWT)
	// Use safe type assertion to avoid panic from misconfigured middleware
	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		h.logger.Warn("tenant_id not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id not found"})
		return
	}
	tenantID, ok := tenantIDVal.(string)
	if !ok {
		h.logger.Error("tenant_id is not a string", zap.Any("tenant_id", tenantIDVal))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Get user ID for audit logging
	userIDVal, _ := c.Get("user_id")
	userID := fmt.Sprintf("%v", userIDVal)

	// Parse the evaluation request
	var req gotrust.EvaluationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Debug("invalid evaluation request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Authorize the query using spocp
	authzReq := &authz.AuthorizationRequest{
		TenantID: tenantID,
		UserID:   userID,
		Request:  &req,
	}

	if err := h.authorizer.Authorize(ctx, authzReq); err != nil {
		h.logger.Info("query authorization denied",
			zap.String("tenant_id", tenantID),
			zap.String("user_id", userID),
			zap.String("subject_id", req.Subject.ID),
			zap.String("action", getActionName(&req)),
			zap.Error(err),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "query not authorized"})
		return
	}

	// Get the PDP URL for this tenant
	pdpURL := h.getPDPURL(tenantID)
	if pdpURL == "" {
		h.logger.Warn("no PDP configured for tenant", zap.String("tenant_id", tenantID))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "trust evaluation not configured"})
		return
	}

	// Get or create client for this PDP
	client, err := h.getClient(pdpURL)
	if err != nil {
		h.logger.Error("failed to create AuthZEN client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Forward the request to the PDP
	resp, err := client.Evaluate(ctx, &req)
	if err != nil {
		h.logger.Error("PDP evaluation failed",
			zap.String("tenant_id", tenantID),
			zap.String("pdp_url", pdpURL),
			zap.Error(err),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "trust evaluation service unavailable"})
		return
	}

	// Log the decision for audit
	h.logger.Info("trust evaluation completed",
		zap.String("tenant_id", tenantID),
		zap.String("user_id", userID),
		zap.String("subject_id", req.Subject.ID),
		zap.String("action", getActionName(&req)),
		zap.Bool("decision", resp.Decision),
	)

	c.JSON(http.StatusOK, resp)
}

// Resolve handles POST /v1/resolve
//
// This is a convenience endpoint for resolution-only requests (no key validation).
// It's used for DID document and metadata resolution.
//
// Request body: { "subject_id": "did:web:example.com" }
// Response: gotrust.EvaluationResponse with trust_metadata
func (h *AuthZENProxyHandler) Resolve(c *gin.Context) {
	// Check if resolution is enabled
	if !h.cfg.AllowResolution {
		c.JSON(http.StatusForbidden, gin.H{"error": "resolution disabled"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.Timeout)*time.Second)
	defer cancel()

	// Get tenant from context (use safe type assertion)
	tenantIDVal, exists := c.Get("tenant_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant_id not found"})
		return
	}
	tenantID, ok := tenantIDVal.(string)
	if !ok {
		h.logger.Error("tenant_id is not a string", zap.Any("tenant_id", tenantIDVal))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Parse the resolve request
	var req struct {
		SubjectID string `json:"subject_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Build an evaluation request for resolution-only
	evalReq := &gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   req.SubjectID,
		},
		Resource: gotrust.Resource{
			Type: "resolution",
			ID:   req.SubjectID,
		},
	}

	// Authorize the query
	authzReq := &authz.AuthorizationRequest{
		TenantID: tenantID,
		Request:  evalReq,
	}
	if err := h.authorizer.Authorize(ctx, authzReq); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "query not authorized"})
		return
	}

	// Get PDP URL and forward
	pdpURL := h.getPDPURL(tenantID)
	if pdpURL == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "trust evaluation not configured"})
		return
	}

	client, err := h.getClient(pdpURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	resp, err := client.Evaluate(ctx, evalReq)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "resolution service unavailable"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// getPDPURL returns the PDP URL for the given tenant.
// TODO: Support per-tenant PDP configuration.
func (h *AuthZENProxyHandler) getPDPURL(tenantID string) string {
	// For now, use the global PDP URL
	// Future: look up per-tenant configuration
	_ = tenantID
	return h.cfg.PDPURL
}

// getActionName safely extracts the action name from a request.
func getActionName(req *gotrust.EvaluationRequest) string {
	if req.Action != nil {
		return req.Action.Name
	}
	return ""
}

// TenantPDPConfig holds per-tenant PDP configuration.
// This will be stored in the tenant configuration.
type TenantPDPConfig struct {
	// PDPURL is the AuthZEN PDP URL for this tenant.
	PDPURL string `json:"pdp_url" bson:"pdp_url"`
	// Enabled indicates whether trust evaluation is enabled for this tenant.
	Enabled bool `json:"enabled" bson:"enabled"`
}

// GetTenantPDPConfig retrieves the PDP configuration for a tenant.
// This is a placeholder for future per-tenant configuration.
func GetTenantPDPConfig(ctx context.Context, tenant *domain.Tenant) *TenantPDPConfig {
	// Future: read from tenant.Config or a separate collection
	return nil
}
