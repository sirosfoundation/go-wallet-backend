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

// TenantLookup is an interface for looking up tenant configuration.
// This abstraction allows for easier testing.
type TenantLookup interface {
	GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error)
}

// AuthZENProxyHandler handles AuthZEN evaluation requests by proxying to a PDP.
// It provides an authenticated endpoint for the frontend to make trust decisions.
type AuthZENProxyHandler struct {
	cfg          *config.AuthZENProxyConfig
	authorizer   authz.Authorizer
	tenantLookup TenantLookup
	clients      map[string]*authzenclient.Client
	clientsMu    sync.RWMutex
	httpClient   *http.Client
	logger       *zap.Logger
}

// NewAuthZENProxyHandler creates a new AuthZEN proxy handler.
// The tenantLookup parameter is optional - if nil, per-tenant configuration is disabled.
func NewAuthZENProxyHandler(cfg *config.AuthZENProxyConfig, authorizer authz.Authorizer, tenantLookup TenantLookup, httpClient *http.Client, logger *zap.Logger) *AuthZENProxyHandler {
	return &AuthZENProxyHandler{
		cfg:          cfg,
		authorizer:   authorizer,
		tenantLookup: tenantLookup,
		clients:      make(map[string]*authzenclient.Client),
		httpClient:   httpClient,
		logger:       logger.Named("authzen-proxy"),
	}
}

// NewAuthZENProxyHandlerFromConfig initializes an AuthZENProxyHandler from the global config.
//
// It handles the full initialization sequence: applying defaults, creating the SPOCP
// authorizer (with a production fail-closed guard), resolving the PDP URL, and wiring
// the handler. Returns (nil, nil) when AuthZEN proxy is disabled.
//
// The caller is responsible for closing any resources (e.g. storage) on error.
func NewAuthZENProxyHandlerFromConfig(cfg *config.Config, tenantLookup TenantLookup, httpClient *http.Client, logger *zap.Logger) (*AuthZENProxyHandler, error) {
	if !cfg.AuthZENProxy.Enabled {
		return nil, nil
	}

	// Apply config defaults
	cfg.AuthZENProxy.SetDefaults()

	// Create SPOCP authorizer
	spocpCfg := &authz.SPOCPConfig{
		RulesFile: cfg.AuthZENProxy.RulesFile,
	}
	authorizer, err := authz.NewSPOCPAuthorizer(spocpCfg, logger)
	if err != nil {
		logger.Error("Failed to initialize SPOCP authorizer", zap.Error(err))
		authorizer = nil
	}

	// Fail-closed: if SPOCP initialization failed in production, refuse to start
	var authorizerInterface authz.Authorizer
	if authorizer != nil {
		authorizerInterface = authorizer
	} else {
		// Production guard: NoOpAuthorizer cannot be used in release mode
		if gin.Mode() == gin.ReleaseMode {
			return nil, fmt.Errorf("SPOCP authorizer failed to initialize and NoOpAuthorizer cannot be used in production (GIN_MODE=release). Configure a valid rules file or set GIN_MODE=debug for development")
		}
		logger.Warn("Using NoOpAuthorizer - ALL requests will be authorized. This is only safe for development!")
		authorizerInterface = authz.NoOpAuthorizer{}
	}

	// Get effective PDP URL and set it on the config so the handler uses it
	pdpURL := cfg.AuthZENProxy.GetPDPURL(cfg.Trust.GetPDPURL())
	cfg.AuthZENProxy.PDPURL = pdpURL

	handler := NewAuthZENProxyHandler(
		&cfg.AuthZENProxy,
		authorizerInterface,
		tenantLookup,
		httpClient,
		logger,
	)

	logger.Info("AuthZEN proxy initialized",
		zap.String("pdp_url", pdpURL),
		zap.String("rules_file", cfg.AuthZENProxy.RulesFile),
	)

	return handler, nil
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
			zap.String("action", getActionName(&req)),
			zap.Error(err),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "query not authorized"})
		return
	}

	// Get the PDP URL for this tenant
	pdpURL, err := h.getPDPURL(ctx, tenantID)
	if err != nil {
		h.logger.Error("tenant lookup failed",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tenant configuration unavailable"})
		return
	}
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

	// Log the decision for audit (no user PII at INFO level)
	h.logger.Info("trust evaluation completed",
		zap.String("tenant_id", tenantID),
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
	pdpURL, err := h.getPDPURL(ctx, tenantID)
	if err != nil {
		h.logger.Error("tenant lookup failed",
			zap.String("tenant_id", tenantID),
			zap.Error(err),
		)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "tenant configuration unavailable"})
		return
	}
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
// If the tenant has a per-tenant PDP configured (in TrustConfig.PDPURL),
// that URL is used. Otherwise, falls back to the global configuration.
//
// Returns an error if tenant lookup fails and FailOpenOnTenantLookupError is false.
func (h *AuthZENProxyHandler) getPDPURL(ctx context.Context, tenantID string) (string, error) {
	// Try to get per-tenant configuration if tenant lookup is available
	if h.tenantLookup != nil && tenantID != "" {
		tenant, err := h.tenantLookup.GetByID(ctx, domain.TenantID(tenantID))
		if err != nil {
			h.logger.Warn("failed to look up tenant for PDP URL",
				zap.String("tenant_id", tenantID),
				zap.Error(err))
			// Fail closed by default - return error unless configured to fail open
			if !h.cfg.FailOpenOnTenantLookupError {
				return "", fmt.Errorf("tenant lookup failed: %w", err)
			}
			// Fall through to global config if fail-open is enabled
		} else if tenant != nil && tenant.TrustConfig.PDPURL != "" {
			h.logger.Debug("using per-tenant PDP URL",
				zap.String("tenant_id", tenantID),
				zap.String("pdp_url", tenant.TrustConfig.PDPURL))
			return tenant.TrustConfig.PDPURL, nil
		}
	}

	// Fall back to global PDP URL
	return h.cfg.PDPURL, nil
}

// getActionName safely extracts the action name from a request.
func getActionName(req *gotrust.EvaluationRequest) string {
	if req.Action != nil {
		return req.Action.Name
	}
	return ""
}
