// Package api provides HTTP handlers for the wallet backend.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/authzenclient"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/authz"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	"go.uber.org/zap"
)

// IssuerMetadataResolver resolves OpenID4VCI issuer metadata from a credential issuer URL.
type IssuerMetadataResolver interface {
	ResolveWithInfo(ctx context.Context, issuerURL string) (*issuermetadata.ResolveResult, error)
}

// TenantLookup is an interface for looking up tenant configuration.
// This abstraction allows for easier testing.
type TenantLookup interface {
	GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error)
}

// IssuerLookup is an interface for looking up registered credential issuers.
// This abstraction allows for easier testing.
type IssuerLookup interface {
	GetByIdentifier(ctx context.Context, tenantID domain.TenantID, identifier string) (*domain.CredentialIssuer, error)
}

// RegisteredIssuerInfo contains issuer registration data from the backend storage.
// It is included in the /v1/resolve response context when the issuer is found in storage.
type RegisteredIssuerInfo struct {
	ClientID       string             `json:"client_id,omitempty"`
	Visible        bool               `json:"visible"`
	TrustStatus    domain.TrustStatus `json:"trust_status,omitempty"`
	TrustFramework string             `json:"trust_framework,omitempty"`
}

// resolveURLResponse is the response type for /v1/resolve URL subject requests.
// It extends gotrust.EvaluationResponse with optional registered issuer info.
type resolveURLResponse struct {
	gotrust.EvaluationResponse
	RegisteredIssuer *RegisteredIssuerInfo `json:"registered_issuer,omitempty"`
}

// AuthZENProxyHandler handles AuthZEN evaluation requests by proxying to a PDP.
// It provides an authenticated endpoint for the frontend to make trust decisions.
type AuthZENProxyHandler struct {
	cfg              *config.AuthZENProxyConfig
	authorizer       authz.Authorizer
	tenantLookup     TenantLookup
	issuerLookup     IssuerLookup
	metadataResolver IssuerMetadataResolver
	clients          map[string]*authzenclient.Client
	clientsMu        sync.RWMutex
	httpClient       *http.Client
	allowHTTP        bool // when true, plain HTTP URLs are permitted for logos and jwks_uri (test/dev envs)
	logger           *zap.Logger
}

// NewAuthZENProxyHandler creates a new AuthZEN proxy handler.
// The tenantLookup and issuerLookup parameters are optional - if nil, the respective
// per-tenant features are disabled.
// The metadataResolver is required for URL subject resolution on /v1/resolve.
func NewAuthZENProxyHandler(cfg *config.AuthZENProxyConfig, authorizer authz.Authorizer, tenantLookup TenantLookup, issuerLookup IssuerLookup, metadataResolver IssuerMetadataResolver, httpClient *http.Client, logger *zap.Logger) *AuthZENProxyHandler {
	return &AuthZENProxyHandler{
		cfg:              cfg,
		authorizer:       authorizer,
		tenantLookup:     tenantLookup,
		issuerLookup:     issuerLookup,
		metadataResolver: metadataResolver,
		clients:          make(map[string]*authzenclient.Client),
		httpClient:       httpClient,
		logger:           logger.Named("authzen-proxy"),
	}
}

// NewAuthZENProxyHandlerFromConfig initializes an AuthZENProxyHandler from the global config.
//
// It handles the full initialization sequence: applying defaults, creating the SPOCP
// authorizer (with a production fail-closed guard), resolving the PDP URL, and wiring
// the handler. Returns (nil, nil) when AuthZEN proxy is disabled.
//
// The caller is responsible for closing any resources (e.g. storage) on error.
func NewAuthZENProxyHandlerFromConfig(cfg *config.Config, tenantLookup TenantLookup, issuerLookup IssuerLookup, metadataResolver IssuerMetadataResolver, httpClient *http.Client, logger *zap.Logger) (*AuthZENProxyHandler, error) {
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

	// Invariant: when resolution is enabled, the resolver must be non-nil.
	// A nil resolver here means the caller failed to construct it — that is a
	// programming error, not a runtime condition, so panic immediately rather
	// than silently serving requests without metadata resolution.
	if cfg.AuthZENProxy.AllowResolution && metadataResolver == nil {
		panic("authzen: AllowResolution=true but metadataResolver is nil — check server startup")
	}

	handler := NewAuthZENProxyHandler(
		&cfg.AuthZENProxy,
		authorizerInterface,
		tenantLookup,
		issuerLookup,
		metadataResolver,
		httpClient,
		logger,
	)
	// Propagate the HTTP client's allow_http setting so that logo and
	// jwks_uri fetches respect the same policy as metadata resolution.
	handler.allowHTTP = cfg.HTTPClient.AllowHTTP || cfg.HTTPClient.InsecureSkipVerify

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
// This endpoint resolves issuer metadata and evaluates trust. For URL subjects,
// metadata is resolved locally and key material is extracted, then sent to the PDP
// for trust evaluation. For key subjects, the request is proxied directly to the PDP.
//
// Request body: { "subject_id": "https://issuer.example.com", "subject_type": "url" }
// Response: gotrust.EvaluationResponse with trust_metadata containing issuer metadata
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
		SubjectID    string `json:"subject_id" binding:"required"`
		SubjectType  string `json:"subject_type"`  // "key" (default) or "url"
		ResourceType string `json:"resource_type"` // e.g. "credential_issuer" (default for url subjects)
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Determine subject type: explicit field takes precedence, default is "key".
	subjectType := req.SubjectType
	if subjectType == "" {
		subjectType = "key"
	}
	if subjectType != "key" && subjectType != "url" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "subject_type must be 'key' or 'url'"})
		return
	}

	// When subject_type is "url", validate that subject_id is a well-formed HTTPS URL.
	if subjectType == "url" {
		u, err := url.Parse(req.SubjectID)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "subject_id must be a valid HTTPS URL when subject_type is 'url'"})
			return
		}
	}

	// Determine resource type based on subject type and optional override.
	resourceType := req.ResourceType
	if resourceType == "" {
		if subjectType == "url" {
			resourceType = "credential_issuer"
		} else {
			resourceType = "resolution"
		}
	}

	// Build an evaluation request for authorization check
	evalReq := &gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: subjectType,
			ID:   req.SubjectID,
		},
		Resource: gotrust.Resource{
			Type: resourceType,
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

	// For URL subjects, resolve locally via the metadata resolver when available.
	// Fall back to proxying to the PDP when no resolver is configured so that
	// deployments without AllowResolution retain backward-compatible behaviour.
	if subjectType == "url" {
		if h.metadataResolver == nil {
			h.logger.Debug("no metadata resolver configured for URL subject — proxying to PDP")
			h.proxyToPDP(c, ctx, tenantID, evalReq)
			return
		}
		h.resolveURLSubject(c, ctx, tenantID, req.SubjectID)
		return
	}

	// For key subjects, proxy to PDP
	h.proxyToPDP(c, ctx, tenantID, evalReq)
}

// resolveURLSubject handles the local resolution path for URL subjects.
// It resolves metadata, extracts key material, evaluates trust via PDP,
// and returns a composite response. Logo inlining is performed when:
//   - metadata is unsigned (no signed_metadata field), OR
//   - metadata is signed AND the PDP returns trusted
//
// If metadata is signed but untrusted, an error is returned.
func (h *AuthZENProxyHandler) resolveURLSubject(c *gin.Context, ctx context.Context, tenantID, issuerURL string) {
	// Step 1: Resolve issuer metadata locally
	result, err := h.metadataResolver.ResolveWithInfo(ctx, issuerURL)
	if err != nil {
		h.logger.Error("metadata resolution failed",
			zap.String("issuer_url", issuerURL),
			zap.Error(err),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "issuer metadata resolution failed"})
		return
	}

	// Determine if metadata is signed (application/jwt or signed_metadata field).
	// The resolver sets Signed=true for both cases.
	metadataIsSigned := result.Signed

	// Step 2: Extract key material from metadata
	keyMaterial, signedButFailed := h.extractKeyMaterial(ctx, result.Metadata)

	// For application/jwt responses the JWT payload claims don't carry
	// signed_metadata/jwks fields, so key material is surfaced via the resolver result.
	if keyMaterial == nil && !signedButFailed && result.SignerKeyMaterial != nil {
		km := result.SignerKeyMaterial
		keyMaterial = &trust.KeyMaterial{Type: km.Type, X5C: km.X5C, JWK: km.JWK}
	}

	// If signed_metadata was present but JWT verification failed, reject immediately.
	// Returning metadata with a claimed-but-unverifiable signature would be misleading.
	if metadataIsSigned && signedButFailed {
		h.logger.Error("signed_metadata JWT verification failed, rejecting request",
			zap.String("issuer_url", issuerURL))
		c.JSON(http.StatusBadGateway, gin.H{"error": "signed issuer metadata could not be verified"})
		return
	}

	// Step 3: Evaluate trust via PDP using extracted key material
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

	// Build trust evaluation request with key material.
	// Action is set to "credential-issuer" so PDP policy can distinguish
	// issuer trust evaluation from verifier or general resolution requests.
	trustReq := &gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   issuerURL,
		},
		Resource: gotrust.Resource{
			ID: issuerURL,
		},
		Action: &gotrust.Action{Name: "credential-issuer"},
	}

	if keyMaterial != nil {
		trustReq.Resource.Type = keyMaterial.Type
		switch keyMaterial.Type {
		case "x5c":
			keys := make([]interface{}, len(keyMaterial.X5C))
			for i, cert := range keyMaterial.X5C {
				keys[i] = cert
			}
			trustReq.Resource.Key = keys
		case "jwk":
			trustReq.Resource.Key = trust.NormalizeJWKS(keyMaterial.JWK)
		}
	} else {
		// No key material could be extracted. Set resource type to "resolution"
		// so the PDP receives a well-formed request and can apply a
		// resolution-only policy rather than a trust-evaluation policy.
		trustReq.Resource.Type = "resolution"
	}

	trustResp, err := client.Evaluate(ctx, trustReq)
	if err != nil {
		h.logger.Error("PDP trust evaluation failed",
			zap.String("issuer_url", issuerURL),
			zap.String("pdp_url", pdpURL),
			zap.Error(err),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "trust evaluation service unavailable"})
		return
	}

	// Step 4: Enforce trust policy for signed metadata
	// Signed but untrusted metadata is rejected — the issuer claims a binding
	// that the trust registry does not recognize, so we must not return it.
	if metadataIsSigned && !trustResp.Decision {
		h.logger.Warn("signed metadata from untrusted issuer rejected",
			zap.String("issuer_url", issuerURL),
		)
		c.JSON(http.StatusForbidden, gin.H{"error": "issuer metadata is signed but issuer is not trusted"})
		return
	}

	// Step 5: Inline logo images as data: URIs.
	// Inlining is safe when metadata is unsigned (display-only, no trust claim)
	// or when signed metadata has been verified as trusted.
	if !metadataIsSigned || trustResp.Decision {
		h.inlineLogos(ctx, result.Metadata)
	}

	// Step 6: Return composite response with trust decision and metadata
	resp := &resolveURLResponse{
		EvaluationResponse: gotrust.EvaluationResponse{
			Decision: trustResp.Decision,
			Context: &gotrust.EvaluationResponseContext{
				TrustMetadata: result.Metadata,
			},
		},
	}
	if trustResp.Context != nil && trustResp.Context.Reason != nil {
		resp.Context.Reason = trustResp.Context.Reason
	}

	// Step 7: Enrich response with registered issuer info from backend storage.
	// Scoped strictly to the authenticated tenant — tenantID is enforced non-empty
	// by Resolve() before this function is called, preventing cross-tenant access.
	// If the issuer is not registered in this tenant's storage, the field is omitted.
	if h.issuerLookup != nil {
		if reg, err := h.issuerLookup.GetByIdentifier(ctx, domain.TenantID(tenantID), issuerURL); err == nil && reg != nil {
			resp.RegisteredIssuer = &RegisteredIssuerInfo{
				ClientID:       reg.ClientID,
				Visible:        reg.Visible,
				TrustStatus:    reg.TrustStatus,
				TrustFramework: reg.TrustFramework,
			}
		}
	}

	h.logger.Info("URL subject resolution completed",
		zap.String("tenant_id", tenantID),
		zap.String("issuer_url", issuerURL),
		zap.Bool("decision", trustResp.Decision),
		zap.Bool("signed", metadataIsSigned),
	)

	c.JSON(http.StatusOK, resp)
}

// proxyToPDP forwards an evaluation request directly to the PDP.
func (h *AuthZENProxyHandler) proxyToPDP(c *gin.Context, ctx context.Context, tenantID string, evalReq *gotrust.EvaluationRequest) {
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

// extractKeyMaterial extracts cryptographic key material from issuer metadata.
// It checks (in order): signed_metadata JWT, inline JWKS, jwks_uri.
// Returns (keyMaterial, signedButFailed) where signedButFailed is true only
// when a signed_metadata JWT was present but its embedded-key verification failed.
// Callers should treat signedButFailed=true as a hard error.
func (h *AuthZENProxyHandler) extractKeyMaterial(ctx context.Context, metadata map[string]interface{}) (*trust.KeyMaterial, bool) {
	// Check signed_metadata JWT
	if signedMetadata, ok := metadata["signed_metadata"].(string); ok && signedMetadata != "" {
		km, err := trust.VerifyJWTWithEmbeddedKey(signedMetadata)
		if err != nil {
			// If the JWT has no embedded key (x5c/jwk), fall through to
			// check jwks/jwks_uri for kid-based verification.
			if errors.Is(err, trust.ErrNoEmbeddedKey) {
				h.logger.Debug("signed_metadata JWT has no embedded key, falling through to jwks/jwks_uri",
					zap.Error(err))
			} else {
				h.logger.Error("signed_metadata JWT verification failed",
					zap.Error(err))
				return nil, true // signal to caller: signing was attempted but failed
			}
		} else {
			return km, false
		}
	}

	// Check inline JWKS
	if jwksRaw, ok := metadata["jwks"]; ok && jwksRaw != nil {
		// jwks may be a map or raw JSON depending on how it was resolved
		switch v := jwksRaw.(type) {
		case map[string]interface{}:
			return &trust.KeyMaterial{Type: "jwk", JWK: v}, false
		case string:
			var jwks interface{}
			if err := json.Unmarshal([]byte(v), &jwks); err == nil {
				return &trust.KeyMaterial{Type: "jwk", JWK: jwks}, false
			}
		}
	}

	// Check jwks_uri — HTTPS is required unless allowHTTP is set (test/dev environments).
	// This prevents SSRF via issuer-controlled jwks_uri pointing to internal services;
	// the httpClient's DialContext additionally blocks private/loopback IPs when AllowPrivateIPs=false.
	if jwksURI, ok := metadata["jwks_uri"].(string); ok && jwksURI != "" {
		parsed, err := url.Parse(jwksURI)
		if err != nil || (parsed.Scheme != "https" && (!h.allowHTTP || parsed.Scheme != "http")) {
			h.logger.Warn("Skipping jwks_uri with non-HTTPS scheme (SSRF protection)",
				zap.String("uri", jwksURI))
		} else {
			jwks, err := trust.FetchJWKS(ctx, jwksURI, h.httpClient)
			if err != nil {
				h.logger.Warn("Failed to fetch JWKS",
					zap.String("uri", jwksURI),
					zap.Error(err))
			} else {
				return &trust.KeyMaterial{Type: "jwk", JWK: jwks}, false
			}
		}
	}

	// No key material available
	return nil, false
}

// inlineLogos walks the metadata tree and replaces logo URIs with data: URIs.
// It modifies the metadata in place. Only HTTPS URLs are fetched; data: URIs
// are left unchanged.
func (h *AuthZENProxyHandler) inlineLogos(ctx context.Context, metadata map[string]interface{}) {
	// Inline logos in top-level display array
	if display, ok := metadata["display"].([]interface{}); ok {
		for _, d := range display {
			if dm, ok := d.(map[string]interface{}); ok {
				h.inlineLogoField(ctx, dm)
			}
		}
	}

	// Inline logos in credential_configurations_supported entries
	if ccs, ok := metadata["credential_configurations_supported"].(map[string]interface{}); ok {
		for _, ccRaw := range ccs {
			cc, ok := ccRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if display, ok := cc["display"].([]interface{}); ok {
				for _, d := range display {
					if dm, ok := d.(map[string]interface{}); ok {
						h.inlineLogoField(ctx, dm)
					}
				}
			}
		}
	}
}

// inlineLogoField replaces a logo.uri field with a data: URI if it's an HTTP(S) URL.
func (h *AuthZENProxyHandler) inlineLogoField(ctx context.Context, displayEntry map[string]interface{}) {
	logoRaw, ok := displayEntry["logo"]
	if !ok {
		return
	}
	logo, ok := logoRaw.(map[string]interface{})
	if !ok {
		return
	}
	uri, ok := logo["uri"].(string)
	if !ok || uri == "" {
		return
	}

	// Skip if already a data: URI
	if strings.HasPrefix(uri, "data:") {
		return
	}

	// Only fetch HTTPS URLs (enforce to prevent SSRF via issuer-controlled logo URIs).
	// Plain HTTP is permitted when allowHTTP is set (test/dev environments).
	parsed, err := url.Parse(uri)
	if err != nil || (parsed.Scheme != "https" && (!h.allowHTTP || parsed.Scheme != "http")) {
		return
	}

	dataURI, err := h.fetchAsDataURI(ctx, uri)
	if err != nil {
		h.logger.Debug("failed to inline logo",
			zap.String("uri", uri),
			zap.Error(err))
		return
	}
	logo["uri"] = dataURI
}

// fetchAsDataURI fetches a URL and returns its content as a data: URI.
// A copy of the shared HTTP client is used with CheckRedirect set to refuse
// any redirect that leaves HTTPS — this prevents a server from issuing a
// 3xx to a plain HTTP URL and bypassing the upstream scheme check.
func (h *AuthZENProxyHandler) fetchAsDataURI(ctx context.Context, imageURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, nil)
	if err != nil {
		return "", err
	}

	// Shallow-copy the client so we can set CheckRedirect without affecting
	// other concurrent users of h.httpClient (Transport is shared/safe).
	client := *h.httpClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" && (!h.allowHTTP || req.URL.Scheme != "http") {
			return fmt.Errorf("refusing redirect to non-HTTPS URL: %s", req.URL)
		}
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("logo fetch returned status %d", resp.StatusCode)
	}

	// Limit read to 1MB to prevent abuse. Read one extra byte to detect
	// truncation — if the body exceeds the limit, reject it rather than
	// returning a partial/corrupt data: URI.
	const maxLogoSize = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxLogoSize+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxLogoSize {
		return "", fmt.Errorf("logo response exceeds %d byte limit", maxLogoSize)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "image/png"
	}
	// Strip parameters from content type (e.g., charset)
	if idx := strings.Index(contentType, ";"); idx >= 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}

	return "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(body), nil
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
