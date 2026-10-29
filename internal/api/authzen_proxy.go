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
	"github.com/sirosfoundation/go-trust/pkg/registry/didutil"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/pkg/authz"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuertrust"
	"github.com/sirosfoundation/go-wallet-backend/pkg/oidc"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
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
// It extends gotrust.EvaluationResponse with optional registered issuer info
// and authorization server metadata.
type resolveURLResponse struct {
	gotrust.EvaluationResponse
	RegisteredIssuer *RegisteredIssuerInfo `json:"registered_issuer,omitempty"`
	// IssuerEntitlement reports whether the provider is registered to issue
	// what it is offering, per ARF §6.6.2.3. Absent when the check was not
	// applicable. Note it is reported separately from Decision: the PDP answers
	// "is this issuer trusted", this answers "is it entitled to issue this",
	// and collapsing them would lose which one failed.
	IssuerEntitlement *issuertrust.Decision `json:"issuer_entitlement,omitempty"`
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
	// httpClient is used for external (user-visible) fetches: VCTM, credential offers, logos, jwks_uri.
	// SSRF restrictions are applied here because these URLs originate from user-supplied content.
	httpClient *http.Client
	// pdpClient is used exclusively for requests to operator-configured PDP endpoints.
	// SSRF dial restrictions are not applied because the PDP URL is operator-controlled.
	pdpClient *http.Client
	allowHTTP bool // when true, plain HTTP URLs are permitted for logos and jwks_uri (test/dev envs)
	logger    *zap.Logger
}

// NewAuthZENProxyHandler creates a new AuthZEN proxy handler.
// The tenantLookup and issuerLookup parameters are optional - if nil, the respective
// per-tenant features are disabled.
// The metadataResolver is required for URL subject resolution on /v1/resolve.
// httpClient is used for external/user-visible fetches (SSRF-protected).
// pdpClient is used for PDP requests (no SSRF restriction; URL is operator-configured).
func NewAuthZENProxyHandler(cfg *config.AuthZENProxyConfig, authorizer authz.Authorizer, tenantLookup TenantLookup, issuerLookup IssuerLookup, metadataResolver IssuerMetadataResolver, httpClient *http.Client, pdpClient *http.Client, logger *zap.Logger) *AuthZENProxyHandler {
	return &AuthZENProxyHandler{
		cfg:              cfg,
		authorizer:       authorizer,
		tenantLookup:     tenantLookup,
		issuerLookup:     issuerLookup,
		metadataResolver: metadataResolver,
		clients:          make(map[string]*authzenclient.Client),
		httpClient:       httpClient,
		pdpClient:        pdpClient,
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

	// Build a separate client for PDP calls. This client:
	// - does NOT use a proxy (PDP is an internal service, reached directly)
	// - does NOT apply SSRF dial restrictions (PDP URL is operator-controlled)
	// - uses PDP-specific TLS settings from cfg.Trust (CACertPath, InsecureSkipVerify)
	pdpClient, err := cfg.Trust.NewPDPHTTPClient(0)
	if err != nil {
		return nil, fmt.Errorf("authzen: failed to create PDP HTTP client: %w", err)
	}
	handler := NewAuthZENProxyHandler(
		&cfg.AuthZENProxy,
		authorizerInterface,
		tenantLookup,
		issuerLookup,
		metadataResolver,
		httpClient,
		pdpClient,
		logger,
	)
	// Propagate the HTTP client's allow_http setting so that logo and
	// jwks_uri fetches respect the same policy as metadata resolution.
	handler.allowHTTP = cfg.HTTPClient.AllowsPlaintext()

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

	client := authzenclient.New(pdpURL, authzenclient.WithHTTPClient(h.pdpClient))
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

	// Get tenant from context (set by TokenAuthMiddleware from the token)
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

	// Get user ID for audit logging. Not set at all for anonymous requests
	// (see TokenAuthMiddleware) - "" (rather than the fmt.Sprintf("<nil>")
	// a bare type assertion on the missing key would otherwise produce)
	// keeps this readable in logs and matches the pre-existing convention
	// used elsewhere in this codebase for "no identity" callers.
	var userID string
	if v, exists := c.Get("user_id"); exists {
		userID = fmt.Sprintf("%v", v)
	}

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
	if !validateEvaluationRequest(c, &req) {
		return
	}
	resp, err := client.Evaluate(ctx, &req)
	if err != nil {
		h.logger.Error("PDP evaluation failed",
			zap.String("tenant_id", tenantID),
			zap.String("pdp_url", pdpURL),
			zap.Error(err),
		)
		h.writePDPError(c, ctx, err, "trust evaluation service unavailable")
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
// This endpoint resolves metadata and evaluates trust. For URL subjects,
// the behavior depends on the resource_type field:
//
//   - "credential_issuer" (default for URL subjects): resolves issuer metadata
//     locally, extracts key material, evaluates trust via PDP, and returns
//     a composite response with decision and trust_metadata.
//   - "oauth-authorization-server": fetches RFC 8414 authorization server
//     metadata. No trust evaluation is performed (decision is always false).
//
// For key subjects, the request is proxied directly to the PDP.
//
// Request body:
//
//	{
//	  "subject_id": "https://issuer.example.com",
//	  "subject_type": "url",
//	  "resource_type": "credential_issuer"  // optional, defaults per subject_type
//	}
//
// Response: gotrust.EvaluationResponse with trust_metadata containing resolved metadata
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
		SubjectID       string   `json:"subject_id" binding:"required"`
		SubjectType     string   `json:"subject_type"`     // "key" (default) or "url"
		ResourceType    string   `json:"resource_type"`    // e.g. "credential_issuer" (default for url subjects)
		CredentialTypes []string `json:"credential_types"` // optional credential type filter (e.g. VCT values)
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

	// When subject_type is "url", validate that subject_id is a well-formed
	// HTTPS URL. Plain HTTP is permitted when allowHTTP is set (test/dev
	// environments) - same escape hatch every other scheme check in this
	// file already honors (jwks_uri, logo URLs, proxy dispatch); this one
	// was missed, so an http:// issuer (e.g. docker-compose's
	// http://vc-apigw:8080) always 400ed here before reaching any of those.
	if subjectType == "url" {
		u, err := url.Parse(req.SubjectID)
		if err != nil || u.Host == "" || (u.Scheme != "https" && (!h.allowHTTP || u.Scheme != "http")) {
			// Message tracks the scheme actually accepted, so an operator
			// running with allow_http isn't told to use HTTPS for a URL that
			// would have been fine over HTTP.
			msg := "subject_id must be a valid HTTPS URL when subject_type is 'url'"
			if h.allowHTTP {
				msg = "subject_id must be a valid HTTPS or HTTP URL (allow_http is enabled) when subject_type is 'url'"
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": msg})
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

	// Attach credential_types as action.parameters so they reach the PDP
	// on all code paths (proxy fallback, key subjects, URL resolution).
	if len(req.CredentialTypes) > 0 {
		evalReq.Action = &gotrust.Action{
			Name: resourceType,
			Parameters: map[string]interface{}{
				"credential_types": req.CredentialTypes,
			},
		}
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

	// For URL subjects, dispatch based on resource type
	if subjectType == "url" {
		if resourceType == "credential_offer_uri" {
			h.resolveCredentialOfferURI(c, ctx, req.SubjectID)
			return
		}
		// Allowlist: only credential_issuer and oauth-authorization-server are
		// valid beyond this point. An unknown resource_type would silently
		// fall through to credential-issuer resolution, creating a
		// policy-bypass surface if SPOCP rules are permissive.
		//
		// oauth-authorization-server was added below (the switch case calling
		// resolveAuthorizationServerMetadata) without updating this allowlist,
		// making that case dead code - every oauth-authorization-server
		// request 400ed here first. Confirmed live: OpenID4VCIHelper's
		// getAuthorizationServerMetadata (used to decide whether to PAR a
		// credential-issuance flow) always got this 400, so
		// pushed_authorization_request_endpoint was never seen even when the
		// issuer's real discovery document advertised one and required PAR -
		// the wallet fell back to an un-PARed authorize redirect instead.
		if resourceType != "credential_issuer" && resourceType != "oauth-authorization-server" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported resource_type for URL subjects: %s", resourceType)})
			return
		}
		// Resolve as credential issuer (fetches /.well-known/openid-credential-issuer)
		if h.metadataResolver == nil {
			h.logger.Debug("no metadata resolver configured for URL subject — proxying to PDP")
			h.proxyToPDP(c, ctx, tenantID, evalReq)
			return
		}
		switch resourceType {
		case "oauth-authorization-server":
			h.resolveAuthorizationServerMetadata(c, ctx, tenantID, req.SubjectID)
		default:
			h.resolveURLSubject(c, ctx, tenantID, req.SubjectID, req.CredentialTypes)
		}
		return
	}

	// For key subjects with resource_type=credential_issuer
	if subjectType == "key" && resourceType == "credential_issuer" && strings.HasPrefix(req.SubjectID, "did:web:") {
		parsed, err := didutil.Parse(req.SubjectID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		issuerURL, err := parsed.ToBaseURL("https")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Reuse existing URL subject resolution (fetches metadata, evaluates trust)
		h.resolveURLSubject(c, ctx, tenantID, issuerURL, req.CredentialTypes)
		return
	}

	// For key subjects, proxy to PDP
	h.proxyToPDP(c, ctx, tenantID, evalReq)
}

// resolveCredentialOfferURI fetches a credential_offer_uri and returns the parsed
// credential offer document. The offer URI is fetched server-side using the
// configured httpClient, which applies SSRF protections via transport-level
// restrictions. The URL must already be validated as HTTPS before this call.
//
// Response: { "decision": true, "context": { "credential_offer": <offer doc> } }
func (h *AuthZENProxyHandler) resolveCredentialOfferURI(c *gin.Context, ctx context.Context, offerURI string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, offerURI, nil)
	if err != nil {
		h.logger.Error("failed to build credential offer request",
			zap.String("offer_uri", offerURI),
			zap.Error(err),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch credential offer"})
		return
	}
	req.Header.Set("Accept", "application/json")

	// Shallow-copy the client to set a per-request CheckRedirect without
	// affecting concurrent callers; Transport is shared and safe.
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
		h.logger.Error("credential offer fetch failed",
			zap.String("offer_uri", offerURI),
			zap.Error(err),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch credential offer"})
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		h.logger.Warn("credential offer endpoint returned non-200",
			zap.String("offer_uri", offerURI),
			zap.Int("status", resp.StatusCode),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("credential offer endpoint returned status %d", resp.StatusCode)})
		return
	}

	// Read one extra byte to detect truncation: if the body exceeds the cap,
	// reject it rather than silently accepting a partial document.
	const maxOfferSize = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOfferSize+1))
	if err != nil {
		h.logger.Error("failed to read credential offer response",
			zap.String("offer_uri", offerURI),
			zap.Error(err),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to read credential offer response"})
		return
	}

	if len(body) > maxOfferSize {
		h.logger.Warn("credential offer response exceeds size limit",
			zap.String("offer_uri", offerURI),
			zap.Int("limit", maxOfferSize),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("credential offer response exceeds %d byte limit", maxOfferSize)})
		return
	}

	var offer map[string]interface{}
	if err := json.Unmarshal(body, &offer); err != nil {
		h.logger.Warn("credential offer response is not valid JSON",
			zap.String("offer_uri", offerURI),
			zap.Error(err),
		)
		c.JSON(http.StatusBadGateway, gin.H{"error": "credential offer response is not valid JSON"})
		return
	}

	// Validate the document contains the required OID4VCI credential offer fields.
	credentialIssuer, ok := offer["credential_issuer"].(string)
	if !ok {
		c.JSON(http.StatusBadGateway, gin.H{"error": "credential offer missing required field: credential_issuer"})
		return
	}
	if _, ok := offer["credential_configuration_ids"].([]interface{}); !ok {
		c.JSON(http.StatusBadGateway, gin.H{"error": "credential offer missing required field: credential_configuration_ids"})
		return
	}

	h.logger.Info("credential offer URI resolved",
		zap.String("offer_uri", offerURI),
		zap.String("credential_issuer", credentialIssuer),
	)

	c.JSON(http.StatusOK, gin.H{
		"decision": true,
		"context": gin.H{
			"credential_offer": offer,
		},
	})
}

// resolveURLSubject handles the local resolution path for URL subjects.
// It resolves metadata, extracts key material, evaluates trust via PDP,
// and returns a composite response. Logo inlining is performed when:
//   - metadata is unsigned (no signed_metadata field), OR
//   - metadata is signed AND the PDP returns trusted
//
// If metadata is signed but untrusted, an error is returned.
func (h *AuthZENProxyHandler) resolveURLSubject(c *gin.Context, ctx context.Context, tenantID, issuerURL string, credentialTypes []string) {
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
	action := &gotrust.Action{Name: "credential-issuer"}
	if len(credentialTypes) > 0 {
		action.Parameters = map[string]interface{}{
			"credential_types": credentialTypes,
		}
	}

	trustReq := &gotrust.EvaluationRequest{
		Subject: gotrust.Subject{
			Type: "key",
			ID:   issuerURL,
		},
		Resource: gotrust.Resource{
			ID: issuerURL,
		},
		Action: action,
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

	if !validateEvaluationRequest(c, trustReq) {
		return
	}
	trustResp, err := client.Evaluate(ctx, trustReq)
	if err != nil {
		h.logger.Error("PDP trust evaluation failed",
			zap.String("issuer_url", issuerURL),
			zap.String("pdp_url", pdpURL),
			zap.Error(err),
		)
		h.writePDPError(c, ctx, err, "trust evaluation service unavailable")
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
	// A valid org.siros.secret_seed advertisement (names only) stays; a
	// malformed one makes the configuration "not offered" (5A.3). This runs
	// after key extraction and the trust decision above, so dropping the
	// original signed_metadata JWT here cannot change that decision.
	sanitizeSecretSeedAdvertisement(result.Metadata)
	sanitizeHolderCommitmentsAdvertisement(result.Metadata)

	// Step 6: Evaluate whether this provider is entitled to issue what it is
	// offering. Distinct from the PDP decision above, which answers whether the
	// issuer is trusted at all — a trusted issuer can still be unregistered for
	// the credential type it is proposing.
	entitlement := h.evaluateIssuerEntitlement(ctx, client, issuerURL, result, keyMaterial, trustResp.Decision, credentialTypes)
	if entitlement != nil && !entitlement.Allowed {
		h.logger.Warn("issuer is not entitled to issue the requested credential",
			zap.String("issuer_url", issuerURL),
			zap.Any("findings", entitlement.Findings))
		c.JSON(http.StatusForbidden, gin.H{
			"error":              "issuer is not registered to issue the requested credential",
			"issuer_entitlement": entitlement,
		})
		return
	}

	// Step 7: Return composite response with trust decision and metadata
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
	resp.IssuerEntitlement = entitlement

	// Step 8: Enrich response with registered issuer info from backend storage.
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

// resolveAuthorizationServerMetadata handles resource_type=oauth-authorization-server.
// It fetches the RFC 8414 OAuth Authorization Server metadata for the given issuer
// and returns it in the standard resolve response format (trust_metadata).
// No trust evaluation or key extraction is performed — this is a simple metadata fetch.
func (h *AuthZENProxyHandler) resolveAuthorizationServerMetadata(c *gin.Context, ctx context.Context, tenantID, issuerURL string) {
	// Use the issuer URL directly as the authorization server base.
	// In OID4VCI, the credential issuer metadata may contain an
	// authorization_servers field, but fetching it here would trigger
	// an additional request to /.well-known/openid-credential-issuer
	// which can interfere with conformance suite state machines.
	// The caller can pass the authorization server URL directly if different.
	// Ordered candidates (RFC 8414 insertion, then OIDC Discovery append),
	// 404-only fallback, exact issuer identity check: see
	// oidc.FetchAuthorizationServerMetadata. The SSRF-protected httpClient is
	// used for every candidate.
	body, err := oidc.FetchAuthorizationServerMetadata(ctx, h.httpClient, issuerURL, 1<<20)
	if err != nil {
		var statusErr *oidc.ASMetadataStatusError
		switch {
		case errors.Is(err, oidc.ErrASIssuerMismatch):
			// Do not log or return the document's issuer (attacker-controlled).
			h.logger.Warn("authorization server metadata issuer mismatch",
				zap.String("tenant_id", tenantID),
			)
			c.JSON(http.StatusBadGateway, gin.H{"error": "authorization server metadata issuer mismatch"})
		case errors.Is(err, oidc.ErrASIdentifierInvalid):
			c.JSON(http.StatusBadGateway, gin.H{"error": "invalid authorization server URL"})
		case errors.Is(err, oidc.ErrASMetadataNotFound):
			h.logger.Debug("authorization server metadata not found", zap.String("issuer_url", issuerURL))
			c.JSON(http.StatusBadGateway, gin.H{"error": "authorization server returned HTTP 404"})
		case errors.As(err, &statusErr):
			h.logger.Debug("authorization server metadata returned non-200",
				zap.String("issuer_url", issuerURL),
				zap.Int("status", statusErr.Status),
			)
			c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("authorization server returned HTTP %d", statusErr.Status)})
		case errors.Is(err, oidc.ErrASMetadataInvalid):
			c.JSON(http.StatusBadGateway, gin.H{"error": "invalid authorization server metadata JSON"})
		default:
			h.logger.Debug("failed to fetch authorization server metadata",
				zap.String("issuer_url", issuerURL),
				zap.Error(err),
			)
			c.JSON(http.StatusBadGateway, gin.H{"error": "authorization server metadata fetch failed"})
		}
		return
	}

	var authzMeta map[string]interface{}
	if err := json.Unmarshal(body, &authzMeta); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid authorization server metadata JSON"})
		return
	}

	h.logger.Info("authorization server metadata resolved",
		zap.String("tenant_id", tenantID),
		zap.String("issuer_url", issuerURL),
	)

	c.JSON(http.StatusOK, &resolveURLResponse{
		EvaluationResponse: gotrust.EvaluationResponse{
			Decision: false, // No trust evaluation performed — metadata fetch only
			Context: &gotrust.EvaluationResponseContext{
				TrustMetadata: authzMeta,
			},
		},
	})
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

	if !validateEvaluationRequest(c, evalReq) {
		return
	}
	resp, err := client.Evaluate(ctx, evalReq)
	if err != nil {
		h.logger.Error("PDP resolution failed",
			zap.String("tenant_id", tenantID),
			zap.String("pdp_url", pdpURL),
			zap.Error(err),
		)
		h.writePDPError(c, ctx, err, "resolution service unavailable")
		return
	}

	c.JSON(http.StatusOK, resp)
}

// maxPDPErrorBodyBytes bounds how much of a PDP error body is echoed to callers.
const maxPDPErrorBodyBytes = 2048

// writePDPError maps a failed PDP call to an HTTP response.
//
// Error contract:
//   - PDP answered 422 -> 422; any other PDP 4xx that signals a bad request
//     (400, 405, 409, 413, 415, ...) -> 400. The PDP's error body is passed
//     through under "details" (parsed JSON if it is JSON, else a truncated
//     string; bounded to maxPDPErrorBodyBytes) so callers can tell a rejected
//     request from an unreachable backend and must NOT fall back to weaker checks.
//   - PDP 401/403/404/408/429 describe the proxy-to-PDP relationship (credentials,
//     routing, throttling), not the caller's request -> 502.
//   - PDP 5xx and transport errors -> 502; deadline exceeded -> 504.
func (h *AuthZENProxyHandler) writePDPError(c *gin.Context, ctx context.Context, err error, unavailableMsg string) {
	var evalErr *authzenclient.EvaluationError
	if errors.As(err, &evalErr) {
		switch sc := evalErr.StatusCode; {
		case sc == http.StatusUnprocessableEntity:
			c.JSON(sc, pdpErrorBody("trust evaluation request rejected by PDP", evalErr.Body))
			return
		case sc >= 400 && sc < 500 &&
			sc != http.StatusUnauthorized && sc != http.StatusForbidden &&
			sc != http.StatusNotFound && sc != http.StatusRequestTimeout &&
			sc != http.StatusTooManyRequests:
			c.JSON(http.StatusBadRequest, pdpErrorBody("trust evaluation request rejected by PDP", evalErr.Body))
			return
		}
	} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": "trust evaluation service timed out"})
		return
	}
	c.JSON(http.StatusBadGateway, gin.H{"error": unavailableMsg})
}

// pdpErrorBody builds a structured error response embedding the PDP's own
// error body. The serialized response is guaranteed to be at most
// maxPDPErrorBodyBytes: a JSON object body is embedded as-is when it fits;
// otherwise (non-JSON, or too large once serialized) a truncated string is
// embedded, shrunk until the serialized response fits.
func pdpErrorBody(msg, pdpBody string) gin.H {
	pdpBody = strings.TrimSpace(pdpBody)
	if pdpBody == "" {
		return gin.H{"error": msg}
	}
	var parsed map[string]interface{}
	if json.Unmarshal([]byte(pdpBody), &parsed) == nil {
		out := gin.H{"error": msg, "details": parsed}
		if e, ok := parsed["error"].(string); ok && e != "" && len(e) <= 256 {
			out["error"] = e
		}
		if serializedLen(out) <= maxPDPErrorBodyBytes {
			return out
		}
	}
	return truncatedPDPErrorBody(msg, pdpBody)
}

// truncatedPDPErrorBody embeds the longest prefix of pdpBody whose serialized
// response still fits in maxPDPErrorBodyBytes, falling back to the bare error
// envelope when not even an empty prefix fits.
//
// A byte-offset cut can split a UTF-8 rune, so each candidate is passed through
// strings.ToValidUTF8, which drops the partial trailing rune. The search is
// sound because the serialized length is monotonically non-decreasing in the
// cut offset n: the cleaned string for n is always a prefix of the cleaned
// string for n+1 (a partial rune is dropped, then completed), and JSON
// escaping is applied independently per rune, so a longer prefix never
// serializes shorter.
func truncatedPDPErrorBody(msg, pdpBody string) gin.H {
	lo, hi := 0, len(pdpBody)
	var best gin.H
	for lo <= hi {
		mid := lo + (hi-lo)/2
		out := gin.H{"error": msg, "details": strings.ToValidUTF8(pdpBody[:mid], "")}
		if serializedLen(out) <= maxPDPErrorBodyBytes {
			best, lo = out, mid+1
		} else {
			hi = mid - 1
		}
	}
	if best != nil {
		return best
	}
	return gin.H{"error": msg}
}

func serializedLen(v interface{}) int {
	b, err := json.Marshal(v)
	if err != nil {
		return maxPDPErrorBodyBytes + 1
	}
	return len(b)
}

// validateEvaluationRequest performs the same local validation the AuthZEN
// client does before sending, so that an invalid request (e.g. mismatched
// subject/resource IDs) is reported as 400 rather than being folded into a
// 502 "unavailable" by the PDP error path. Returns false after responding.
func validateEvaluationRequest(c *gin.Context, req *gotrust.EvaluationRequest) bool {
	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid evaluation request: " + err.Error()})
		return false
	}
	return true
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

// sanitizeSecretSeedAdvertisement enforces privatedata-spec 5A.3/5A.4 on the
// issuer metadata served to the wallet, in place. A valid advertisement
// ({"org.siros.secret_seed":{"namespaces":[...]}}, names only) is public and is
// served unchanged, because the wallet needs it to request response encryption.
// A credential configuration whose org.siros.secret_seed member is malformed
// (carrying hex or any other non-list content) is treated as not offered: the
// whole configuration is removed, so no such value reaches the wallet.
//
// When a configuration is removed, the original signed_metadata JWT (kept by
// the resolver for legacy signed metadata) is also dropped from the served
// document: its base64url payload still carries the rejected configuration,
// and editing the payload would invalidate the signature. The wallet then
// receives the sanitized claims without that JWT. The signature was verified
// and the trust decision taken before this runs; the effect is only that the
// wallet cannot re-verify the (by now modified) document itself.
func sanitizeSecretSeedAdvertisement(metadata map[string]interface{}) {
	sanitizeAdvertisement(metadata, "org.siros.secret_seed", func(raw []byte) bool {
		present, valid := engine.SecretSeedAdvertisement(raw)
		return present && !valid
	})
}

// sanitizeAdvertisement removes every credential configuration whose
// credential_metadata[member] is judged malformed by malformed (which receives
// the whole credential_metadata object, JSON encoded), and drops
// signed_metadata when it removed one.
func sanitizeAdvertisement(metadata map[string]interface{}, member string, malformed func(raw []byte) bool) {
	ccs, ok := metadata["credential_configurations_supported"].(map[string]interface{})
	if !ok {
		return
	}
	for id, ccRaw := range ccs {
		cc, ok := ccRaw.(map[string]interface{})
		if !ok {
			continue
		}
		cm, ok := cc["credential_metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		if _, has := cm[member]; !has {
			continue
		}
		raw, err := json.Marshal(cm)
		if err != nil || malformed(raw) {
			delete(ccs, id)
			delete(metadata, "signed_metadata")
		}
	}
}

// sanitizeHolderCommitmentsAdvertisement removes, in place, every credential
// configuration whose org.siros.holder_commitments member is malformed (not
// {"commitments": [1..4 short names]}, or carrying hex-looking values), so no
// such value reaches the wallet; signed_metadata is dropped when that happens,
// for the same reason as in sanitizeSecretSeedAdvertisement.
func sanitizeHolderCommitmentsAdvertisement(metadata map[string]interface{}) {
	sanitizeAdvertisement(metadata, "org.siros.holder_commitments", func(raw []byte) bool {
		present, _, valid := engine.HolderCommitmentsAdvertisement(raw)
		return present && !valid
	})
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
			// Inline logos in credential_metadata.display (merged VCTM)
			if credMeta, ok := cc["credential_metadata"].(map[string]interface{}); ok {
				if display, ok := credMeta["display"].([]interface{}); ok {
					for _, d := range display {
						if dm, ok := d.(map[string]interface{}); ok {
							h.inlineLogoField(ctx, dm)
						}
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

// evaluateIssuerEntitlement applies the ARF §6.6.2.3 wallet-side checks to a
// resolved provider: is the signing certificate a WRPAC, does the registration
// certificate describe this provider, and is it registered for what it offers.
//
// Returns nil when there is nothing to say — mode off, or metadata that was
// never signed, in which case the trust decision above has already dealt with it.
func (h *AuthZENProxyHandler) evaluateIssuerEntitlement(
	ctx context.Context,
	pdp registrarPDP,
	issuerURL string,
	result *issuermetadata.ResolveResult,
	keyMaterial *trust.KeyMaterial,
	chainTrusted bool,
	credentialTypes []string,
) *issuertrust.Decision {
	mode := issuertrust.ParseMode(h.cfg.IssuerEntitlementMode)
	if mode == issuertrust.ModeOff || result == nil {
		return nil
	}

	chain := issuertrust.ChainFromX5C(keyMaterialX5C(keyMaterial))
	if len(chain) == 0 && !result.Signed {
		// Unsigned metadata is not an entitlement problem, and reporting it as
		// one would double up on a decision already made above.
		return nil
	}

	registrationCert := issuermetadata.RegistrationCertificate(result.Metadata)
	return issuertrust.Evaluate(issuertrust.Input{
		Chain:            chain,
		RegistrationCert: registrationCert,
		// keyMaterial is what the PDP decision above was made on, and chain is
		// taken from it, so the decision covers the chain.
		ChainAnchored:    chainTrusted,
		Offers:           issuertrust.OffersFor(result.Metadata, credentialTypes),
		RegistrationAuth: h.authenticateRegistrationCert(ctx, pdp, issuerURL, registrationCert),
	}, mode)
}

// registrarPDP is the slice of the AuthZEN client the registrar check needs.
type registrarPDP interface {
	Evaluate(ctx context.Context, req *gotrust.EvaluationRequest) (*gotrust.EvaluationResponse, error)
}

// authenticateRegistrationCert verifies the registration certificate's
// signature and asks the PDP whether its signer is a trusted Registrar
// (action trust.RegistrarAction). Any failure to establish that is
// AuthUnchecked, which Evaluate reports as a finding.
func (h *AuthZENProxyHandler) authenticateRegistrationCert(ctx context.Context, pdp registrarPDP, issuerURL, token string) issuertrust.AuthResult {
	if token == "" || pdp == nil {
		return issuertrust.AuthUnchecked
	}
	return issuertrust.AuthenticateRegistrationCert(ctx, token, func(ctx context.Context, km *trust.KeyMaterial) (bool, error) {
		keys := make([]interface{}, len(km.X5C))
		for i, cert := range km.X5C {
			keys[i] = cert
		}
		resp, err := pdp.Evaluate(ctx, &gotrust.EvaluationRequest{
			Subject:  gotrust.Subject{Type: "key", ID: issuerURL},
			Resource: gotrust.Resource{Type: "x5c", ID: issuerURL, Key: keys},
			Action:   &gotrust.Action{Name: trust.RegistrarAction},
		})
		if err != nil {
			return false, err
		}
		return resp != nil && resp.Decision, nil
	})
}

// keyMaterialX5C returns the x5c entries of key material, or nil when it is not
// an x5c chain.
func keyMaterialX5C(km *trust.KeyMaterial) []string {
	if km == nil || km.Type != "x5c" {
		return nil
	}
	return km.X5C
}
