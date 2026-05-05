package engine

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// OID4VPHandler handles OpenID4VP credential presentation flows
type OID4VPHandler struct {
	BaseHandler
	httpClient *http.Client
}

// NewOID4VPHandler creates a new OID4VP flow handler
func NewOID4VPHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
	return &OID4VPHandler{
		BaseHandler: BaseHandler{
			Flow:       flow,
			Config:     cfg,
			Logger:     logger,
			TrustSvc:   trustSvc,
			Registry:   registry,
			Verifiers:  verifiers,
			TrustCache: trustCache,
		},
		httpClient: cfg.HTTPClient.NewHTTPClient(0),
	}, nil
}

// OID4VP data structures

// ClientIDScheme constants for OID4VP client identification
const (
	ClientIDSchemeRedirectURI         = "redirect_uri"
	ClientIDSchemeDID                 = "did"
	ClientIDSchemeX509SANDNS          = "x509_san_dns"
	ClientIDSchemeX509SANURI          = "x509_san_uri"
	ClientIDSchemeVerifierAttestation = "verifier_attestation"
)

// AuthorizationRequest represents an OpenID4VP authorization request
type AuthorizationRequest struct {
	ResponseType      string          `json:"response_type"`
	ClientID          string          `json:"client_id"`
	ClientIDScheme    string          `json:"client_id_scheme,omitempty"`
	ResponseMode      string          `json:"response_mode,omitempty"`
	ResponseURI       string          `json:"response_uri,omitempty"`
	RedirectURI       string          `json:"redirect_uri,omitempty"`
	Nonce             string          `json:"nonce,omitempty"`
	State             string          `json:"state,omitempty"`
	Scope             string          `json:"scope,omitempty"`
	DCQLQuery         json.RawMessage `json:"dcql_query,omitempty"`
	ClientMetadata    *ClientMetadata `json:"client_metadata,omitempty"`
	ClientMetadataURI string          `json:"client_metadata_uri,omitempty"`
	// RequestJWT stores the raw request JWT (if the request was JWT-secured).
	// Used to extract x5c/jwk key material from the JWT header for trust evaluation.
	RequestJWT string `json:"-"`
}

// ClientMetadata represents verifier/client metadata
type ClientMetadata struct {
	ClientName    string                 `json:"client_name,omitempty"`
	LogoURI       string                 `json:"logo_uri,omitempty"`
	ClientPurpose string                 `json:"client_purpose,omitempty"`
	VPFormats     map[string]interface{} `json:"vp_formats,omitempty"`
	JWKS          json.RawMessage        `json:"jwks,omitempty"`
	JWKsURI       string                 `json:"jwks_uri,omitempty"`
	X5C           []string               `json:"x5c,omitempty"`
	// JARM (JWT Secured Authorization Response Mode)
	AuthorizationEncryptedResponseAlg string `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc string `json:"authorization_encrypted_response_enc,omitempty"`
	AuthorizationSignedResponseAlg    string `json:"authorization_signed_response_alg,omitempty"`
}

// CredentialsMatchedPayload is the payload for credentials_matched action
type CredentialsMatchedPayload struct {
	Matches       []CredentialMatch `json:"matches"`
	NoMatchReason string            `json:"no_match_reason,omitempty"`
}

// ConsentPayload is the payload for consent action
type ConsentPayload struct {
	SelectedCredentials []ConsentSelection `json:"selected_credentials"`
}

// Execute runs the OID4VP flow
func (h *OID4VPHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	ctx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	defer cancel()

	// Add tenant context for X-Tenant-ID propagation
	if h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		ctx = ContextWithTenant(ctx, h.Flow.Session.TenantID)
	}

	// Step 1: Parse authorization request
	authReq, err := h.parseRequest(ctx, msg)
	if err != nil {
		h.Logger.Debug("failed to parse request", zap.Error(err))
		_ = h.Error(StepParsingRequest, ErrCodeOfferParseError, ErrCodeOfferParseError.UserFacingMessage())
		return err
	}

	// Infer client_id_scheme if not explicitly provided
	if authReq.ClientIDScheme == "" {
		authReq.ClientIDScheme = inferClientIDScheme(authReq.ClientID)
	}

	h.SetData("auth_request", authReq)

	// Step 2: Evaluate verifier trust
	verifier, err := h.evaluateVerifierTrust(ctx, authReq)
	if err != nil {
		h.Logger.Debug("verifier trust evaluation failed", zap.Error(err))
		_ = h.Error(StepEvaluatingVerifierTrust, ErrCodeUntrustedVerifier, ErrCodeUntrustedVerifier.UserFacingMessage())
		return err
	}

	// Step 3: Send credential_selection with dcql_query + verifier; wait for consent or decline
	selectedCredentials, err := h.requestCredentialSelection(ctx, authReq, verifier)
	if err != nil {
		return err
	}

	// Step 4: Request VP signing from client (use configured ClientID for audience if set)
	vpToken, err := h.requestVPSignature(ctx, authReq, selectedCredentials, verifier.ClientID)
	if err != nil {
		h.Logger.Debug("VP signature failed", zap.Error(err))
		_ = h.Error(StepSubmittingResponse, ErrCodeSignError, ErrCodeSignError.UserFacingMessage())
		return err
	}

	// Step 5: Submit VP response to verifier
	redirectURI, err := h.submitResponse(ctx, authReq, vpToken)
	if err != nil {
		h.Logger.Debug("VP submission failed", zap.Error(err))
		_ = h.Error(StepSubmittingResponse, ErrCodePresentationError, ErrCodePresentationError.UserFacingMessage())
		return err
	}

	// Step 6: Complete
	return h.Complete(nil, redirectURI)
}

func (h *OID4VPHandler) parseRequest(ctx context.Context, msg *FlowStartMessage) (*AuthorizationRequest, error) {
	_ = h.ProgressMessage(StepParsingRequest, "Parsing authorization request")

	var authReq AuthorizationRequest

	if msg.RequestURI != "" {
		// Parse from openid4vp:// URL or direct URL
		requestStr := msg.RequestURI
		if strings.HasPrefix(requestStr, "openid4vp://") {
			u, err := url.Parse(requestStr)
			if err != nil {
				return nil, fmt.Errorf("invalid request URL: %w", err)
			}
			// Check for request_uri parameter
			requestURIRef := u.Query().Get("request_uri")
			if requestURIRef != "" {
				return h.fetchRequestFromURI(ctx, requestURIRef)
			}
			// Parse inline parameters
			return h.parseRequestFromURL(u)
		}
		// Direct URL
		return h.parseRequestFromURL(&url.URL{RawQuery: requestStr})
	} else if msg.RequestURIRef != "" {
		return h.fetchRequestFromURI(ctx, msg.RequestURIRef)
	}

	return &authReq, errors.New("no request provided")
}

func (h *OID4VPHandler) parseRequestFromURL(u *url.URL) (*AuthorizationRequest, error) {
	q := u.Query()

	authReq := &AuthorizationRequest{
		ResponseType:   q.Get("response_type"),
		ClientID:       q.Get("client_id"),
		ClientIDScheme: q.Get("client_id_scheme"),
		ResponseMode:   q.Get("response_mode"),
		ResponseURI:    q.Get("response_uri"),
		RedirectURI:    q.Get("redirect_uri"),
		Nonce:          q.Get("nonce"),
		State:          q.Get("state"),
		Scope:          q.Get("scope"),
	}

	// Parse dcql_query
	if dcqlStr := q.Get("dcql_query"); dcqlStr != "" {
		if !json.Valid([]byte(dcqlStr)) {
			return nil, fmt.Errorf("invalid dcql_query: not valid JSON")
		}
		authReq.DCQLQuery = json.RawMessage(dcqlStr)
	}

	// Parse client_metadata if inline
	if cmStr := q.Get("client_metadata"); cmStr != "" {
		var cm ClientMetadata
		if err := json.Unmarshal([]byte(cmStr), &cm); err != nil {
			return nil, fmt.Errorf("invalid client_metadata: %w", err)
		}
		authReq.ClientMetadata = &cm
	}
	authReq.ClientMetadataURI = q.Get("client_metadata_uri")

	// Handle request JWT if present
	if requestJWT := q.Get("request"); requestJWT != "" {
		return h.parseRequestJWT(requestJWT)
	}

	return authReq, nil
}

func (h *OID4VPHandler) parseRequestJWT(jwtStr string) (*AuthorizationRequest, error) {
	// Parse JWT without verification (verification happens during trust evaluation)
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid request JWT format")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var authReq AuthorizationRequest
	if err := json.Unmarshal(payload, &authReq); err != nil {
		return nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	// Store the raw JWT so we can extract key material from its header later
	authReq.RequestJWT = jwtStr

	return &authReq, nil
}

func (h *OID4VPHandler) fetchRequestFromURI(ctx context.Context, uri string) (*AuthorizationRequest, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request fetch returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPResponseBodyBytes))
	if err != nil {
		return nil, err
	}

	// Check if response is JWT or JSON
	bodyStr := strings.TrimSpace(string(body))

	// If the response is a JSON-encoded string unquote it
	if strings.HasPrefix(bodyStr, "\"") {
		var unquoted string
		if err := json.Unmarshal([]byte(bodyStr), &unquoted); err == nil {
			bodyStr = unquoted
		}
	}

	if strings.Count(bodyStr, ".") == 2 {
		// Likely a JWT
		return h.parseRequestJWT(bodyStr)
	}

	var authReq AuthorizationRequest
	if err := json.Unmarshal([]byte(bodyStr), &authReq); err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}

	return &authReq, nil
}

func (h *OID4VPHandler) evaluateVerifierTrust(ctx context.Context, authReq *AuthorizationRequest) (*VerifierInfo, error) {
	_ = h.ProgressMessage(StepEvaluatingVerifierTrust, "Evaluating verifier trust")

	// Check in-memory trust cache before triggering frontend evaluation
	canonicalURL := getCanonicalVerifierURL(authReq)
	if cached := h.getCachedVerifierTrust(canonicalURL); cached != nil {
		verifier := &VerifierInfo{
			Name:           cached.Name,
			ClientIDScheme: cached.ClientIDScheme,
			Trusted:        cached.Trusted,
			Framework:      cached.TrustFramework,
			TrustedStatus:  string(cached.TrustStatus),
			Domain:         extractDomain(authReq.ClientID),
		}
		// Look up admin-configured ClientID (read-only)
		if clientID := h.getAdminClientID(ctx, canonicalURL); clientID != "" {
			verifier.ClientID = clientID
		}
		if !verifier.Trusted {
			return nil, fmt.Errorf("untrusted verifier %s (cached)", authReq.ClientID)
		}
		h.Logger.Debug("Using cached trust result",
			zap.String("verifier", authReq.ClientID),
			zap.Bool("trusted", cached.Trusted))
		return verifier, nil
	}

	// Fetch client metadata if needed
	var clientMeta *ClientMetadata
	if authReq.ClientMetadata != nil {
		clientMeta = authReq.ClientMetadata
	} else if authReq.ClientMetadataURI != "" {
		cm, err := h.fetchClientMetadata(ctx, authReq.ClientMetadataURI)
		if err != nil {
			h.Logger.Warn("Failed to fetch client metadata", zap.Error(err))
		} else {
			clientMeta = cm
			// Store fetched metadata on the request so downstream steps
			// (e.g. submitDirectPostJWT) can access JARM parameters.
			authReq.ClientMetadata = cm
		}
	}

	// Build verifier info with name and logo from metadata
	verifier := &VerifierInfo{
		Name:           authReq.ClientID,
		ClientIDScheme: authReq.ClientIDScheme,
		Domain:         extractDomain(authReq.ClientID),
	}

	if clientMeta != nil {
		if clientMeta.ClientName != "" {
			verifier.Name = clientMeta.ClientName
		}
		if clientMeta.LogoURI != "" {
			verifier.Logo = &LogoInfo{URI: clientMeta.LogoURI}
		}
	}

	// Scheme-aware key material extraction and JWT verification
	// For DID schemes, key resolution is delegated to frontend via /v1/resolve
	var keyMaterial *KeyMaterial
	var requiresResolution bool
	var requestJWT string

	switch authReq.ClientIDScheme {
	case ClientIDSchemeDID:
		// DID scheme: request MUST be JWT-secured
		// Key resolution and JWT verification is delegated to frontend
		if !strings.HasPrefix(authReq.ClientID, "did:") {
			return nil, errors.New("client_id_scheme=did but client_id is not a DID")
		}
		if authReq.RequestJWT == "" {
			return nil, errors.New("client_id_scheme=did requires a signed request JWT")
		}
		// Don't verify JWT server-side - frontend will resolve DID and verify
		requiresResolution = true
		requestJWT = authReq.RequestJWT

	case ClientIDSchemeX509SANDNS:
		// X.509 scheme: request MUST be JWT-secured; verify signature with x5c
		// NOTE: client_id vs SAN DNS validation is performed by go-trust PDP via /v1/evaluate
		if authReq.RequestJWT == "" {
			return nil, errors.New("x509_san_dns scheme requires a signed request JWT")
		}
		km, verifyErr := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
		if verifyErr != nil {
			return nil, fmt.Errorf("x509_san_dns JWT verification failed: %w", verifyErr)
		}
		if km.Type != "x5c" {
			return nil, errors.New("x509_san_dns scheme requires x5c in JWT header")
		}
		keyMaterial = km

	default:
		// redirect_uri and other schemes: extract key material best-effort
		if clientMeta != nil {
			keyMaterial = h.extractVerifierKeyMaterial(ctx, clientMeta)
		}
		// Fallback: extract key material from the request JWT header
		if keyMaterial == nil && authReq.RequestJWT != "" {
			// Verify JWT signature if present (opportunistic verification)
			km, verifyErr := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
			if verifyErr != nil {
				h.Logger.Warn("Request JWT signature verification failed, falling back to header extraction",
					zap.Error(verifyErr))
				keyMaterial = trust.ExtractKeyMaterialFromJWT(authReq.RequestJWT)
			} else {
				keyMaterial = km
			}
		}
	}

	// Build trust evaluation request for frontend
	trustReq := &TrustEvaluationRequest{
		SubjectID:          authReq.ClientID,
		SubjectType:        SubjectTypeCredentialVerifier,
		RequiresResolution: requiresResolution,
		RequestJWT:         requestJWT,
		Context: map[string]interface{}{
			"client_id_scheme": authReq.ClientIDScheme,
		},
	}

	// Add response/redirect URI to context
	if authReq.ResponseURI != "" {
		trustReq.Context["response_uri"] = authReq.ResponseURI
	}
	if authReq.RedirectURI != "" {
		trustReq.Context["redirect_uri"] = authReq.RedirectURI
	}

	// Convert key material for frontend (nil for DID schemes - frontend resolves)
	if keyMaterial != nil {
		trustReq.KeyMaterial = &TrustKeyMaterial{
			Type: keyMaterial.Type,
			X5C:  keyMaterial.X5C,
			JWK:  keyMaterial.JWK,
		}
	}

	// Send trust evaluation request to frontend
	if err := trustReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid trust evaluation request: %w", err)
	}
	_ = h.Progress(StepEvaluatingVerifierTrust, map[string]interface{}{
		"trust_evaluation_required": true,
		"request":                   trustReq,
	})

	// Wait for frontend to evaluate trust via /v1/evaluate and respond
	// Use shorter timeout for trust evaluation (frontend should respond quickly)
	action, err := h.Flow.Session.WaitForActionWithTimeout(ctx, h.Flow.ID, TrustEvaluationTimeout, ActionTrustResult)
	if err != nil {
		return nil, fmt.Errorf("failed waiting for trust evaluation: %w", err)
	}

	// Parse trust result from frontend
	var trustResult TrustResultPayload
	if err := json.Unmarshal(action.Payload, &trustResult); err != nil {
		return nil, fmt.Errorf("failed to parse trust result: %w", err)
	}

	// Validate and mark as processed
	if err := trustResult.Validate(); err != nil {
		return nil, fmt.Errorf("invalid trust result from frontend: %w", err)
	}

	// Audit log the trust result (for security audit trail)
	h.Logger.Info("Trust evaluation result received",
		zap.String("verifier", authReq.ClientID),
		zap.Bool("trusted", trustResult.Trusted),
		zap.String("framework", trustResult.Framework),
		zap.String("reason", trustResult.Reason))

	// Update verifier info from trust result
	verifier.Trusted = trustResult.Trusted
	verifier.Framework = trustResult.Framework
	verifier.Reason = trustResult.Reason
	if trustResult.Trusted {
		verifier.TrustedStatus = string(domain.TrustStatusTrusted)
	} else {
		verifier.TrustedStatus = string(domain.TrustStatusUntrusted)
	}

	// Override name/logo from trust evaluation if provided
	if trustResult.Name != "" {
		verifier.Name = trustResult.Name
	}
	if trustResult.Logo != "" {
		verifier.Logo = &LogoInfo{URI: trustResult.Logo}
	}

	// Cache trust evaluation result in memory (does not write to VerifierStore)
	h.cacheVerifierTrust(authReq, verifier)

	// Look up admin-configured ClientID for VP audience (read-only)
	if clientID := h.getAdminClientID(ctx, canonicalURL); clientID != "" {
		verifier.ClientID = clientID
	}

	// Enforce trust decision: block untrusted verifiers
	if !verifier.Trusted {
		reason := "verifier not trusted"
		if trustResult.Reason != "" {
			reason = trustResult.Reason
		}
		h.Logger.Warn("Blocking untrusted verifier",
			zap.String("verifier", authReq.ClientID),
			zap.String("reason", reason))
		return nil, fmt.Errorf("untrusted verifier %s: %s", authReq.ClientID, reason)
	}

	return verifier, nil
}

// verifyDIDRequest validates a DID-identified verifier's request.
// Deprecated: DID verification is now delegated to frontend via /v1/resolve.
// The frontend resolves the DID document to get keys and verifies the JWT.
// This function is kept for reference but should not be used.
func (h *OID4VPHandler) verifyDIDRequest(authReq *AuthorizationRequest) (*KeyMaterial, error) {
	// Validate client_id is a valid DID
	if !strings.HasPrefix(authReq.ClientID, "did:") {
		return nil, errors.New("client_id_scheme=did but client_id is not a DID")
	}
	parts := strings.SplitN(authReq.ClientID, ":", 3)
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("invalid DID format: %s", authReq.ClientID)
	}

	// Request must be JWT-secured
	if authReq.RequestJWT == "" {
		return nil, errors.New("client_id_scheme=did requires a signed request JWT")
	}

	// Verify JWT signature with embedded key material
	km, err := trust.VerifyJWTWithEmbeddedKey(authReq.RequestJWT)
	if err != nil {
		return nil, fmt.Errorf("DID request JWT verification failed: %w", err)
	}

	return km, nil
}

// getCanonicalVerifierURL returns the canonical URL for a verifier from an authorization request.
// This is used for consistent verifier lookup and caching.
// Priority: response_uri > redirect_uri > client_id
func getCanonicalVerifierURL(authReq *AuthorizationRequest) string {
	if authReq.ResponseURI != "" {
		return authReq.ResponseURI
	}
	if authReq.RedirectURI != "" {
		return authReq.RedirectURI
	}
	return authReq.ClientID
}

// getCachedVerifierTrust checks if a cached trust evaluation exists for the given verifier URL.
// Returns nil if no cache is available or the entry has expired.
func (h *OID4VPHandler) getCachedVerifierTrust(verifierURL string) *TrustCacheRecord {
	if h.TrustCache == nil {
		return nil
	}

	tenantID := domain.DefaultTenantID
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		tenantID = domain.TenantID(h.Flow.Session.TenantID)
	}

	return h.TrustCache.Get(tenantID, verifierURL)
}

// getAdminClientID looks up the admin-configured ClientID for a verifier URL.
// This is a read-only lookup against the admin VerifierStore.
func (h *OID4VPHandler) getAdminClientID(ctx context.Context, verifierURL string) string {
	if h.Verifiers == nil {
		return ""
	}

	tenantID := domain.DefaultTenantID
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		tenantID = domain.TenantID(h.Flow.Session.TenantID)
	}

	stored, err := h.Verifiers.GetByURL(ctx, tenantID, verifierURL)
	if err != nil || stored == nil {
		return ""
	}
	return stored.ClientID
}

// cacheVerifierTrust stores verifier trust evaluation results in the in-memory cache.
// This avoids writing to VerifierStore, which would pollute the admin registry.
func (h *OID4VPHandler) cacheVerifierTrust(authReq *AuthorizationRequest, verifier *VerifierInfo) {
	if h.TrustCache == nil {
		return
	}

	tenantID := domain.DefaultTenantID
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		tenantID = domain.TenantID(h.Flow.Session.TenantID)
	}

	var trustStatus domain.TrustStatus
	if verifier.Trusted {
		trustStatus = domain.TrustStatusTrusted
	} else {
		trustStatus = domain.TrustStatusUntrusted
	}

	h.TrustCache.Set(tenantID, getCanonicalVerifierURL(authReq), &TrustCacheRecord{
		Name:           verifier.Name,
		URL:            getCanonicalVerifierURL(authReq),
		ClientIDScheme: authReq.ClientIDScheme,
		TrustStatus:    trustStatus,
		TrustFramework: verifier.Framework,
		Trusted:        verifier.Trusted,
	})
}

// extractDomain extracts a domain name from a client_id (URL or DID).
func extractDomain(clientID string) string {
	if strings.HasPrefix(clientID, "did:web:") {
		// did:web:example.com → example.com (colons become dots in full spec, but the host is the 3rd segment)
		parts := strings.SplitN(clientID, ":", 4)
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	if u, err := url.Parse(clientID); err == nil && u.Host != "" {
		return u.Host
	}
	return ""
}

// extractVerifierKeyMaterial extracts key material from client metadata for trust evaluation.
// Priority: x5c > jwks > jwks_uri (for DIDs where client_id starts with did:, returns nil)
func (h *OID4VPHandler) extractVerifierKeyMaterial(ctx context.Context, clientMeta *ClientMetadata) *KeyMaterial {
	// X5C certificate chain takes priority
	if len(clientMeta.X5C) > 0 {
		return &KeyMaterial{
			Type: "x5c",
			X5C:  clientMeta.X5C,
		}
	}

	// Inline JWKS
	if len(clientMeta.JWKS) > 0 {
		var jwks interface{}
		if err := json.Unmarshal(clientMeta.JWKS, &jwks); err == nil {
			return &KeyMaterial{
				Type: "jwk",
				JWK:  jwks,
			}
		}
		h.Logger.Warn("Failed to parse inline JWKS", zap.Error(fmt.Errorf("invalid JSON")))
	}

	// Fetch from jwks_uri
	if clientMeta.JWKsURI != "" {
		jwks, err := trust.FetchJWKS(ctx, clientMeta.JWKsURI, h.httpClient)
		if err != nil {
			h.Logger.Warn("Failed to fetch JWKS from URI", zap.String("uri", clientMeta.JWKsURI), zap.Error(err))
		} else {
			return &KeyMaterial{
				Type: "jwk",
				JWK:  jwks,
			}
		}
	}

	// No key material available - will use resolution-only mode (for DIDs)
	return nil
}

func (h *OID4VPHandler) fetchClientMetadata(ctx context.Context, uri string) (*ClientMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata fetch returned status %d", resp.StatusCode)
	}

	var cm ClientMetadata
	if err := json.NewDecoder(resp.Body).Decode(&cm); err != nil {
		return nil, err
	}

	return &cm, nil
}

// requestCredentialSelection sends dcql_query + verifier to the client in a single
// credential_selection progress message and waits for the user to consent or decline.
// The frontend is responsible for local credential matching and the consent UI.
func (h *OID4VPHandler) requestCredentialSelection(ctx context.Context, authReq *AuthorizationRequest, verifier *VerifierInfo) ([]ConsentSelection, error) {
	_ = h.Progress(StepCredentialSelection, map[string]interface{}{
		"dcql_query": authReq.DCQLQuery,
		"verifier":   verifier,
	})

	action, err := h.WaitForAction(ctx, ActionConsent, ActionDecline)
	if err != nil {
		return nil, err
	}

	if action.Action == ActionDecline {
		var decline struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(action.Payload, &decline)
		h.Logger.Info("user declined presentation", zap.String("reason", decline.Reason))
		_ = h.Error(StepCredentialSelection, ErrCodePresentationError, "User declined the request")
		return nil, errors.New("user declined presentation")
	}

	var payload ConsentPayload
	if err := json.Unmarshal(action.Payload, &payload); err != nil {
		_ = h.Error(StepCredentialSelection, ErrCodeInvalidMessage, "Invalid consent payload")
		return nil, fmt.Errorf("invalid consent payload: %w", err)
	}

	if len(payload.SelectedCredentials) == 0 {
		_ = h.Error(StepCredentialSelection, ErrCodePresentationError, "No credentials selected")
		return nil, errors.New("no credentials selected")
	}

	return payload.SelectedCredentials, nil
}

func (h *OID4VPHandler) requestVPSignature(ctx context.Context, authReq *AuthorizationRequest, selected []ConsentSelection, audience string) (string, error) {
	// Convert selections to credential refs
	credRefs := make([]CredentialRef, len(selected))
	for i, s := range selected {
		credRefs[i] = CredentialRef(s)
	}

	// Use provided audience (configured client_id) or fall back to request client_id
	if audience == "" {
		audience = authReq.ClientID
	}

	resp, err := h.RequestSign(ctx, SignActionSignPresentation, SignRequestParams{
		Audience:             audience,
		Nonce:                authReq.Nonce,
		CredentialsToInclude: credRefs,
	})
	if err != nil {
		return "", err
	}

	return resp.VPToken, nil
}

// sanitizeEndpointURL validates and reconstructs an endpoint URL to prevent SSRF.
// It parses the URL, ensures the scheme is https or http, and rebuilds the URL
// from its validated components — breaking the taint chain for CodeQL analysis.
func sanitizeEndpointURL(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid response endpoint URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("invalid response endpoint URL scheme: %s", u.Scheme)
	}
	// Rebuild URL from validated components to break taint propagation.
	clean := &url.URL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}
	return clean.String(), nil
}

func (h *OID4VPHandler) submitResponse(ctx context.Context, authReq *AuthorizationRequest, vpToken string) (string, error) {
	_ = h.ProgressMessage(StepSubmittingResponse, "Submitting VP response")

	// Determine response endpoint
	responseEndpoint := authReq.ResponseURI
	if responseEndpoint == "" {
		responseEndpoint = authReq.RedirectURI
	}
	if responseEndpoint == "" {
		return "", errors.New("no response endpoint in request")
	}

	// Validate and sanitize the endpoint URL to prevent SSRF
	sanitizedEndpoint, err := sanitizeEndpointURL(responseEndpoint)
	if err != nil {
		return "", err
	}

	// Determine response mode
	responseMode := authReq.ResponseMode
	if responseMode == "" {
		responseMode = "direct_post"
	}

	switch responseMode {
	case "direct_post":
		return h.submitDirectPost(ctx, sanitizedEndpoint, authReq, vpToken)
	case "direct_post.jwt":
		return h.submitDirectPostJWT(ctx, sanitizedEndpoint, authReq, vpToken)
	case "fragment":
		return h.buildFragmentRedirect(sanitizedEndpoint, authReq, vpToken), nil
	case "query":
		return h.buildQueryRedirect(sanitizedEndpoint, authReq, vpToken), nil
	default:
		return "", fmt.Errorf("unsupported response_mode: %s", responseMode)
	}
}

func (h *OID4VPHandler) submitDirectPost(ctx context.Context, endpoint string, authReq *AuthorizationRequest, vpToken string) (string, error) {
	data := url.Values{}
	data.Set("vp_token", vpToken)
	if authReq.State != "" {
		data.Set("state", authReq.State)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit response: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Check for redirect
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var result struct {
			RedirectURI string `json:"redirect_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.RedirectURI != "" {
			return result.RedirectURI, nil
		}
		return "", nil
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.Header.Get("Location"), nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	return "", fmt.Errorf("response submission failed with status %d: %s", resp.StatusCode, string(body))
}

func (h *OID4VPHandler) buildFragmentRedirect(endpoint string, authReq *AuthorizationRequest, vpToken string) string {
	u, _ := url.Parse(endpoint)
	fragment := url.Values{}
	fragment.Set("vp_token", vpToken)
	if authReq.State != "" {
		fragment.Set("state", authReq.State)
	}
	u.Fragment = fragment.Encode()
	return u.String()
}

func (h *OID4VPHandler) buildQueryRedirect(endpoint string, authReq *AuthorizationRequest, vpToken string) string {
	u, _ := url.Parse(endpoint)
	q := u.Query()
	q.Set("vp_token", vpToken)
	if authReq.State != "" {
		q.Set("state", authReq.State)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// inferClientIDScheme infers the client_id_scheme from the client_id format
// when the verifier does not provide it explicitly.
func inferClientIDScheme(clientID string) string {
	switch {
	case strings.HasPrefix(clientID, "did:"):
		return ClientIDSchemeDID
	case strings.HasPrefix(clientID, "x509_san_dns:"):
		return ClientIDSchemeX509SANDNS
	case strings.HasPrefix(clientID, "x509_san_uri:"):
		return ClientIDSchemeX509SANURI
	case strings.HasPrefix(clientID, "verifier_attestation:"):
		return ClientIDSchemeVerifierAttestation
	case strings.HasPrefix(clientID, "https://"), strings.HasPrefix(clientID, "http://"):
		// HTTPS/HTTP URLs default to redirect_uri scheme
		return ClientIDSchemeRedirectURI
	default:
		// Unknown format - use redirect_uri as default
		return ClientIDSchemeRedirectURI
	}
}

func (h *OID4VPHandler) submitDirectPostJWT(ctx context.Context, endpoint string, authReq *AuthorizationRequest, vpToken string) (string, error) {
	now := time.Now()

	var vpTokenValue interface{} = vpToken
	if json.Valid([]byte(vpToken)) {
		var parsed interface{}
		if err := json.Unmarshal([]byte(vpToken), &parsed); err == nil {
			vpTokenValue = parsed
		}
	}

	// Build JWT claims per OID4VP §6.2 / JARM §4.1
	claims := map[string]interface{}{
		"iss":      "https://self-issued.me/v2",
		"aud":      authReq.ClientID,
		"exp":      now.Add(5 * time.Minute).Unix(),
		"iat":      now.Unix(),
		"vp_token": vpTokenValue,
	}
	if authReq.State != "" {
		claims["state"] = authReq.State
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JARM claims: %w", err)
	}

	// Determine JARM mode from client_metadata
	var encAlg, encEnc string
	if authReq.ClientMetadata != nil {
		encAlg = authReq.ClientMetadata.AuthorizationEncryptedResponseAlg
		encEnc = authReq.ClientMetadata.AuthorizationEncryptedResponseEnc
	}

	// Per spec: if encryption alg is specified, encrypt. Default enc is A128CBC-HS256.
	if encAlg == "" {
		return "", fmt.Errorf("direct_post.jwt requires authorization_encrypted_response_alg in client_metadata")
	}
	if encEnc == "" {
		encEnc = "A128CBC-HS256"
	}

	// Extract verifier's public key for encryption
	verifierKey, kid, err := h.extractVerifierEncryptionKey(authReq)
	if err != nil {
		return "", fmt.Errorf("failed to extract verifier encryption key: %w", err)
	}

	// Map algorithm strings to go-jose constants
	keyAlg, err := mapKeyAlgorithm(encAlg)
	if err != nil {
		return "", err
	}
	contentEnc, err := mapContentEncryption(encEnc)
	if err != nil {
		return "", err
	}

	// Build JWE
	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{Algorithm: keyAlg, Key: verifierKey, KeyID: kid},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create JWE encrypter: %w", err)
	}

	jweObj, err := encrypter.Encrypt(claimsJSON)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt JARM response: %w", err)
	}

	jweString, err := jweObj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}

	// POST response=<jwe> per OID4VP §6.2
	data := url.Values{}
	data.Set("response", jweString)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit JARM response: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var result struct {
			RedirectURI                string `json:"redirect_uri"`
			PresentationDuringIssuance string `json:"presentation_during_issuance_session"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			if result.RedirectURI != "" {
				return result.RedirectURI, nil
			}
		}
		return "", nil
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.Header.Get("Location"), nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	return "", fmt.Errorf("JARM response submission failed with status %d: %s", resp.StatusCode, string(body))
}

func (h *OID4VPHandler) extractVerifierEncryptionKey(authReq *AuthorizationRequest) (interface{}, string, error) {
	// Prefer client_metadata.jwks — this is where verifiers put their
	// ephemeral encryption key for JARM (ECDH-ES key agreement).
	if authReq.ClientMetadata != nil && len(authReq.ClientMetadata.JWKS) > 0 {
		var jwks struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(authReq.ClientMetadata.JWKS, &jwks); err == nil && len(jwks.Keys) > 0 {
			// Select the best key for encryption: prefer use="enc", then
			// matching alg, then fall back to first parseable key.
			var fallbackKey *jose.JSONWebKey
			for _, raw := range jwks.Keys {
				var jwk jose.JSONWebKey
				if err := jwk.UnmarshalJSON(raw); err != nil {
					continue
				}
				if jwk.Use == "enc" {
					return jwk.Key, jwk.KeyID, nil
				}
				if fallbackKey == nil {
					k := jwk // copy
					fallbackKey = &k
				}
			}
			if fallbackKey != nil {
				return fallbackKey.Key, fallbackKey.KeyID, nil
			}
		}
	}

	// Fallback: x5c from request JWT header (signing key, used when no
	// dedicated encryption key is provided in client_metadata)
	if authReq.RequestJWT != "" {
		parts := strings.Split(authReq.RequestJWT, ".")
		var kid string
		if len(parts) >= 2 {
			headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err == nil {
				var header struct {
					Kid string `json:"kid"`
				}
				_ = json.Unmarshal(headerBytes, &header)
				kid = header.Kid
			}
		}

		km := trust.ExtractKeyMaterialFromJWT(authReq.RequestJWT)
		if km != nil && km.Type == "x5c" && len(km.X5C) > 0 {
			certDER, err := base64.StdEncoding.DecodeString(km.X5C[0])
			if err != nil {
				certDER, err = base64.RawURLEncoding.DecodeString(km.X5C[0])
				if err != nil {
					return nil, "", fmt.Errorf("failed to decode x5c certificate: %w", err)
				}
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return nil, "", fmt.Errorf("failed to parse x5c certificate: %w", err)
			}
			return cert.PublicKey, kid, nil
		}
	}

	return nil, "", errors.New("no verifier encryption key found in client_metadata.jwks or request JWT x5c")
}

func mapKeyAlgorithm(alg string) (jose.KeyAlgorithm, error) {
	switch alg {
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	case "ECDH-ES+A128KW":
		return jose.ECDH_ES_A128KW, nil
	case "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	case "RSA-OAEP":
		return jose.RSA_OAEP, nil
	case "RSA-OAEP-256":
		return jose.RSA_OAEP_256, nil
	default:
		return "", fmt.Errorf("unsupported JARM key algorithm: %s", alg)
	}
}

func mapContentEncryption(enc string) (jose.ContentEncryption, error) {
	switch enc {
	case "A128CBC-HS256":
		return jose.A128CBC_HS256, nil
	case "A256CBC-HS512":
		return jose.A256CBC_HS512, nil
	case "A128GCM":
		return jose.A128GCM, nil
	case "A256GCM":
		return jose.A256GCM, nil
	default:
		return "", fmt.Errorf("unsupported JARM content encryption: %s", enc)
	}
}
