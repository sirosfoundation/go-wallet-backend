package engine

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
	"time"

	"go.uber.org/zap"

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
func NewOID4VPHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore) (FlowHandler, error) {
	return &OID4VPHandler{
		BaseHandler: BaseHandler{
			Flow:      flow,
			Config:    cfg,
			Logger:    logger,
			TrustSvc:  trustSvc,
			Registry:  registry,
			Verifiers: verifiers,
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
	ResponseType              string                  `json:"response_type"`
	ClientID                  string                  `json:"client_id"`
	ClientIDScheme            string                  `json:"client_id_scheme,omitempty"`
	ResponseMode              string                  `json:"response_mode,omitempty"`
	ResponseURI               string                  `json:"response_uri,omitempty"`
	RedirectURI               string                  `json:"redirect_uri,omitempty"`
	Nonce                     string                  `json:"nonce,omitempty"`
	State                     string                  `json:"state,omitempty"`
	Scope                     string                  `json:"scope,omitempty"`
	PresentationDefinition    *PresentationDefinition `json:"presentation_definition,omitempty"`
	PresentationDefinitionURI string                  `json:"presentation_definition_uri,omitempty"`
	ClientMetadata            *ClientMetadata         `json:"client_metadata,omitempty"`
	ClientMetadataURI         string                  `json:"client_metadata_uri,omitempty"`
	// RequestJWT stores the raw request JWT (if the request was JWT-secured).
	// Used to extract x5c/jwk key material from the JWT header for trust evaluation.
	RequestJWT string `json:"-"`
}

// PresentationDefinition represents a DIF Presentation Definition
type PresentationDefinition struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name,omitempty"`
	Purpose          string                 `json:"purpose,omitempty"`
	InputDescriptors []InputDescriptor      `json:"input_descriptors"`
	Format           map[string]interface{} `json:"format,omitempty"`
}

// InputDescriptor represents a single input requirement
type InputDescriptor struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name,omitempty"`
	Purpose     string                 `json:"purpose,omitempty"`
	Format      map[string]interface{} `json:"format,omitempty"`
	Constraints *Constraints           `json:"constraints,omitempty"`
}

// Constraints represents input descriptor constraints
type Constraints struct {
	LimitDisclosure string  `json:"limit_disclosure,omitempty"`
	Fields          []Field `json:"fields,omitempty"`
}

// Field represents a required field in credentials
type Field struct {
	Path     []string               `json:"path"`
	Filter   map[string]interface{} `json:"filter,omitempty"`
	Optional bool                   `json:"optional,omitempty"`
}

// ClientMetadata represents verifier/client metadata
type ClientMetadata struct {
	ClientName    string                 `json:"client_name,omitempty"`
	LogoURI       string                 `json:"logo_uri,omitempty"`
	ClientPurpose string                 `json:"client_purpose,omitempty"`
	VPFormats     map[string]interface{} `json:"vp_formats,omitempty"`
	// Key material for trust evaluation
	JWKS    json.RawMessage `json:"jwks,omitempty"`
	JWKsURI string          `json:"jwks_uri,omitempty"`
	X5C     []string        `json:"x5c,omitempty"`
}

// RequestedClaim describes a claim being requested
type RequestedClaim struct {
	Path     string `json:"path"`
	Required bool   `json:"required"`
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

	// Step 3: Send parsed request info to client
	requestedClaims := h.extractRequestedClaims(authReq.PresentationDefinition)
	_ = h.Progress(StepRequestParsed, map[string]interface{}{
		"verifier":                verifier,
		"presentation_definition": authReq.PresentationDefinition,
		"requested_claims":        requestedClaims,
	})

	// Step 4: Request client-side credential matching (privacy-preserving)
	matches, err := h.requestCredentialMatching(ctx, authReq.PresentationDefinition)
	if err != nil {
		return err
	}

	if len(matches) == 0 {
		_ = h.Error(StepMatchCredentials, ErrCodePresentationError, "No matching credentials found")
		return errors.New("no matching credentials")
	}

	// Step 5: Request user consent
	selectedCredentials, err := h.requestConsent(ctx, matches, verifier)
	if err != nil {
		return err
	}

	// Step 6: Request VP signing from client (use configured ClientID for audience if set)
	vpToken, err := h.requestVPSignature(ctx, authReq, selectedCredentials, verifier.ClientID)
	if err != nil {
		h.Logger.Debug("VP signature failed", zap.Error(err))
		_ = h.Error(StepSubmittingResponse, ErrCodeSignError, ErrCodeSignError.UserFacingMessage())
		return err
	}

	// Step 7: Submit VP response to verifier
	result, err := h.submitResponse(ctx, authReq, vpToken)
	if err != nil {
		h.Logger.Debug("VP submission failed", zap.Error(err))
		_ = h.Error(StepSubmittingResponse, ErrCodePresentationError, ErrCodePresentationError.UserFacingMessage())
		return err
	}

	// Step 8: Complete
	if result.vpResponse != nil {
		// DC API mode: send VP response data to frontend for postMessage delivery
		msg := FlowCompleteMessage{
			Message: Message{
				Type:      TypeFlowComplete,
				FlowID:    h.Flow.ID,
				Timestamp: Now(),
			},
			ResponseData: result.vpResponse,
		}
		return h.Flow.Session.Send(&msg)
	}
	return h.Complete(nil, result.redirectURI)
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

	// Parse presentation_definition if inline
	if pdStr := q.Get("presentation_definition"); pdStr != "" {
		var pd PresentationDefinition
		if err := json.Unmarshal([]byte(pdStr), &pd); err != nil {
			return nil, fmt.Errorf("invalid presentation_definition: %w", err)
		}
		authReq.PresentationDefinition = &pd
	}
	authReq.PresentationDefinitionURI = q.Get("presentation_definition_uri")

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
	bodyStr := string(body)
	if strings.Count(bodyStr, ".") == 2 {
		// Likely a JWT
		return h.parseRequestJWT(bodyStr)
	}

	var authReq AuthorizationRequest
	if err := json.Unmarshal(body, &authReq); err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}

	return &authReq, nil
}

func (h *OID4VPHandler) evaluateVerifierTrust(ctx context.Context, authReq *AuthorizationRequest) (*VerifierInfo, error) {
	_ = h.ProgressMessage(StepEvaluatingVerifierTrust, "Evaluating verifier trust")

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
		}
	}

	// Fetch presentation_definition if needed
	if authReq.PresentationDefinition == nil && authReq.PresentationDefinitionURI != "" {
		pd, err := h.fetchPresentationDefinition(ctx, authReq.PresentationDefinitionURI)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch presentation definition: %w", err)
		}
		authReq.PresentationDefinition = pd
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

	// Cache trust evaluation result (best-effort, don't block the flow)
	h.cacheVerifierTrust(ctx, authReq, verifier)

	// Look up stored verifier to get configured ClientID for VP audience
	canonicalURL := getCanonicalVerifierURL(authReq)
	if stored := h.getCachedVerifierTrust(ctx, canonicalURL); stored != nil && stored.ClientID != "" {
		verifier.ClientID = stored.ClientID
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
// Returns nil if no cache is available or lookup fails.
func (h *OID4VPHandler) getCachedVerifierTrust(ctx context.Context, verifierURL string) *domain.Verifier {
	if h.Verifiers == nil {
		return nil
	}

	tenantID := domain.TenantID("default")
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		tenantID = domain.TenantID(h.Flow.Session.TenantID)
	}

	cached, err := h.Verifiers.GetByURL(ctx, tenantID, verifierURL)
	if err != nil {
		return nil // Not found or error — proceed with fresh evaluation
	}
	return cached
}

// cacheVerifierTrust persists verifier trust evaluation results for future lookups.
// This is best-effort — failures are logged but don't affect the flow.
func (h *OID4VPHandler) cacheVerifierTrust(ctx context.Context, authReq *AuthorizationRequest, verifier *VerifierInfo) {
	if h.Verifiers == nil {
		return // No store available (standalone engine mode)
	}

	tenantID := domain.TenantID("default")
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		tenantID = domain.TenantID(h.Flow.Session.TenantID)
	}

	var trustStatus domain.TrustStatus
	if verifier.Trusted {
		trustStatus = domain.TrustStatusTrusted
	} else {
		trustStatus = domain.TrustStatusUntrusted
	}

	now := time.Now()
	v := &domain.Verifier{
		TenantID:         tenantID,
		Name:             verifier.Name,
		URL:              getCanonicalVerifierURL(authReq),
		ClientIDScheme:   authReq.ClientIDScheme,
		TrustStatus:      trustStatus,
		TrustFramework:   verifier.Framework,
		TrustEvaluatedAt: &now,
	}
	// Note: ClientID is intentionally NOT set here.
	// If admin has configured a custom ClientID via the admin API,
	// the Upsert will preserve it from the existing record.

	if err := h.Verifiers.Upsert(ctx, v); err != nil {
		h.Logger.Warn("Failed to cache verifier trust result",
			zap.String("client_id", authReq.ClientID),
			zap.Error(err))
	}
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

func (h *OID4VPHandler) fetchPresentationDefinition(ctx context.Context, uri string) (*PresentationDefinition, error) {
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
		return nil, fmt.Errorf("presentation definition fetch returned status %d", resp.StatusCode)
	}

	var pd PresentationDefinition
	if err := json.NewDecoder(resp.Body).Decode(&pd); err != nil {
		return nil, err
	}

	return &pd, nil
}

func (h *OID4VPHandler) extractRequestedClaims(pd *PresentationDefinition) []RequestedClaim {
	if pd == nil {
		return nil
	}

	var claims []RequestedClaim
	seen := make(map[string]bool)

	for _, desc := range pd.InputDescriptors {
		if desc.Constraints == nil {
			continue
		}
		for _, field := range desc.Constraints.Fields {
			for _, path := range field.Path {
				// Normalize path (remove $. prefix if present)
				normalizedPath := strings.TrimPrefix(path, "$.")
				if seen[normalizedPath] {
					continue
				}
				seen[normalizedPath] = true
				claims = append(claims, RequestedClaim{
					Path:     normalizedPath,
					Required: !field.Optional,
				})
			}
		}
	}

	return claims
}

func (h *OID4VPHandler) requestCredentialMatching(ctx context.Context, pd *PresentationDefinition) ([]CredentialMatch, error) {
	// Send match_request to client for local matching (privacy-preserving)
	// The client matches credentials locally and returns only the matching credential IDs/metadata
	resp, err := h.RequestMatch(ctx, pd)
	if err != nil {
		if errors.Is(err, ErrMatchTimeout) {
			h.Logger.Warn("Credential matching timed out")
			// Notify client that matching timed out so UI can show appropriate message
			_ = h.Error(StepMatchCredentials, ErrCodeMatchTimeout, "Credential matching timed out")
			return nil, err
		}
		h.Logger.Debug("Credential matching failed", zap.Error(err))
		return nil, err
	}

	if resp.NoMatchReason != "" {
		h.Logger.Info("No credentials matched", zap.String("reason", resp.NoMatchReason))
	}

	return resp.Matches, nil
}

func (h *OID4VPHandler) requestConsent(ctx context.Context, matches []CredentialMatch, verifier *VerifierInfo) ([]ConsentSelection, error) {
	// Build matched credentials display
	matchedCredentials := make([]MatchedCredential, len(matches))
	for i, m := range matches {
		matchedCredentials[i] = MatchedCredential{
			InputDescriptorID: m.InputDescriptorID,
			CredentialID:      m.CredentialID,
			DisclosableClaims: m.AvailableClaims,
		}

		// Fetch credential display from VCTM if available
		if m.VCT != "" && h.Registry != nil {
			matchedCredentials[i].CredentialDisplay = h.Registry.FetchTypeMetadataJSON(ctx, m.VCT)
		}
	}

	_ = h.Progress(StepAwaitingConsent, map[string]interface{}{
		"matched_credentials": matchedCredentials,
		"verifier":            verifier,
	})

	// Wait for consent or decline
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
		_ = h.Error(StepAwaitingConsent, ErrCodePresentationError, "User declined the request")
		return nil, errors.New("user declined presentation")
	}

	var payload ConsentPayload
	if err := json.Unmarshal(action.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid consent payload: %w", err)
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

// vpSubmitResult holds the result of VP response submission.
// For server-side delivery (direct_post), redirectURI may be set.
// For client-side delivery (dc_api), vpResponse contains the payload.
type vpSubmitResult struct {
	redirectURI string
	vpResponse  map[string]interface{}
}

func (h *OID4VPHandler) submitResponse(ctx context.Context, authReq *AuthorizationRequest, vpToken string) (*vpSubmitResult, error) {
	// Determine response mode
	responseMode := authReq.ResponseMode
	if responseMode == "" {
		responseMode = "direct_post"
	}

	// DC API modes: response is delivered client-side via postMessage (no server submission)
	if responseMode == "dc_api" {
		_ = h.ProgressMessage(StepSubmittingResponse, "Preparing DC API response")
		return h.buildDCAPIResponse(authReq, vpToken)
	}

	_ = h.ProgressMessage(StepSubmittingResponse, "Submitting VP response")

	// Server-side delivery modes require a response endpoint
	responseEndpoint := authReq.ResponseURI
	if responseEndpoint == "" {
		responseEndpoint = authReq.RedirectURI
	}
	if responseEndpoint == "" {
		return nil, errors.New("no response endpoint in request")
	}

	switch responseMode {
	case "direct_post":
		redirectURI, err := h.submitDirectPost(ctx, responseEndpoint, authReq, vpToken)
		if err != nil {
			return nil, err
		}
		return &vpSubmitResult{redirectURI: redirectURI}, nil
	case "fragment":
		return &vpSubmitResult{redirectURI: h.buildFragmentRedirect(responseEndpoint, authReq, vpToken)}, nil
	case "query":
		return &vpSubmitResult{redirectURI: h.buildQueryRedirect(responseEndpoint, authReq, vpToken)}, nil
	default:
		return nil, fmt.Errorf("unsupported response_mode: %s", responseMode)
	}
}

// buildDCAPIResponse builds the VP response payload for W3C Digital Credentials API delivery.
// Instead of posting to a verifier endpoint, the response data is returned to the frontend
// which delivers it via window.opener.postMessage() to the requesting origin.
func (h *OID4VPHandler) buildDCAPIResponse(authReq *AuthorizationRequest, vpToken string) (*vpSubmitResult, error) {
	responseData := map[string]interface{}{
		"vp_token": vpToken,
	}

	if authReq.PresentationDefinition != nil {
		submission := h.buildPresentationSubmission(authReq.PresentationDefinition)
		submissionJSON, err := json.Marshal(submission)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal presentation_submission: %w", err)
		}
		responseData["presentation_submission"] = string(submissionJSON)
	}

	if authReq.State != "" {
		responseData["state"] = authReq.State
	}

	return &vpSubmitResult{vpResponse: responseData}, nil
}

func (h *OID4VPHandler) submitDirectPost(ctx context.Context, endpoint string, authReq *AuthorizationRequest, vpToken string) (string, error) {
	data := url.Values{}
	data.Set("vp_token", vpToken)
	if authReq.State != "" {
		data.Set("state", authReq.State)
	}

	// Build presentation_submission
	submission := h.buildPresentationSubmission(authReq.PresentationDefinition)
	submissionJSON, _ := json.Marshal(submission)
	data.Set("presentation_submission", string(submissionJSON))

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

func (h *OID4VPHandler) buildPresentationSubmission(pd *PresentationDefinition) map[string]interface{} {
	if pd == nil {
		return nil
	}

	descriptorMap := make([]map[string]interface{}, len(pd.InputDescriptors))
	for i, desc := range pd.InputDescriptors {
		descriptorMap[i] = map[string]interface{}{
			"id":     desc.ID,
			"format": "jwt_vp",
			"path":   "$",
		}
	}

	return map[string]interface{}{
		"id":             pd.ID + "_submission",
		"definition_id":  pd.ID,
		"descriptor_map": descriptorMap,
	}
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
