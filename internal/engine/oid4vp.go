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
		_ = h.Error(StepParsingRequest, ErrCodeOfferParseError, err.Error())
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
		_ = h.Error(StepEvaluatingVerifierTrust, ErrCodeUntrustedVerifier, err.Error())
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
		_ = h.Error(StepSubmittingResponse, ErrCodeSignError, err.Error())
		return err
	}

	// Step 7: Submit VP response to verifier
	redirectURI, err := h.submitResponse(ctx, authReq, vpToken)
	if err != nil {
		_ = h.Error(StepSubmittingResponse, ErrCodePresentationError, err.Error())
		return err
	}

	// Step 8: Complete
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

	body, err := io.ReadAll(resp.Body)
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
	var keyMaterial *KeyMaterial
	var err error
	switch authReq.ClientIDScheme {
	case ClientIDSchemeDID:
		// DID scheme: request MUST be JWT-secured; verify signature with embedded key
		keyMaterial, err = h.verifyDIDRequest(authReq)
		if err != nil {
			return nil, fmt.Errorf("DID verifier request validation failed: %w", err)
		}

	case ClientIDSchemeX509SANDNS:
		// X.509 scheme: request MUST be JWT-secured; verify signature with x5c
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

	// Evaluate trust via TrustService
	trustEndpoint := ""
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TrustEndpoint != "" {
		trustEndpoint = h.Flow.Session.TrustEndpoint
	}

	// Check cached trust result (skip PDP call if fresh)
	const trustCacheTTL = 5 * time.Minute
	canonicalURL := getCanonicalVerifierURL(authReq)
	if cached := h.getCachedVerifierTrust(ctx, canonicalURL); cached != nil {
		if cached.TrustEvaluatedAt != nil && time.Since(*cached.TrustEvaluatedAt) < trustCacheTTL {
			h.Logger.Debug("Using cached verifier trust",
				zap.String("client_id", authReq.ClientID),
				zap.String("status", string(cached.TrustStatus)))
			verifier.Trusted = cached.TrustStatus == domain.TrustStatusTrusted
			verifier.TrustedStatus = string(cached.TrustStatus)
			verifier.Framework = cached.TrustFramework
			// Use stored ClientID for VP audience if configured
			if cached.ClientID != "" {
				verifier.ClientID = cached.ClientID
			}

			// Still enforce trust even from cache
			trustEnforced := h.TrustSvc.IsVerifierTrustEnabled() || trustEndpoint != ""
			if trustEnforced && !verifier.Trusted {
				return nil, fmt.Errorf("untrusted verifier %s (cached)", authReq.ClientID)
			}
			return verifier, nil
		}
	}

	trustInfo, err := h.TrustSvc.EvaluateVerifier(ctx, authReq.ClientID, trustEndpoint, keyMaterial)
	if err != nil {
		h.Logger.Warn("Verifier trust evaluation failed", zap.String("verifier", authReq.ClientID), zap.Error(err))
		verifier.Trusted = false
		verifier.TrustedStatus = string(domain.TrustStatusUnknown)
		verifier.Framework = "error"
		verifier.Reason = err.Error()
	} else {
		verifier.Trusted = trustInfo.Trusted
		verifier.Framework = trustInfo.Framework
		verifier.Reason = trustInfo.Reason
		if trustInfo.Trusted {
			verifier.TrustedStatus = string(domain.TrustStatusTrusted)
		} else {
			verifier.TrustedStatus = string(domain.TrustStatusUntrusted)
		}
	}

	// Cache trust evaluation result (best-effort, don't block the flow)
	h.cacheVerifierTrust(ctx, authReq, verifier)

	// Look up stored verifier to get configured ClientID for VP audience
	if stored := h.getCachedVerifierTrust(ctx, canonicalURL); stored != nil && stored.ClientID != "" {
		verifier.ClientID = stored.ClientID
	}

	// Enforce trust decision: block untrusted verifiers when a PDP URL is configured.
	trustEnforced := h.TrustSvc.IsVerifierTrustEnabled() || trustEndpoint != ""
	if trustEnforced && !verifier.Trusted {
		reason := "verifier not trusted"
		if trustInfo != nil && trustInfo.Reason != "" {
			reason = trustInfo.Reason
		}
		h.Logger.Warn("Blocking untrusted verifier",
			zap.String("verifier", authReq.ClientID),
			zap.String("reason", reason))
		return nil, fmt.Errorf("untrusted verifier %s: %s", authReq.ClientID, reason)
	}

	return verifier, nil
}

// verifyDIDRequest validates a DID-identified verifier's request.
// Per OID4VP, when client_id_scheme=did, the request MUST be a signed JWT
// and the JWT's key material must bind to the DID (verified by the PDP).
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
	// Send presentation_definition to client for local matching
	_ = h.Progress(StepMatchCredentials, map[string]interface{}{
		"presentation_definition": pd,
	})

	// Wait for client response
	action, err := h.WaitForAction(ctx, ActionCredentialsMatched)
	if err != nil {
		return nil, err
	}

	var payload CredentialsMatchedPayload
	if err := json.Unmarshal(action.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid credentials_matched payload: %w", err)
	}

	if payload.NoMatchReason != "" {
		h.Logger.Info("No credentials matched", zap.String("reason", payload.NoMatchReason))
	}

	return payload.Matches, nil
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
		_ = h.Error(StepAwaitingConsent, ErrCodePresentationError, "User declined: "+decline.Reason)
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

	// Determine response mode
	responseMode := authReq.ResponseMode
	if responseMode == "" {
		responseMode = "direct_post"
	}

	switch responseMode {
	case "direct_post":
		return h.submitDirectPost(ctx, responseEndpoint, authReq, vpToken)
	case "fragment":
		return h.buildFragmentRedirect(responseEndpoint, authReq, vpToken), nil
	case "query":
		return h.buildQueryRedirect(responseEndpoint, authReq, vpToken), nil
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

	body, _ := io.ReadAll(resp.Body)
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
	if strings.HasPrefix(clientID, "did:") {
		return ClientIDSchemeDID
	}
	return ClientIDSchemeRedirectURI
}
