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

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// OID4VPHandler handles OpenID4VP credential presentation flows
type OID4VPHandler struct {
	BaseHandler
	httpClient *http.Client
}

// NewOID4VPHandler creates a new OID4VP flow handler
func NewOID4VPHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient) (FlowHandler, error) {
	return &OID4VPHandler{
		BaseHandler: BaseHandler{
			Flow:     flow,
			Config:   cfg,
			Logger:   logger,
			TrustSvc: trustSvc,
			Registry: registry,
		},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// OID4VP data structures

// AuthorizationRequest represents an OpenID4VP authorization request
type AuthorizationRequest struct {
	ResponseType              string                  `json:"response_type"`
	ClientID                  string                  `json:"client_id"`
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

	// Step 1: Parse authorization request
	authReq, err := h.parseRequest(ctx, msg)
	if err != nil {
		h.Error(StepParsingRequest, ErrCodeOfferParseError, err.Error())
		return err
	}
	h.SetData("auth_request", authReq)

	// Step 2: Evaluate verifier trust
	verifier, err := h.evaluateVerifierTrust(ctx, authReq)
	if err != nil {
		h.Error(StepEvaluatingVerifierTrust, ErrCodeUntrustedVerifier, err.Error())
		return err
	}

	// Step 3: Send parsed request info to client
	requestedClaims := h.extractRequestedClaims(authReq.PresentationDefinition)
	h.Progress(StepRequestParsed, map[string]interface{}{
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
		h.Error(StepMatchCredentials, ErrCodePresentationError, "No matching credentials found")
		return errors.New("no matching credentials")
	}

	// Step 5: Request user consent
	selectedCredentials, err := h.requestConsent(ctx, matches, verifier)
	if err != nil {
		return err
	}

	// Step 6: Request VP signing from client
	vpToken, err := h.requestVPSignature(ctx, authReq, selectedCredentials)
	if err != nil {
		h.Error(StepSubmittingResponse, ErrCodeSignError, err.Error())
		return err
	}

	// Step 7: Submit VP response to verifier
	redirectURI, err := h.submitResponse(ctx, authReq, vpToken)
	if err != nil {
		h.Error(StepSubmittingResponse, ErrCodePresentationError, err.Error())
		return err
	}

	// Step 8: Complete
	return h.Complete(nil, redirectURI)
}

func (h *OID4VPHandler) parseRequest(ctx context.Context, msg *FlowStartMessage) (*AuthorizationRequest, error) {
	h.ProgressMessage(StepParsingRequest, "Parsing authorization request")

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
		ResponseType: q.Get("response_type"),
		ClientID:     q.Get("client_id"),
		ResponseMode: q.Get("response_mode"),
		ResponseURI:  q.Get("response_uri"),
		RedirectURI:  q.Get("redirect_uri"),
		Nonce:        q.Get("nonce"),
		State:        q.Get("state"),
		Scope:        q.Get("scope"),
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
	defer resp.Body.Close()

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
	h.ProgressMessage(StepEvaluatingVerifierTrust, "Evaluating verifier trust")

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
		Name: authReq.ClientID,
	}

	if clientMeta != nil {
		if clientMeta.ClientName != "" {
			verifier.Name = clientMeta.ClientName
		}
		if clientMeta.LogoURI != "" {
			verifier.Logo = &LogoInfo{URI: clientMeta.LogoURI}
		}
	}

	// Evaluate trust via TrustService
	trustEndpoint := "" // TODO: Look up tenant's trust endpoint from session.TenantID
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		// In future: load tenant config and get trust endpoint
		// trustEndpoint = tenant.TrustConfig.TrustEndpoint
	}

	trustInfo, err := h.TrustSvc.EvaluateVerifier(ctx, authReq.ClientID, trustEndpoint)
	if err != nil {
		h.Logger.Warn("Verifier trust evaluation failed", zap.String("verifier", authReq.ClientID), zap.Error(err))
		verifier.Trusted = false
		verifier.Framework = "error"
	} else {
		verifier.Trusted = trustInfo.Trusted
		verifier.Framework = trustInfo.Framework
	}

	return verifier, nil
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
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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
	h.Progress(StepMatchCredentials, map[string]interface{}{
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
			// TODO: Fetch credential display from VCTM
		}
	}

	h.Progress(StepAwaitingConsent, map[string]interface{}{
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
		h.Error(StepAwaitingConsent, ErrCodePresentationError, "User declined: "+decline.Reason)
		return nil, errors.New("user declined presentation")
	}

	var payload ConsentPayload
	if err := json.Unmarshal(action.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid consent payload: %w", err)
	}

	return payload.SelectedCredentials, nil
}

func (h *OID4VPHandler) requestVPSignature(ctx context.Context, authReq *AuthorizationRequest, selected []ConsentSelection) (string, error) {
	// Convert selections to credential refs
	credRefs := make([]CredentialRef, len(selected))
	for i, s := range selected {
		credRefs[i] = CredentialRef{
			CredentialID:    s.CredentialID,
			DisclosedClaims: s.DisclosedClaims,
		}
	}

	resp, err := h.RequestSign(ctx, SignActionSignPresentation, SignRequestParams{
		Audience:             authReq.ClientID,
		Nonce:                authReq.Nonce,
		CredentialsToInclude: credRefs,
	})
	if err != nil {
		return "", err
	}

	return resp.VPToken, nil
}

func (h *OID4VPHandler) submitResponse(ctx context.Context, authReq *AuthorizationRequest, vpToken string) (string, error) {
	h.ProgressMessage(StepSubmittingResponse, "Submitting VP response")

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
	defer resp.Body.Close()

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
