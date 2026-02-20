package engine

import (
	"context"
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

// OID4VCIHandler handles OpenID4VCI credential issuance flows
type OID4VCIHandler struct {
	BaseHandler
	httpClient *http.Client
}

// NewOID4VCIHandler creates a new OID4VCI flow handler
func NewOID4VCIHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient) (FlowHandler, error) {
	return &OID4VCIHandler{
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

// OID4VCI data structures

// CredentialOffer represents an OpenID4VCI credential offer
type CredentialOffer struct {
	CredentialIssuer           string                 `json:"credential_issuer"`
	CredentialConfigurationIDs []string               `json:"credential_configuration_ids"`
	Grants                     map[string]interface{} `json:"grants,omitempty"`
}

// IssuerMetadata represents OpenID4VCI issuer metadata
type IssuerMetadata struct {
	CredentialIssuer                  string                      `json:"credential_issuer"`
	CredentialEndpoint                string                      `json:"credential_endpoint"`
	TokenEndpoint                     string                      `json:"token_endpoint,omitempty"`
	AuthorizationServer               string                      `json:"authorization_server,omitempty"`
	Display                           []IssuerDisplay             `json:"display,omitempty"`
	CredentialConfigurationsSupported map[string]CredentialConfig `json:"credential_configurations_supported,omitempty"`
}

// IssuerDisplay represents issuer display information
type IssuerDisplay struct {
	Name   string    `json:"name"`
	Locale string    `json:"locale,omitempty"`
	Logo   *LogoInfo `json:"logo,omitempty"`
}

// CredentialConfig represents a credential configuration
type CredentialConfig struct {
	Format              string                 `json:"format"`
	VCT                 string                 `json:"vct,omitempty"`
	Scope               string                 `json:"scope,omitempty"`
	Display             []CredentialDisplay    `json:"display,omitempty"`
	ProofTypesSupported map[string]interface{} `json:"proof_types_supported,omitempty"`
	Claims              map[string]interface{} `json:"claims,omitempty"`
}

// CredentialDisplay represents credential display information
type CredentialDisplay struct {
	Name            string    `json:"name"`
	Description     string    `json:"description,omitempty"`
	Locale          string    `json:"locale,omitempty"`
	Logo            *LogoInfo `json:"logo,omitempty"`
	TextColor       string    `json:"text_color,omitempty"`
	BackgroundColor string    `json:"background_color,omitempty"`
}

// TokenResponse represents OAuth token endpoint response
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	CNonce          string `json:"c_nonce,omitempty"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
}

// CredentialResponse represents credential endpoint response
type CredentialResponse struct {
	Credential      interface{}   `json:"credential,omitempty"`
	Credentials     []interface{} `json:"credentials,omitempty"`
	CNonce          string        `json:"c_nonce,omitempty"`
	CNonceExpiresIn int           `json:"c_nonce_expires_in,omitempty"`
	TransactionID   string        `json:"transaction_id,omitempty"`
	NotificationID  string        `json:"notification_id,omitempty"`
}

// AvailableCredential represents a credential available for selection
type AvailableCredential struct {
	ID      string             `json:"id"`
	Display *CredentialDisplay `json:"display,omitempty"`
	Format  string             `json:"format"`
	VCT     string             `json:"vct,omitempty"`
}

// Execute runs the OID4VCI flow
func (h *OID4VCIHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	ctx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	defer cancel()

	// Step 1: Parse credential offer
	offer, err := h.parseOffer(ctx, msg)
	if err != nil {
		h.Error(StepParsingOffer, ErrCodeOfferParseError, err.Error())
		return err
	}
	h.SetData("offer", offer)

	// Step 2: Fetch issuer metadata
	metadata, err := h.fetchMetadata(ctx, offer.CredentialIssuer)
	if err != nil {
		h.Error(StepFetchingMetadata, ErrCodeMetadataFetchErr, err.Error())
		return err
	}
	h.SetData("metadata", metadata)

	// Step 3: Evaluate trust
	trust, err := h.evaluateTrust(ctx, offer.CredentialIssuer, metadata)
	if err != nil {
		h.Error(StepEvaluatingTrust, ErrCodeUntrustedIssuer, err.Error())
		return err
	}

	// Step 4: User selects credential configuration
	selectedConfig, err := h.awaitCredentialSelection(ctx, offer, metadata)
	if err != nil {
		return err
	}
	h.SetData("selected_config", selectedConfig)

	// Step 5: Handle authorization
	token, err := h.handleAuthorization(ctx, offer, metadata)
	if err != nil {
		return err
	}

	// Step 6: Generate proof (if required)
	var proofJWT string
	if h.needsProof(selectedConfig) {
		proof, err := h.requestProof(ctx, metadata.CredentialIssuer, token.CNonce)
		if err != nil {
			h.Error(StepRequestingCredential, ErrCodeSignError, err.Error())
			return err
		}
		proofJWT = proof
	}

	// Step 7: Request credential
	credential, err := h.requestCredential(ctx, metadata, token, selectedConfig, proofJWT)
	if err != nil {
		return err
	}

	// Step 8: Handle deferred or immediate issuance
	if credential.TransactionID != "" {
		// Deferred issuance
		h.Progress(StepDeferred, map[string]interface{}{
			"transaction_id": credential.TransactionID,
			"interval":       5,
			"message":        "Credential issuance is pending",
		})
		// TODO: Implement polling
		return nil
	}

	// Step 9: Complete with issued credential (fetch VCTM for display)
	results := h.buildCredentialResults(ctx, credential, selectedConfig, trust)
	return h.Complete(results, "")
}

func (h *OID4VCIHandler) parseOffer(ctx context.Context, msg *FlowStartMessage) (*CredentialOffer, error) {
	h.ProgressMessage(StepParsingOffer, "Parsing credential offer")

	var offerStr string

	if msg.Offer != "" {
		// Parse from openid-credential-offer:// URL
		offerStr = msg.Offer
		if strings.HasPrefix(offerStr, "openid-credential-offer://") {
			// Extract credential_offer parameter
			u, err := url.Parse(offerStr)
			if err != nil {
				return nil, fmt.Errorf("invalid offer URL: %w", err)
			}
			offerStr = u.Query().Get("credential_offer")
			if offerStr == "" {
				// Try credential_offer_uri
				offerURI := u.Query().Get("credential_offer_uri")
				if offerURI != "" {
					return h.fetchOfferFromURI(ctx, offerURI)
				}
				return nil, errors.New("offer URL missing credential_offer parameter")
			}
		}
	} else if msg.CredentialOfferURI != "" {
		return h.fetchOfferFromURI(ctx, msg.CredentialOfferURI)
	} else {
		return nil, errors.New("no offer provided")
	}

	var offer CredentialOffer
	if err := json.Unmarshal([]byte(offerStr), &offer); err != nil {
		return nil, fmt.Errorf("invalid offer JSON: %w", err)
	}

	h.Progress(StepOfferParsed, map[string]interface{}{
		"credential_issuer":            offer.CredentialIssuer,
		"credential_configuration_ids": offer.CredentialConfigurationIDs,
		"grants":                       offer.Grants,
	})

	return &offer, nil
}

func (h *OID4VCIHandler) fetchOfferFromURI(ctx context.Context, uri string) (*CredentialOffer, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch offer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("offer fetch returned status %d", resp.StatusCode)
	}

	var offer CredentialOffer
	if err := json.NewDecoder(resp.Body).Decode(&offer); err != nil {
		return nil, fmt.Errorf("failed to parse offer: %w", err)
	}

	return &offer, nil
}

func (h *OID4VCIHandler) fetchMetadata(ctx context.Context, issuer string) (*IssuerMetadata, error) {
	h.ProgressMessage(StepFetchingMetadata, "Fetching issuer metadata")

	// Fetch from well-known endpoint
	metadataURL := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-credential-issuer"

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("metadata fetch returned status %d: %s", resp.StatusCode, string(body))
	}

	var metadata IssuerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	h.Progress(StepMetadataFetched, map[string]interface{}{
		"credential_issuer":   metadata.CredentialIssuer,
		"credential_endpoint": metadata.CredentialEndpoint,
		"display":             metadata.Display,
	})

	return &metadata, nil
}

func (h *OID4VCIHandler) evaluateTrust(ctx context.Context, issuer string, metadata *IssuerMetadata) (*TrustInfo, error) {
	h.ProgressMessage(StepEvaluatingTrust, "Evaluating issuer trust")

	// Get tenant trust endpoint (if configured)
	// For now, use the default trust endpoint
	trustEndpoint := "" // TODO: Look up tenant's trust endpoint from session.TenantID
	if h.Flow != nil && h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		// In future: load tenant config and get trust endpoint
		// trustEndpoint = tenant.TrustConfig.TrustEndpoint
	}

	trust, err := h.TrustSvc.EvaluateIssuer(ctx, issuer, trustEndpoint)
	if err != nil {
		h.Logger.Error("Trust evaluation failed", zap.String("issuer", issuer), zap.Error(err))
		trust = &TrustInfo{
			Trusted:   false,
			Framework: "error",
			Reason:    "Trust evaluation error: " + err.Error(),
		}
	}

	h.Progress(StepTrustEvaluated, trust)
	return trust, nil
}

func (h *OID4VCIHandler) awaitCredentialSelection(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata) (*CredentialConfig, error) {
	// Build available credentials list
	available := make([]AvailableCredential, 0, len(offer.CredentialConfigurationIDs))
	for _, configID := range offer.CredentialConfigurationIDs {
		config, ok := metadata.CredentialConfigurationsSupported[configID]
		if !ok {
			continue
		}
		var display *CredentialDisplay
		if len(config.Display) > 0 {
			display = &config.Display[0]
		}
		available = append(available, AvailableCredential{
			ID:      configID,
			Display: display,
			Format:  config.Format,
			VCT:     config.VCT,
		})
	}

	// If only one credential, auto-select
	if len(available) == 1 {
		configID := available[0].ID
		config := metadata.CredentialConfigurationsSupported[configID]
		return &config, nil
	}

	// Send selection request
	h.Progress(StepAwaitingSelection, map[string]interface{}{
		"available_credentials": available,
	})

	// Wait for user selection
	action, err := h.WaitForAction(ctx, ActionSelectCredential)
	if err != nil {
		return nil, err
	}

	// Parse selection
	var selection struct {
		CredentialConfigurationID string `json:"credential_configuration_id"`
	}
	if err := json.Unmarshal(action.Payload, &selection); err != nil {
		h.Error(StepAwaitingSelection, ErrCodeInvalidMessage, "Invalid selection payload")
		return nil, err
	}

	config, ok := metadata.CredentialConfigurationsSupported[selection.CredentialConfigurationID]
	if !ok {
		h.Error(StepAwaitingSelection, ErrCodeInvalidMessage, "Invalid credential configuration")
		return nil, errors.New("invalid credential configuration")
	}

	return &config, nil
}

func (h *OID4VCIHandler) handleAuthorization(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata) (*TokenResponse, error) {
	// Check for pre-authorized code grant
	if grants, ok := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]; ok {
		grantMap, ok := grants.(map[string]interface{})
		if ok {
			return h.handlePreAuthorized(ctx, metadata, grantMap)
		}
	}

	// Check for authorization_code grant
	if _, ok := offer.Grants["authorization_code"]; ok {
		return h.handleAuthorizationCode(ctx, offer, metadata)
	}

	return nil, errors.New("no supported grant type in offer")
}

func (h *OID4VCIHandler) handlePreAuthorized(ctx context.Context, metadata *IssuerMetadata, grant map[string]interface{}) (*TokenResponse, error) {
	preAuthCode, _ := grant["pre-authorized_code"].(string)

	// Check if TX code required
	if txCodeRequired, ok := grant["tx_code"]; ok && txCodeRequired != nil {
		// Request TX code from user
		h.Progress(StepAuthorizationReq, map[string]interface{}{
			"type":    "tx_code",
			"message": "Please enter the transaction code",
		})

		action, err := h.WaitForAction(ctx, ActionProvidePin)
		if err != nil {
			return nil, err
		}

		var pinData struct {
			TxCode string `json:"tx_code"`
		}
		if err := json.Unmarshal(action.Payload, &pinData); err != nil {
			return nil, err
		}

		return h.exchangePreAuthCode(ctx, metadata, preAuthCode, pinData.TxCode)
	}

	return h.exchangePreAuthCode(ctx, metadata, preAuthCode, "")
}

func (h *OID4VCIHandler) exchangePreAuthCode(ctx context.Context, metadata *IssuerMetadata, code, txCode string) (*TokenResponse, error) {
	h.ProgressMessage(StepExchangingToken, "Exchanging pre-authorized code for token")

	tokenEndpoint := metadata.TokenEndpoint
	if tokenEndpoint == "" {
		// Try to construct from issuer
		tokenEndpoint = strings.TrimSuffix(metadata.CredentialIssuer, "/") + "/token"
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	data.Set("pre-authorized_code", code)
	if txCode != "" {
		data.Set("tx_code", txCode)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		h.Error(StepExchangingToken, ErrCodeTokenError, string(body))
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	h.ProgressMessage(StepTokenObtained, "Access token obtained")
	return &token, nil
}

func (h *OID4VCIHandler) handleAuthorizationCode(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata) (*TokenResponse, error) {
	// Build authorization URL
	authServer := metadata.AuthorizationServer
	if authServer == "" {
		authServer = metadata.CredentialIssuer
	}

	// Fetch OAuth metadata
	oauthMetadataURL := strings.TrimSuffix(authServer, "/") + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, "GET", oauthMetadataURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		// Fallback: construct auth URL directly
		return h.startAuthorizationFlow(ctx, offer, metadata, authServer+"/authorize")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var oauthMeta struct {
			AuthorizationEndpoint string `json:"authorization_endpoint"`
			TokenEndpoint         string `json:"token_endpoint"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&oauthMeta); err == nil && oauthMeta.AuthorizationEndpoint != "" {
			return h.startAuthorizationFlow(ctx, offer, metadata, oauthMeta.AuthorizationEndpoint)
		}
	}

	return h.startAuthorizationFlow(ctx, offer, metadata, authServer+"/authorize")
}

func (h *OID4VCIHandler) startAuthorizationFlow(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata, authEndpoint string) (*TokenResponse, error) {
	// Build authorization URL with PKCE
	// Note: In a real implementation, we'd use proper PKCE and state
	redirectURI := h.Config.Server.BaseURL + "/callback"

	authURL, _ := url.Parse(authEndpoint)
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", metadata.CredentialIssuer) // Use issuer as client_id
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid") // Basic scope
	if grant, ok := offer.Grants["authorization_code"].(map[string]interface{}); ok {
		if issuerState, ok := grant["issuer_state"].(string); ok {
			q.Set("issuer_state", issuerState)
		}
	}
	authURL.RawQuery = q.Encode()

	h.Progress(StepAuthorizationReq, map[string]interface{}{
		"authorization_url":     authURL.String(),
		"expected_redirect_uri": redirectURI,
	})

	// Wait for authorization complete
	action, err := h.WaitForAction(ctx, ActionAuthorizationComplete)
	if err != nil {
		return nil, err
	}

	var authResult struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(action.Payload, &authResult); err != nil {
		h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "Invalid authorization response")
		return nil, err
	}

	// Exchange code for token
	return h.exchangeAuthCode(ctx, metadata, authResult.Code, redirectURI)
}

func (h *OID4VCIHandler) exchangeAuthCode(ctx context.Context, metadata *IssuerMetadata, code, redirectURI string) (*TokenResponse, error) {
	h.ProgressMessage(StepExchangingToken, "Exchanging authorization code for token")

	tokenEndpoint := metadata.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = strings.TrimSuffix(metadata.CredentialIssuer, "/") + "/token"
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		h.Error(StepExchangingToken, ErrCodeTokenError, string(body))
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	h.ProgressMessage(StepTokenObtained, "Access token obtained")
	return &token, nil
}

func (h *OID4VCIHandler) needsProof(config *CredentialConfig) bool {
	return config.ProofTypesSupported != nil && len(config.ProofTypesSupported) > 0
}

func (h *OID4VCIHandler) requestProof(ctx context.Context, audience, nonce string) (string, error) {
	resp, err := h.RequestSign(ctx, SignActionGenerateProof, SignRequestParams{
		Audience:  audience,
		Nonce:     nonce,
		ProofType: "jwt",
	})
	if err != nil {
		return "", err
	}
	return resp.ProofJWT, nil
}

func (h *OID4VCIHandler) requestCredential(ctx context.Context, metadata *IssuerMetadata, token *TokenResponse, config *CredentialConfig, proofJWT string) (*CredentialResponse, error) {
	h.ProgressMessage(StepRequestingCredential, "Requesting credential from issuer")

	reqBody := map[string]interface{}{
		"format": config.Format,
	}
	if config.VCT != "" {
		reqBody["vct"] = config.VCT
	}
	if proofJWT != "" {
		reqBody["proof"] = map[string]interface{}{
			"proof_type": "jwt",
			"jwt":        proofJWT,
		}
	}

	bodyBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", metadata.CredentialEndpoint, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		h.Error(StepRequestingCredential, ErrCodeCredentialError, string(body))
		return nil, fmt.Errorf("credential endpoint returned status %d", resp.StatusCode)
	}

	var credResp CredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
		return nil, fmt.Errorf("failed to parse credential response: %w", err)
	}

	return &credResp, nil
}

func (h *OID4VCIHandler) buildCredentialResults(ctx context.Context, resp *CredentialResponse, config *CredentialConfig, trust *TrustInfo) []CredentialResult {
	var results []CredentialResult

	// Fetch VCTM for display metadata embedding
	var typeMetadata json.RawMessage
	if config.VCT != "" && h.Registry != nil {
		typeMetadata = h.Registry.FetchTypeMetadataJSON(ctx, config.VCT)
	}

	if resp.Credential != nil {
		credStr := ""
		switch v := resp.Credential.(type) {
		case string:
			credStr = v
		default:
			bytes, _ := json.Marshal(v)
			credStr = string(bytes)
		}
		results = append(results, CredentialResult{
			Format:       config.Format,
			Credential:   credStr,
			VCT:          config.VCT,
			TypeMetadata: typeMetadata,
		})
	}

	for _, cred := range resp.Credentials {
		credStr := ""
		switch v := cred.(type) {
		case string:
			credStr = v
		default:
			bytes, _ := json.Marshal(v)
			credStr = string(bytes)
		}
		results = append(results, CredentialResult{
			Format:       config.Format,
			Credential:   credStr,
			VCT:          config.VCT,
			TypeMetadata: typeMetadata,
		})
	}

	return results
}
