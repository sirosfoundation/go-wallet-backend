package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// OID4VCIHandler handles OpenID4VCI credential issuance flows
type OID4VCIHandler struct {
	BaseHandler
	httpClient *http.Client
	dpopKey    *ecdsa.PrivateKey // ephemeral DPoP key pair (RFC 9449)
}

// NewOID4VCIHandler creates a new OID4VCI flow handler
func NewOID4VCIHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore) (FlowHandler, error) {
	return &OID4VCIHandler{
		BaseHandler: BaseHandler{
			Flow:     flow,
			Config:   cfg,
			Logger:   logger,
			TrustSvc: trustSvc,
			Registry: registry,
		},
		httpClient: cfg.HTTPClient.NewHTTPClient(0),
	}, nil
}

// OID4VCI data structures

// oauthServerMetadata contains the OAuth Authorization Server metadata fields
// relevant for the OID4VCI authorization code flow.
type oauthServerMetadata struct {
	AuthorizationEndpoint              string   `json:"authorization_endpoint"`
	TokenEndpoint                      string   `json:"token_endpoint"`
	PushedAuthorizationRequestEndpoint string   `json:"pushed_authorization_request_endpoint"`
	CodeChallengeMethodsSupported      []string `json:"code_challenge_methods_supported"`
}

// supportsPKCE returns true if the AS metadata indicates S256 PKCE support,
// or if code_challenge_methods_supported is absent (assume support per OID4VCI spec).
func (m *oauthServerMetadata) supportsPKCE() bool {
	if len(m.CodeChallengeMethodsSupported) == 0 {
		// Not declared — assume S256 is supported (OID4VCI spec default)
		return true
	}
	for _, method := range m.CodeChallengeMethodsSupported {
		if method == "S256" {
			return true
		}
	}
	return false
}

// generateCodeVerifier creates a cryptographically random PKCE code_verifier (RFC 7636 §4.1).
func generateCodeVerifier() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// computeCodeChallenge computes the S256 PKCE code_challenge for a given verifier (RFC 7636 §4.2).
func computeCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

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
	// mDOC IACA certificates URL
	MdocIacasURI string `json:"mdoc_iacas_uri,omitempty"`
	// Signed metadata JWT (contains x5c or jwk for trust evaluation)
	SignedMetadata string `json:"signed_metadata,omitempty"`
	// Inline JWKS for issuer keys
	JWKS json.RawMessage `json:"jwks,omitempty"`
	// JWKS URI for issuer keys
	JWKsURI string `json:"jwks_uri,omitempty"`
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

// generateDPoPKey creates an ephemeral P-256 key pair for DPoP proofs (RFC 9449).
func generateDPoPKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ecPublicKeyJWK returns the JWK representation of an ECDSA P-256 public key as a map.
func ecPublicKeyJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	// ECDH conversion gives us the raw uncompressed point bytes
	ecdhKey, err := pub.ECDH()
	if err != nil {
		// Should never fail for a valid P-256 key generated by us
		panic("ecPublicKeyJWK: failed to convert to ECDH key: " + err.Error())
	}
	// ECDH PublicKey.Bytes() returns the uncompressed point: 0x04 || x (32 bytes) || y (32 bytes)
	raw := ecdhKey.Bytes()
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}
}

// createDPoPProof creates a DPoP proof JWT per RFC 9449 §4.2.
// accessToken should be empty for token endpoint requests, non-empty for resource requests.
func createDPoPProof(key *ecdsa.PrivateKey, htm, htu, accessToken string) (string, error) {
	claims := jwt.MapClaims{
		"jti": uuid.New().String(),
		"htm": htm,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		// ath: base64url(SHA-256(access_token)) per RFC 9449 §4.2
		h := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(h[:])
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = ecPublicKeyJWK(&key.PublicKey)

	return tok.SignedString(key)
}

// setDPoPHeader adds a DPoP proof header to the request if h.dpopKey is set.
// For token requests, accessToken should be empty; for resource requests it should contain the access token.
func (h *OID4VCIHandler) setDPoPHeader(req *http.Request, htu, accessToken string) error {
	if h.dpopKey == nil {
		return nil
	}
	proof, err := createDPoPProof(h.dpopKey, req.Method, htu, accessToken)
	if err != nil {
		return fmt.Errorf("failed to create DPoP proof: %w", err)
	}
	req.Header.Set("DPoP", proof)
	return nil
}

// setAuthorizationHeader sets the Authorization header using DPoP scheme when the token
// was DPoP-bound, otherwise uses Bearer.
func (h *OID4VCIHandler) setAuthorizationHeader(req *http.Request, token *TokenResponse) {
	if strings.EqualFold(token.TokenType, "DPoP") {
		req.Header.Set("Authorization", "DPoP "+token.AccessToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	}
}

// Execute runs the OID4VCI flow
func (h *OID4VCIHandler) Execute(ctx context.Context, msg *FlowStartMessage) error {
	ctx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	defer cancel()

	// Add tenant context for X-Tenant-ID propagation
	if h.Flow.Session != nil && h.Flow.Session.TenantID != "" {
		ctx = ContextWithTenant(ctx, h.Flow.Session.TenantID)
	}

	// Step 1: Parse credential offer
	offer, err := h.parseOffer(ctx, msg)
	if err != nil {
		h.Logger.Debug("failed to parse offer", zap.Error(err))
		_ = h.Error(StepParsingOffer, ErrCodeOfferParseError, ErrCodeOfferParseError.UserFacingMessage())
		return err
	}
	h.SetData("offer", offer)

	// Step 2: Fetch issuer metadata
	metadata, err := h.fetchMetadata(ctx, offer.CredentialIssuer)
	if err != nil {
		h.Logger.Debug("failed to fetch metadata", zap.Error(err))
		_ = h.Error(StepFetchingMetadata, ErrCodeMetadataFetchErr, ErrCodeMetadataFetchErr.UserFacingMessage())
		return err
	}
	h.SetData("metadata", metadata)

	// Step 3: Evaluate trust
	trust, err := h.evaluateTrust(ctx, offer.CredentialIssuer, metadata)
	if err != nil {
		h.Logger.Debug("issuer trust evaluation failed", zap.Error(err))
		_ = h.Error(StepEvaluatingTrust, ErrCodeUntrustedIssuer, ErrCodeUntrustedIssuer.UserFacingMessage())
		return err
	}

	// Step 4: User selects credential configuration
	selectedConfig, err := h.awaitCredentialSelection(ctx, offer, metadata)
	if err != nil {
		return err
	}
	h.SetData("selected_config", selectedConfig)

	// Generate ephemeral DPoP key pair (RFC 9449)
	h.dpopKey, err = generateDPoPKey()
	if err != nil {
		h.Logger.Debug("failed to generate DPoP key", zap.Error(err))
		return err
	}

	// Step 5: Handle authorization
	token, err := h.handleAuthorization(ctx, offer, metadata, selectedConfig)
	if err != nil {
		return err
	}

	// Step 6: Generate proof (if required)
	var proofJWT string
	if h.needsProof(selectedConfig) {
		proof, err := h.requestProof(ctx, metadata.CredentialIssuer, token.CNonce)
		if err != nil {
			h.Logger.Debug("failed to request proof", zap.Error(err))
			_ = h.Error(StepRequestingCredential, ErrCodeSignError, ErrCodeSignError.UserFacingMessage())
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
		// Deferred issuance - poll for credential
		_ = h.Progress(StepDeferred, map[string]interface{}{
			"transaction_id": credential.TransactionID,
			"interval":       5,
			"message":        "Credential issuance is pending",
		})

		// Poll for deferred credential
		deferredResp, err := h.pollDeferredCredential(ctx, metadata, token, credential.TransactionID)
		if err != nil {
			h.Logger.Debug("deferred polling failed", zap.Error(err))
			_ = h.Error(StepDeferred, ErrCodeCredentialError, ErrCodeCredentialError.UserFacingMessage())
			return err
		}

		// Complete with the issued credential
		results := h.buildCredentialResults(ctx, deferredResp, selectedConfig, trust)
		return h.Complete(results, "")
	}

	// Step 9: Complete with issued credential (fetch VCTM for display)
	results := h.buildCredentialResults(ctx, credential, selectedConfig, trust)
	return h.Complete(results, "")
}

func (h *OID4VCIHandler) parseOffer(ctx context.Context, msg *FlowStartMessage) (*CredentialOffer, error) {
	_ = h.ProgressMessage(StepParsingOffer, "Parsing credential offer")

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

	_ = h.Progress(StepOfferParsed, map[string]interface{}{
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
	defer resp.Body.Close() //nolint:errcheck

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
	_ = h.ProgressMessage(StepFetchingMetadata, "Fetching issuer metadata")

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
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		return nil, fmt.Errorf("metadata fetch returned status %d: %s", resp.StatusCode, string(body))
	}

	var metadata IssuerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata: %w", err)
	}

	_ = h.Progress(StepMetadataFetched, map[string]interface{}{
		"credential_issuer":   metadata.CredentialIssuer,
		"credential_endpoint": metadata.CredentialEndpoint,
		"display":             metadata.Display,
	})

	return &metadata, nil
}

func (h *OID4VCIHandler) evaluateTrust(ctx context.Context, issuer string, metadata *IssuerMetadata) (*TrustInfo, error) {
	_ = h.ProgressMessage(StepEvaluatingTrust, "Evaluating issuer trust")

	// Extract key material from issuer metadata for trust evaluation
	keyMaterial := h.extractIssuerKeyMaterial(ctx, metadata)

	// Collect credential types from the offered configurations for trust policy
	if keyMaterial != nil && keyMaterial.CredentialType == "" {
		keyMaterial.CredentialType = h.collectCredentialTypes(metadata)
	}

	// Check if issuer is a DID - requires resolution via /v1/resolve
	requiresResolution := strings.HasPrefix(issuer, "did:")

	// Build trust evaluation request for frontend
	trustReq := &TrustEvaluationRequest{
		SubjectID:          issuer,
		SubjectType:        SubjectTypeCredentialIssuer,
		RequiresResolution: requiresResolution,
		Context: map[string]interface{}{
			"credential_types": h.collectCredentialTypes(metadata),
		},
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
	// Skip validation for issuers - RequiresResolution doesn't require RequestJWT
	if trustReq.SubjectID == "" {
		return nil, errors.New("invalid trust evaluation request: SubjectID is required")
	}
	_ = h.Progress(StepEvaluatingTrust, map[string]interface{}{
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
		zap.String("issuer", issuer),
		zap.Bool("trusted", trustResult.Trusted),
		zap.String("framework", trustResult.Framework),
		zap.String("reason", trustResult.Reason))

	info := &TrustInfo{
		Trusted:   trustResult.Trusted,
		Framework: trustResult.Framework,
		Reason:    trustResult.Reason,
	}

	_ = h.Progress(StepTrustEvaluated, info)

	// Enforce trust decision: always block untrusted issuers
	// (frontend has already evaluated trust via AuthZEN)
	if !info.Trusted {
		reason := info.Reason
		if reason == "" {
			reason = "issuer not trusted"
		}
		h.Logger.Warn("Blocking untrusted issuer",
			zap.String("issuer", issuer),
			zap.String("reason", reason))
		return info, fmt.Errorf("untrusted issuer %s: %s", issuer, reason)
	}

	return info, nil
}

// collectCredentialTypes returns a comma-separated list of VCT/doctype values
// from the issuer metadata's credential configurations.
func (h *OID4VCIHandler) collectCredentialTypes(metadata *IssuerMetadata) string {
	var types []string
	for _, cfg := range metadata.CredentialConfigurationsSupported {
		if cfg.VCT != "" {
			types = append(types, cfg.VCT)
		}
	}
	if len(types) == 1 {
		return types[0]
	}
	return strings.Join(types, ",")
}

// extractIssuerKeyMaterial extracts key material from issuer metadata for trust evaluation.
// Priority: mdoc_iacas_uri > signed_metadata (x5c or jwk) > inline jwks > jwks_uri
// For DIDs (issuerID starts with did:), returns nil to use resolution-only mode.
func (h *OID4VCIHandler) extractIssuerKeyMaterial(ctx context.Context, metadata *IssuerMetadata) *KeyMaterial {
	// Fetch IACA certificates for mDOC
	if metadata.MdocIacasURI != "" {
		certs, err := h.fetchIACACertificates(ctx, metadata.MdocIacasURI)
		if err != nil {
			h.Logger.Warn("Failed to fetch IACA certificates",
				zap.String("uri", metadata.MdocIacasURI),
				zap.Error(err))
		} else if len(certs) > 0 {
			return &KeyMaterial{
				Type: "x5c",
				X5C:  certs,
			}
		}
	}

	// Verify and extract key material from signed_metadata JWT.
	// Uses signature verification to prevent header injection attacks.
	// Security: No fallback to unverified extraction - if verification fails, we reject.
	if metadata.SignedMetadata != "" {
		km, err := trust.VerifyJWTWithEmbeddedKey(metadata.SignedMetadata)
		if err != nil {
			h.Logger.Error("signed_metadata JWT verification failed - rejecting unsigned key material",
				zap.Error(err))
			// Do NOT fall back to unverified extraction - this would allow header injection attacks
			return nil
		}
		return km
	}

	// Inline JWKS in metadata
	if len(metadata.JWKS) > 0 {
		var jwks interface{}
		if err := json.Unmarshal(metadata.JWKS, &jwks); err == nil {
			return &KeyMaterial{
				Type: "jwk",
				JWK:  jwks,
			}
		}
		h.Logger.Warn("Failed to parse inline JWKS from issuer metadata")
	}

	// Fetch JWKS from jwks_uri
	if metadata.JWKsURI != "" {
		jwks, err := trust.FetchJWKS(ctx, metadata.JWKsURI, h.httpClient)
		if err != nil {
			h.Logger.Warn("Failed to fetch JWKS",
				zap.String("uri", metadata.JWKsURI),
				zap.Error(err))
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

// fetchIACACertificates fetches IACA certificates from mdoc_iacas_uri
func (h *OID4VCIHandler) fetchIACACertificates(ctx context.Context, iacasURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", iacasURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IACA fetch returned status %d", resp.StatusCode)
	}

	var iacasResp struct {
		Iacas []struct {
			Certificate string `json:"certificate"`
		} `json:"iacas"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&iacasResp); err != nil {
		return nil, err
	}

	certs := make([]string, 0, len(iacasResp.Iacas))
	for _, iaca := range iacasResp.Iacas {
		if iaca.Certificate != "" {
			certs = append(certs, iaca.Certificate)
		}
	}

	return certs, nil
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
	_ = h.Progress(StepAwaitingSelection, map[string]interface{}{
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
		_ = h.Error(StepAwaitingSelection, ErrCodeInvalidMessage, "Invalid selection payload")
		return nil, err
	}

	config, ok := metadata.CredentialConfigurationsSupported[selection.CredentialConfigurationID]
	if !ok {
		_ = h.Error(StepAwaitingSelection, ErrCodeInvalidMessage, "Invalid credential configuration")
		return nil, errors.New("invalid credential configuration")
	}

	return &config, nil
}

func (h *OID4VCIHandler) handleAuthorization(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata, selectedConfig *CredentialConfig) (*TokenResponse, error) {
	// Check for pre-authorized code grant
	if grants, ok := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]; ok {
		grantMap, ok := grants.(map[string]interface{})
		if ok {
			return h.handlePreAuthorized(ctx, metadata, grantMap)
		}
	}

	// Check for authorization_code grant
	if _, ok := offer.Grants["authorization_code"]; ok {
		return h.handleAuthorizationCode(ctx, offer, metadata, selectedConfig)
	}

	return nil, errors.New("no supported grant type in offer")
}

func (h *OID4VCIHandler) handlePreAuthorized(ctx context.Context, metadata *IssuerMetadata, grant map[string]interface{}) (*TokenResponse, error) {
	preAuthCode, _ := grant["pre-authorized_code"].(string)

	// Check if TX code required
	if txCodeRequired, ok := grant["tx_code"]; ok && txCodeRequired != nil {
		// Request TX code from user
		_ = h.Progress(StepAuthorizationReq, map[string]interface{}{
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
	_ = h.ProgressMessage(StepExchangingToken, "Exchanging pre-authorized code for token")

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
	if err := h.setDPoPHeader(req, tokenEndpoint, ""); err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		h.Logger.Debug("token endpoint error", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		_ = h.Error(StepExchangingToken, ErrCodeTokenError, ErrCodeTokenError.UserFacingMessage())
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	_ = h.ProgressMessage(StepTokenObtained, "Access token obtained")
	return &token, nil
}

func (h *OID4VCIHandler) handleAuthorizationCode(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata, selectedConfig *CredentialConfig) (*TokenResponse, error) {
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

	fallbackEndpoint := strings.TrimSuffix(authServer, "/") + "/authorize"

	resp, err := h.httpClient.Do(req)
	if err != nil {
		// Fallback: construct auth URL directly, no PAR
		return h.startAuthorizationFlow(ctx, offer, metadata, selectedConfig, &oauthServerMetadata{
			AuthorizationEndpoint: fallbackEndpoint,
		})
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusOK {
		var oauthMeta oauthServerMetadata
		if err := json.NewDecoder(resp.Body).Decode(&oauthMeta); err == nil && oauthMeta.AuthorizationEndpoint != "" {
			return h.startAuthorizationFlow(ctx, offer, metadata, selectedConfig, &oauthMeta)
		}
	}

	return h.startAuthorizationFlow(ctx, offer, metadata, selectedConfig, &oauthServerMetadata{
		AuthorizationEndpoint: fallbackEndpoint,
	})
}

func (h *OID4VCIHandler) startAuthorizationFlow(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata, selectedConfig *CredentialConfig, oauthMeta *oauthServerMetadata) (*TokenResponse, error) {
	redirectURI := h.Config.Server.BaseURL + "/callback"

	// Generate PKCE code verifier and challenge (RFC 7636)
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, err
	}
	codeChallenge := computeCodeChallenge(codeVerifier)

	// Parse and validate the authorization endpoint URL once
	authEndpoint, err := url.Parse(oauthMeta.AuthorizationEndpoint)
	if err != nil || authEndpoint.Scheme == "" {
		return nil, fmt.Errorf("invalid authorization endpoint URL: %q", oauthMeta.AuthorizationEndpoint)
	}

	pkceEnabled := oauthMeta.supportsPKCE()

	// Build common authorization parameters
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", redirectURI) // OID4VCI: use redirect_uri as client_id for unregistered clients
	params.Set("redirect_uri", redirectURI)
	scope := "openid"
	if selectedConfig != nil && selectedConfig.Scope != "" {
		scope = selectedConfig.Scope
	}
	params.Set("scope", scope)
	if pkceEnabled {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}
	if grant, ok := offer.Grants["authorization_code"].(map[string]interface{}); ok {
		if issuerState, ok := grant["issuer_state"].(string); ok {
			params.Set("issuer_state", issuerState)
		}
	}

	var authURL string

	if oauthMeta.PushedAuthorizationRequestEndpoint != "" {
		// Use Pushed Authorization Request (RFC 9126)
		requestURI, parErr := h.sendPushedAuthorizationRequest(ctx, oauthMeta.PushedAuthorizationRequestEndpoint, params)
		if parErr != nil {
			h.Logger.Debug("PAR request failed", zap.Error(parErr))
			_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "Pushed authorization request failed")
			return nil, parErr
		}

		// Build authorization URL with only client_id and request_uri
		q := authEndpoint.Query()
		q.Set("client_id", redirectURI)
		q.Set("request_uri", requestURI)
		authEndpoint.RawQuery = q.Encode()
		authURL = authEndpoint.String()
	} else {
		// Standard authorization URL with all parameters
		authEndpoint.RawQuery = params.Encode()
		authURL = authEndpoint.String()
	}

	// Use token endpoint from OAuth metadata if the issuer metadata doesn't have one
	if metadata.TokenEndpoint == "" && oauthMeta.TokenEndpoint != "" {
		metadata.TokenEndpoint = oauthMeta.TokenEndpoint
	}

	_ = h.Progress(StepAuthorizationReq, map[string]interface{}{
		"authorization_url":     authURL,
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
		_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "Invalid authorization response")
		return nil, err
	}

	// Exchange code for token, including PKCE code_verifier when enabled
	verifier := ""
	if pkceEnabled {
		verifier = codeVerifier
	}
	return h.exchangeAuthCode(ctx, metadata, authResult.Code, redirectURI, verifier)
}

// PARResponse represents the response from a Pushed Authorization Request endpoint (RFC 9126).
type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in,omitempty"`
	Error      string `json:"error,omitempty"`
	ErrorDesc  string `json:"error_description,omitempty"`
}

// sendPushedAuthorizationRequest sends authorization parameters to the PAR endpoint
// and returns the request_uri to use in the authorization redirect (RFC 9126).
func (h *OID4VCIHandler) sendPushedAuthorizationRequest(ctx context.Context, parEndpoint string, params url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", parEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create PAR request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("PAR request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		h.Logger.Debug("PAR endpoint error", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		return "", fmt.Errorf("PAR endpoint returned status %d", resp.StatusCode)
	}

	var parResp PARResponse
	if err := json.NewDecoder(resp.Body).Decode(&parResp); err != nil {
		return "", fmt.Errorf("failed to parse PAR response: %w", err)
	}

	if parResp.Error != "" {
		return "", fmt.Errorf("PAR error: %s %s", parResp.Error, parResp.ErrorDesc)
	}

	if parResp.RequestURI == "" {
		return "", errors.New("PAR response missing request_uri")
	}

	return parResp.RequestURI, nil
}

func (h *OID4VCIHandler) exchangeAuthCode(ctx context.Context, metadata *IssuerMetadata, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	_ = h.ProgressMessage(StepExchangingToken, "Exchanging authorization code for token")

	tokenEndpoint := metadata.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = strings.TrimSuffix(metadata.CredentialIssuer, "/") + "/token"
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := h.setDPoPHeader(req, tokenEndpoint, ""); err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		h.Logger.Debug("token endpoint error (auth code)", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		_ = h.Error(StepExchangingToken, ErrCodeTokenError, ErrCodeTokenError.UserFacingMessage())
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	_ = h.ProgressMessage(StepTokenObtained, "Access token obtained")
	return &token, nil
}

func (h *OID4VCIHandler) needsProof(config *CredentialConfig) bool {
	return len(config.ProofTypesSupported) > 0
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
	_ = h.ProgressMessage(StepRequestingCredential, "Requesting credential from issuer")

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
	h.setAuthorizationHeader(req, token)
	if err := h.setDPoPHeader(req, metadata.CredentialEndpoint, token.AccessToken); err != nil {
		return nil, err
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
		h.Logger.Debug("credential endpoint error", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
		_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, ErrCodeCredentialError.UserFacingMessage())
		return nil, fmt.Errorf("credential endpoint returned status %d", resp.StatusCode)
	}

	var credResp CredentialResponse
	if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
		return nil, fmt.Errorf("failed to parse credential response: %w", err)
	}

	return &credResp, nil
}

// pollDeferredCredential polls the deferred credential endpoint until the credential is ready
// or the polling times out.
func (h *OID4VCIHandler) pollDeferredCredential(ctx context.Context, metadata *IssuerMetadata, token *TokenResponse, transactionID string) (*CredentialResponse, error) {
	// Determine deferred endpoint (OpenID4VCI spec: {credential_issuer}/deferred_credential or from metadata)
	deferredEndpoint := strings.TrimSuffix(metadata.CredentialIssuer, "/") + "/deferred_credential"

	// Default polling interval and max attempts
	interval := 5 * time.Second
	maxAttempts := 60 // 5 minutes at 5 second intervals

	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		// Send progress update
		_ = h.Progress(StepDeferred, map[string]interface{}{
			"transaction_id": transactionID,
			"attempt":        attempt + 1,
			"max_attempts":   maxAttempts,
			"message":        fmt.Sprintf("Polling for credential (attempt %d/%d)", attempt+1, maxAttempts),
		})

		// Build request body
		reqBody := map[string]interface{}{
			"transaction_id": transactionID,
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req, err := http.NewRequestWithContext(ctx, "POST", deferredEndpoint, strings.NewReader(string(bodyBytes)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		h.setAuthorizationHeader(req, token)
		if err := h.setDPoPHeader(req, deferredEndpoint, token.AccessToken); err != nil {
			return nil, err
		}

		resp, err := h.httpClient.Do(req)
		if err != nil {
			h.Logger.Warn("Deferred polling request failed", zap.Error(err), zap.Int("attempt", attempt+1))
			continue // Retry on network errors
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPResponseBodyBytes))
		_ = resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			// Credential is ready
			var credResp CredentialResponse
			if err := json.Unmarshal(body, &credResp); err != nil {
				return nil, fmt.Errorf("failed to parse deferred credential response: %w", err)
			}
			h.Logger.Info("Deferred credential received", zap.String("transaction_id", transactionID))
			return &credResp, nil

		case http.StatusAccepted:
			// Still pending, continue polling
			// Check for new interval if provided in response
			var pendingResp struct {
				Interval int `json:"interval,omitempty"`
			}
			if err := json.Unmarshal(body, &pendingResp); err == nil && pendingResp.Interval > 0 {
				interval = time.Duration(pendingResp.Interval) * time.Second
			}
			h.Logger.Debug("Deferred credential still pending",
				zap.String("transaction_id", transactionID),
				zap.Int("attempt", attempt+1))
			continue

		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
			// Non-retryable errors
			return nil, fmt.Errorf("deferred credential request failed with status %d: %s", resp.StatusCode, string(body))

		default:
			h.Logger.Warn("Unexpected deferred response status",
				zap.Int("status", resp.StatusCode),
				zap.String("body", string(body)))
			continue // Retry on unexpected responses
		}
	}

	return nil, fmt.Errorf("deferred credential polling timeout after %d attempts", maxAttempts)
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
