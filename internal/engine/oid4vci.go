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
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
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
	httpClient  *http.Client
	dpopKey     *ecdsa.PrivateKey // ephemeral DPoP key pair (RFC 9449)
	dpopNonce   string            // server-provided DPoP nonce (RFC 9449 §8)
	redirectURI string
}

// NewOID4VCIHandler creates a new OID4VCI flow handler
func NewOID4VCIHandler(flow *Flow, cfg *config.Config, logger *zap.Logger, trustSvc *TrustService, registry *RegistryClient, verifiers storage.VerifierStore, trustCache *TrustCache) (FlowHandler, error) {
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
	codeChallengeMethodsDeclared       bool
}

// UnmarshalJSON preserves whether code_challenge_methods_supported was present
// so supportsPKCE can distinguish an absent field from an explicit empty list.
func (m *oauthServerMetadata) UnmarshalJSON(data []byte) error {
	type alias struct {
		AuthorizationEndpoint              string    `json:"authorization_endpoint"`
		TokenEndpoint                      string    `json:"token_endpoint"`
		PushedAuthorizationRequestEndpoint string    `json:"pushed_authorization_request_endpoint"`
		CodeChallengeMethodsSupported      *[]string `json:"code_challenge_methods_supported"`
	}
	var aux alias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	m.AuthorizationEndpoint = aux.AuthorizationEndpoint
	m.TokenEndpoint = aux.TokenEndpoint
	m.PushedAuthorizationRequestEndpoint = aux.PushedAuthorizationRequestEndpoint
	m.codeChallengeMethodsDeclared = aux.CodeChallengeMethodsSupported != nil
	if aux.CodeChallengeMethodsSupported != nil {
		m.CodeChallengeMethodsSupported = *aux.CodeChallengeMethodsSupported
	}
	return nil
}

// supportsPKCE returns true if the AS metadata indicates S256 PKCE support,
// or if code_challenge_methods_supported is absent (assume support per OID4VCI spec).
// An explicitly empty list is treated as "no PKCE support declared".
func (m *oauthServerMetadata) supportsPKCE() bool {
	if !m.codeChallengeMethodsDeclared {
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
	// Credential response encryption configuration
	CredentialResponseEncryption *CredentialResponseEncryptionConfig `json:"credential_response_encryption,omitempty"`
	// Batch credential issuance configuration (OID4VCI §E.1)
	BatchCredentialIssuance *BatchCredentialIssuance `json:"batch_credential_issuance,omitempty"`
	// mDOC IACA certificates URL
	MdocIacasURI string `json:"mdoc_iacas_uri,omitempty"`
	// Signed metadata JWT (contains x5c or jwk for trust evaluation)
	SignedMetadata string `json:"signed_metadata,omitempty"`
	// Inline JWKS for issuer keys
	JWKS json.RawMessage `json:"jwks,omitempty"`
	// JWKS URI for issuer keys
	JWKsURI string `json:"jwks_uri,omitempty"`
}

// BatchCredentialIssuance contains batch credential issuance configuration from issuer metadata.
type BatchCredentialIssuance struct {
	BatchSize int `json:"batch_size"`
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

// CredentialResponseEncryptionConfig represents the issuer's credential_response_encryption metadata.
type CredentialResponseEncryptionConfig struct {
	AlgValuesSupported []string `json:"alg_values_supported"`
	EncValuesSupported []string `json:"enc_values_supported"`
	EncryptionRequired bool     `json:"encryption_required"`
}

// supportsAlg returns true if the encryption config supports the given algorithm.
func (c *CredentialResponseEncryptionConfig) supportsAlg(alg string) bool {
	for _, a := range c.AlgValuesSupported {
		if a == alg {
			return true
		}
	}
	return false
}

// supportsEnc returns true if the encryption config supports the given content encryption.
func (c *CredentialResponseEncryptionConfig) supportsEnc(enc string) bool {
	for _, e := range c.EncValuesSupported {
		if e == enc {
			return true
		}
	}
	return false
}

// decryptJWEResponse decrypts a JWE compact-serialized credential response using
// the ephemeral ECDH-ES private key.
func decryptJWEResponse(jweString string, privKey *ecdsa.PrivateKey) (*CredentialResponse, error) {
	jwe, err := jose.ParseEncrypted(jweString,
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		[]jose.ContentEncryption{jose.A128CBC_HS256, jose.A256CBC_HS512, jose.A128GCM, jose.A256GCM},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWE: %w", err)
	}

	plaintext, err := jwe.Decrypt(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential response: %w", err)
	}

	var credResp CredentialResponse
	if err := json.Unmarshal(plaintext, &credResp); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted credential response: %w", err)
	}
	return &credResp, nil
}

// generateDPoPKey creates an ephemeral P-256 key pair for DPoP proofs (RFC 9449).
func generateDPoPKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// ecPublicKeyJWK returns the JWK representation of an ECDSA P-256 public key as a map.
func ecPublicKeyJWK(pub *ecdsa.PublicKey) (map[string]interface{}, error) {
	// ECDH conversion gives us the raw uncompressed point bytes
	ecdhKey, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ecPublicKeyJWK: failed to convert to ECDH key: %w", err)
	}
	// ECDH PublicKey.Bytes() returns the uncompressed point: 0x04 || x (32 bytes) || y (32 bytes)
	raw := ecdhKey.Bytes()
	if len(raw) != 65 {
		return nil, fmt.Errorf("ecPublicKeyJWK: unexpected raw key length %d (expected 65)", len(raw))
	}
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}, nil
}

// createDPoPProof creates a DPoP proof JWT per RFC 9449 §4.2.
// accessToken should be empty for token endpoint requests, non-empty for resource requests.
// nonce is the server-provided DPoP nonce (may be empty).
func createDPoPProof(key *ecdsa.PrivateKey, htm, htu, accessToken, nonce string) (string, error) {
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
	if nonce != "" {
		claims["nonce"] = nonce
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt"
	jwk, err := ecPublicKeyJWK(&key.PublicKey)
	if err != nil {
		return "", err
	}
	tok.Header["jwk"] = jwk

	return tok.SignedString(key)
}

// setDPoPHeader adds a DPoP proof header to the request if h.dpopKey is set.
// For token requests, accessToken should be empty; for resource requests it should contain the access token.
func (h *OID4VCIHandler) setDPoPHeader(req *http.Request, htu, accessToken string) error {
	if h.dpopKey == nil {
		return nil
	}
	proof, err := createDPoPProof(h.dpopKey, req.Method, htu, accessToken, h.dpopNonce)
	if err != nil {
		return fmt.Errorf("failed to create DPoP proof: %w", err)
	}
	req.Header.Set("DPoP", proof)
	return nil
}

// updateDPoPNonce stores a server-provided DPoP nonce for subsequent requests (RFC 9449 §8).
func (h *OID4VCIHandler) updateDPoPNonce(resp *http.Response) {
	if nonce := resp.Header.Get("DPoP-Nonce"); nonce != "" {
		h.dpopNonce = nonce
	}
}

// isDPoPNonceError returns true if the response indicates a DPoP nonce is required.
func isDPoPNonceError(resp *http.Response) bool {
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	return resp.Header.Get("DPoP-Nonce") != ""
}

// OAuthError represents a structured OAuth 2.0 error response (RFC 6749 §5.2).
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// parseOAuthError attempts to parse a structured OAuth error from a response body.
// Returns the parsed error or a generic error with the status code.
func parseOAuthError(statusCode int, body []byte) error {
	var oauthErr OAuthError
	if err := json.Unmarshal(body, &oauthErr); err == nil && oauthErr.Error != "" {
		if oauthErr.ErrorDescription != "" {
			return fmt.Errorf("%s: %s", oauthErr.Error, oauthErr.ErrorDescription)
		}
		return fmt.Errorf("%s", oauthErr.Error)
	}
	return fmt.Errorf("endpoint returned status %d", statusCode)
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

	if msg.RedirectURI != "" {
		h.redirectURI = msg.RedirectURI
	}

	// Step 1: Parse credential offer
	offer, err := h.parseOffer(ctx, msg)
	if err != nil {
		h.Logger.Debug("failed to parse offer", zap.Error(err))
		_ = h.Error(StepParsingOffer, ErrCodeOfferParseError, ErrCodeOfferParseError.UserFacingMessage())
		return err
	}
	h.SetData("offer", offer)
	h.SetData("credential_issuer", offer.CredentialIssuer)

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
	selectedConfigID, selectedConfig, err := h.awaitCredentialSelection(ctx, offer, metadata)
	if err != nil {
		return err
	}
	h.SetData("selected_config", selectedConfig)
	h.SetData("selected_credential_configuration_id", selectedConfigID)

	// Generate ephemeral DPoP key pair (RFC 9449)
	h.dpopKey, err = generateDPoPKey()
	if err != nil {
		h.Logger.Debug("failed to generate DPoP key", zap.Error(err))
		_ = h.Error(StepRequestingCredential, ErrCodeSignError, ErrCodeSignError.UserFacingMessage())
		return err
	}

	// Step 5: Handle authorization (or resume with provided auth code)
	var token *TokenResponse
	if msg.AuthCode != "" {
		// Resumption: client already completed OAuth and returned with auth code.
		// Verify the offer actually supports the authorization_code grant.
		if _, ok := offer.Grants["authorization_code"]; !ok {
			_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "credential offer does not support authorization_code grant")
			return errors.New("cannot resume with auth code: credential offer does not support authorization_code grant")
		}
		token, err = h.resumeWithAuthCode(ctx, msg, metadata)
	} else {
		// Normal flow: handle authorization (pre-auth or auth code grant)
		token, err = h.handleAuthorization(ctx, offer, metadata, selectedConfig)
	}
	if err != nil {
		return err
	}

	// Step 6 + 7: Request proofs and credential, with full retry on c_nonce refresh.
	// OID4VCI spec: when the issuer returns a fresh c_nonce in an error response,
	// the engine re-requests ALL proofs from the frontend with the new nonce and
	// retries the credential request once.
	nonce := token.CNonce
	var credential *CredentialResponse
	for retries := 0; retries <= 1; retries++ {
		var proofs []ProofObject
		if h.needsProof(selectedConfig) {
			var proofErr error
			proofs, proofErr = h.requestProofs(ctx, metadata, selectedConfig, nonce)
			if proofErr != nil {
				h.Logger.Debug("failed to request proofs", zap.Error(proofErr))
				_ = h.Error(StepRequestingCredential, ErrCodeSignError, ErrCodeSignError.UserFacingMessage())
				return proofErr
			}
		}

		var credErr error
		credential, credErr = h.requestCredential(ctx, metadata, token, selectedConfigID, selectedConfig, proofs)
		if credErr != nil {
			var cNonceErr *CNonceRequiredError
			if retries == 0 && errors.As(credErr, &cNonceErr) {
				// Issuer returned a refreshed c_nonce — re-request all proofs and retry
				h.Logger.Debug("c_nonce refreshed by issuer, re-requesting proofs")
				nonce = cNonceErr.NewNonce
				continue
			}
			// On the second attempt or for non-c_nonce errors, surface the error.
			// For CNonceRequiredError on the final retry, send the flow error here
			// and unwrap the underlying credential error so the caller receives a
			// meaningful issuer error message (e.g. "invalid_nonce: ...").
			if errors.As(credErr, &cNonceErr) {
				_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, ErrCodeCredentialError.UserFacingMessage())
				return cNonceErr.Err
			}
			return credErr
		}
		break
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

func (h *OID4VCIHandler) awaitCredentialSelection(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata) (string, *CredentialConfig, error) {
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
		return configID, &config, nil
	}

	// Send selection request
	_ = h.Progress(StepAwaitingSelection, map[string]interface{}{
		"available_credentials": available,
	})

	// Wait for user selection
	action, err := h.WaitForAction(ctx, ActionSelectCredential)
	if err != nil {
		return "", nil, err
	}

	// Parse selection
	var selection struct {
		CredentialConfigurationID string `json:"credential_configuration_id"`
	}
	if err := json.Unmarshal(action.Payload, &selection); err != nil {
		_ = h.Error(StepAwaitingSelection, ErrCodeInvalidMessage, "Invalid selection payload")
		return "", nil, err
	}

	config, ok := metadata.CredentialConfigurationsSupported[selection.CredentialConfigurationID]
	if !ok {
		_ = h.Error(StepAwaitingSelection, ErrCodeInvalidMessage, "Invalid credential configuration")
		return "", nil, errors.New("invalid credential configuration")
	}

	return selection.CredentialConfigurationID, &config, nil
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

	// Fetch OAuth metadata to get token endpoint if not in issuer metadata
	if metadata.TokenEndpoint == "" {
		if oauthMeta := h.fetchOAuthMetadata(ctx, metadata); oauthMeta != nil && oauthMeta.TokenEndpoint != "" {
			metadata.TokenEndpoint = oauthMeta.TokenEndpoint
		}
	}

	// Check if TX code required
	if txCodeRequired, ok := grant["tx_code"]; ok && txCodeRequired != nil {
		// Use issuer-provided description from tx_code spec (OID4VCI §4.1.1)
		progressPayload := map[string]interface{}{
			"type":                "tx_code",
			"pre_authorized_code": preAuthCode,
			"tx_code":             txCodeRequired,
			"credential_issuer":   metadata.CredentialIssuer,
		}
		if txMap, ok := txCodeRequired.(map[string]interface{}); ok {
			if desc, ok := txMap["description"].(string); ok && desc != "" {
				progressPayload["message"] = desc
			}
		}
		_ = h.Progress(StepAuthorizationReq, progressPayload)

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

	// Token exchange with DPoP nonce retry (RFC 9449 §8)
	for attempt := 0; attempt < 2; attempt++ {
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

		// Check for DPoP nonce requirement — retry once with server-provided nonce
		if attempt == 0 && isDPoPNonceError(resp) {
			h.updateDPoPNonce(resp)
			_ = resp.Body.Close()
			continue
		}
		h.updateDPoPNonce(resp)

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
			_ = resp.Body.Close()
			h.Logger.Debug("token endpoint error", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
			_ = h.Error(StepExchangingToken, ErrCodeTokenError, ErrCodeTokenError.UserFacingMessage())
			return nil, parseOAuthError(resp.StatusCode, body)
		}

		var token TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("failed to parse token response: %w", err)
		}
		_ = resp.Body.Close()

		_ = h.ProgressMessage(StepTokenObtained, "Access token obtained")
		return &token, nil
	}

	return nil, errors.New("token request failed after DPoP nonce retry")
}

// fetchOAuthMetadata fetches OAuth Authorization Server metadata from the well-known endpoint.
// Returns nil (not an error) if the metadata cannot be fetched, allowing callers to use fallbacks.
func (h *OID4VCIHandler) fetchOAuthMetadata(ctx context.Context, metadata *IssuerMetadata) *oauthServerMetadata {
	authServer := metadata.AuthorizationServer
	if authServer == "" {
		authServer = metadata.CredentialIssuer
	}

	oauthMetadataURL := strings.TrimSuffix(authServer, "/") + "/.well-known/oauth-authorization-server"
	req, err := http.NewRequestWithContext(ctx, "GET", oauthMetadataURL, nil)
	if err != nil {
		return nil
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var oauthMeta oauthServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&oauthMeta); err != nil {
		return nil
	}
	return &oauthMeta
}

func (h *OID4VCIHandler) handleAuthorizationCode(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata, selectedConfig *CredentialConfig) (*TokenResponse, error) {
	authServer := metadata.AuthorizationServer
	if authServer == "" {
		authServer = metadata.CredentialIssuer
	}
	fallbackEndpoint := strings.TrimSuffix(authServer, "/") + "/authorize"

	oauthMeta := h.fetchOAuthMetadata(ctx, metadata)
	if oauthMeta == nil || oauthMeta.AuthorizationEndpoint == "" {
		// Fallback: construct auth URL directly, no PAR
		return h.startAuthorizationFlow(ctx, offer, metadata, selectedConfig, &oauthServerMetadata{
			AuthorizationEndpoint: fallbackEndpoint,
		})
	}
	return h.startAuthorizationFlow(ctx, offer, metadata, selectedConfig, oauthMeta)
}

func (h *OID4VCIHandler) startAuthorizationFlow(ctx context.Context, offer *CredentialOffer, metadata *IssuerMetadata, selectedConfig *CredentialConfig, oauthMeta *oauthServerMetadata) (*TokenResponse, error) {
	if h.redirectURI == "" {
		_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "redirect_uri is required for authorization code flow")
		return nil, errors.New("redirect_uri is required for authorization code flow")
	}
	redirectURI := h.redirectURI

	// Generate PKCE code verifier and challenge (RFC 7636)
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, err
	}
	codeChallenge := computeCodeChallenge(codeVerifier)

	// Generate OAuth state parameter for CSRF protection (RFC 6749 §10.12)
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("failed to generate state parameter: %w", err)
	}
	oauthState := base64.RawURLEncoding.EncodeToString(stateBytes)

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
	params.Set("state", oauthState)
	if selectedConfig != nil && selectedConfig.Scope != "" {
		params.Set("scope", selectedConfig.Scope)
	}
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
			// PAR failed — fall back to standard authorization URL
			h.Logger.Debug("PAR request failed, falling back to standard authorization", zap.Error(parErr))
			q := authEndpoint.Query()
			for key, values := range params {
				for _, value := range values {
					q.Set(key, value)
				}
			}
			authEndpoint.RawQuery = q.Encode()
			authURL = authEndpoint.String()
		} else {
			// Build authorization URL with only client_id and request_uri
			q := authEndpoint.Query()
			q.Set("client_id", redirectURI)
			q.Set("request_uri", requestURI)
			authEndpoint.RawQuery = q.Encode()
			authURL = authEndpoint.String()
		}
	} else {
		// Standard authorization URL with all parameters, preserving any fixed
		// query parameters already present on the authorization endpoint.
		q := authEndpoint.Query()
		for key, values := range params {
			for _, value := range values {
				q.Set(key, value)
			}
		}
		authEndpoint.RawQuery = q.Encode()
		authURL = authEndpoint.String()
	}

	// Use token endpoint from OAuth metadata if the issuer metadata doesn't have one
	if metadata.TokenEndpoint == "" && oauthMeta.TokenEndpoint != "" {
		metadata.TokenEndpoint = oauthMeta.TokenEndpoint
	}

	// Send authorization URL and PKCE code_verifier to the client.
	// The client stores code_verifier for flow resume after redirect (option A).
	// Include the parsed credential offer so client can resume with a stateless backend.
	progressData := map[string]interface{}{
		"authorization_url":     authURL,
		"expected_redirect_uri": redirectURI,
		"state":                 oauthState,
		"credential_offer":      offer,
	}
	if pkceEnabled {
		progressData["code_verifier"] = codeVerifier
	}
	_ = h.Progress(StepAuthorizationReq, progressData)

	// Wait for authorization complete
	action, err := h.WaitForAction(ctx, ActionAuthorizationComplete)
	if err != nil {
		return nil, err
	}

	var authResult struct {
		Code         string `json:"code"`
		State        string `json:"state"`
		CodeVerifier string `json:"code_verifier"`
	}
	if err := json.Unmarshal(action.Payload, &authResult); err != nil {
		_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "Invalid authorization response")
		return nil, err
	}

	// Validate state parameter (CSRF protection)
	if authResult.State != oauthState {
		_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "State parameter mismatch")
		return nil, errors.New("state parameter mismatch (possible CSRF)")
	}

	// Use client-provided code_verifier if present (flow resume scenario);
	// otherwise use the locally generated one.
	verifier := ""
	if pkceEnabled {
		if authResult.CodeVerifier != "" {
			verifier = authResult.CodeVerifier
		} else {
			verifier = codeVerifier
		}
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
	data.Set("client_id", redirectURI)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	// Token exchange with DPoP nonce retry (RFC 9449 §8)
	for attempt := 0; attempt < 2; attempt++ {
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

		// Check for DPoP nonce requirement — retry once with server-provided nonce
		if attempt == 0 && isDPoPNonceError(resp) {
			h.updateDPoPNonce(resp)
			_ = resp.Body.Close()
			continue
		}
		h.updateDPoPNonce(resp)

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
			_ = resp.Body.Close()
			h.Logger.Debug("token endpoint error (auth code)", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))
			_ = h.Error(StepExchangingToken, ErrCodeTokenError, ErrCodeTokenError.UserFacingMessage())
			return nil, parseOAuthError(resp.StatusCode, body)
		}

		var token TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("failed to parse token response: %w", err)
		}
		_ = resp.Body.Close()

		_ = h.ProgressMessage(StepTokenObtained, "Access token obtained")
		return &token, nil
	}

	return nil, errors.New("token request failed after DPoP nonce retry")
}

// resumeWithAuthCode handles flow resumption after same-tab redirect.
// The client has saved the credential offer and code_verifier, redirected to the AS,
// and returned with an authorization code. This function skips authorization URL
// generation and directly exchanges the auth code for a token.
func (h *OID4VCIHandler) resumeWithAuthCode(ctx context.Context, msg *FlowStartMessage, metadata *IssuerMetadata) (*TokenResponse, error) {
	h.Logger.Info("Resuming OID4VCI flow with authorization code")
	_ = h.ProgressMessage(StepAuthorizationReq, "Resuming flow with authorization code")

	// Fetch OAuth metadata to get token endpoint and check PKCE requirements
	oauthMeta := h.fetchOAuthMetadata(ctx, metadata)
	if oauthMeta != nil && oauthMeta.TokenEndpoint != "" && metadata.TokenEndpoint == "" {
		metadata.TokenEndpoint = oauthMeta.TokenEndpoint
	}

	// Validate code_verifier: PKCE defaults to enabled (OID4VCI spec), so if the
	// AS requires it the token exchange will fail without a verifier. Catch this
	// early with a clear error rather than an opaque OAuth error from the AS.
	pkceRequired := oauthMeta == nil || oauthMeta.supportsPKCE()
	codeVerifier := strings.TrimSpace(msg.CodeVerifier)
	if pkceRequired && codeVerifier == "" {
		_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "code_verifier is required for flow resumption")
		return nil, errors.New("code_verifier is required for flow resumption")
	}

	// Use redirect URI from message
	redirectURI := msg.RedirectURI
	if redirectURI == "" {
		_ = h.Error(StepAuthorizationReq, ErrCodeAuthorizationFail, "redirect_uri is required for flow resumption")
		return nil, errors.New("redirect_uri is required for flow resumption")
	}

	// Exchange authorization code using provided code_verifier
	return h.exchangeAuthCode(ctx, metadata, msg.AuthCode, redirectURI, codeVerifier)
}

// CNonceRequiredError is returned by requestCredential when the credential
// endpoint responds with an error that includes a refreshed c_nonce. The
// engine should re-request all proofs from the frontend using the new nonce
// and retry the credential request.
type CNonceRequiredError struct {
	NewNonce string
	Err      error
}

func (e *CNonceRequiredError) Error() string { return e.Err.Error() }
func (e *CNonceRequiredError) Unwrap() error { return e.Err }

func (h *OID4VCIHandler) needsProof(config *CredentialConfig) bool {
	return len(config.ProofTypesSupported) > 0
}

// credentialBatchSize returns the number of proofs the engine should request
// for a credential. It is 1 when batch_credential_issuance is absent or has a
// batch_size ≤ 1. A batch_size of 0 is treated as absent (defaults to 1).
func credentialBatchSize(metadata *IssuerMetadata) int {
	if metadata.BatchCredentialIssuance == nil || metadata.BatchCredentialIssuance.BatchSize <= 1 {
		return 1
	}
	return metadata.BatchCredentialIssuance.BatchSize
}

// requestProofs asks the frontend to generate the required OID4VCI proofs and
// validates that each returned proof type is listed in proof_types_supported.
func (h *OID4VCIHandler) requestProofs(ctx context.Context, metadata *IssuerMetadata, config *CredentialConfig, nonce string) ([]ProofObject, error) {
	count := credentialBatchSize(metadata)

	resp, err := h.RequestSign(ctx, SignActionGenerateProof, SignRequestParams{
		Audience:            metadata.CredentialIssuer,
		Nonce:               nonce,
		Issuer:              h.redirectURI,
		ProofTypesSupported: config.ProofTypesSupported,
		Count:               count,
	})
	if err != nil {
		return nil, err
	}

	if len(resp.Proofs) == 0 {
		return nil, errors.New("frontend returned no proofs")
	}

	// Determine proof type from first proof
	proofType := resp.Proofs[0].ProofType

	// Validate proof count based on proof type:
	// - 'attestation': one proof can cover multiple credentials (batch attestation)
	// - 'jwt' or other: need one proof per credential in the batch
	if proofType != "attestation" && len(resp.Proofs) != count {
		return nil, fmt.Errorf("frontend returned %d %s proofs (expected %d)", len(resp.Proofs), proofType, count)
	}

	// Validate that every returned proof type is listed in proof_types_supported
	// and that all proofs are the same type
	for _, proof := range resp.Proofs {
		if proof.ProofType != proofType {
			return nil, fmt.Errorf("mixed proof types not allowed: got %q and %q", proofType, proof.ProofType)
		}
		if _, ok := config.ProofTypesSupported[proof.ProofType]; !ok {
			return nil, fmt.Errorf("unsupported proof type %q: not listed in proof_types_supported", proof.ProofType)
		}
	}

	return resp.Proofs, nil
}

func (h *OID4VCIHandler) requestCredential(ctx context.Context, metadata *IssuerMetadata, token *TokenResponse, configID string, config *CredentialConfig, proofs []ProofObject) (*CredentialResponse, error) {
	_ = h.ProgressMessage(StepRequestingCredential, "Requesting credential from issuer")

	reqBody := map[string]interface{}{
		"format":                      config.Format,
		"credential_configuration_id": configID,
	}
	if config.VCT != "" {
		reqBody["vct"] = config.VCT
	}
	// Always use the "proofs" object (OID4VCI §7.2), even for a single proof
	if len(proofs) > 0 {
		// Validate all proofs are the same type (OID4VCI spec requirement)
		proofType := proofs[0].ProofType
		for _, p := range proofs[1:] {
			if p.ProofType != proofType {
				return nil, fmt.Errorf("mixed proof types not allowed: got %q and %q", proofType, p.ProofType)
			}
		}

		// Transform to OID4VCI spec format: {"<proof_type>": ["...", "..."]}
		var proofValues []string
		for _, p := range proofs {
			switch p.ProofType {
			case "jwt":
				proofValues = append(proofValues, p.JWT)
			case "attestation":
				proofValues = append(proofValues, p.Attestation)
			}
		}
		reqBody["proofs"] = map[string][]string{proofType: proofValues}
	}

	// Credential response encryption (OID4VCI §7.3)
	var encKey *ecdsa.PrivateKey
	encCfg := metadata.CredentialResponseEncryption
	if encCfg != nil {
		// Negotiate a mutually supported alg/enc pair (prefer stronger encryption)
		type algEnc struct{ alg, enc string }
		candidates := []algEnc{
			{"ECDH-ES", "A256GCM"},
			{"ECDH-ES", "A128GCM"},
			{"ECDH-ES", "A256CBC-HS512"},
			{"ECDH-ES", "A128CBC-HS256"},
		}
		var selectedAlg, selectedEnc string
		for _, c := range candidates {
			if encCfg.supportsAlg(c.alg) && encCfg.supportsEnc(c.enc) {
				selectedAlg = c.alg
				selectedEnc = c.enc
				break
			}
		}
		if selectedAlg == "" || selectedEnc == "" {
			if encCfg.EncryptionRequired {
				return nil, fmt.Errorf("issuer requires credential response encryption but no mutually supported alg/enc pair is available")
			}
		} else {
			var err error
			encKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("failed to generate encryption key: %w", err)
			}
			encJWK, err := ecPublicKeyJWK(&encKey.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to build encryption JWK: %w", err)
			}
			encJWK["use"] = "enc"
			encJWK["alg"] = selectedAlg
			reqBody["credential_response_encryption"] = map[string]interface{}{
				"alg": selectedAlg,
				"enc": selectedEnc,
				"jwk": encJWK,
			}
		}
	}

	bodyBytes, _ := json.Marshal(reqBody)

	// Credential request with DPoP nonce retry (RFC 9449 §8)
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", metadata.CredentialEndpoint, strings.NewReader(string(bodyBytes)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		h.setAuthorizationHeader(req, token)
		if strings.EqualFold(token.TokenType, "DPoP") {
			if err := h.setDPoPHeader(req, metadata.CredentialEndpoint, token.AccessToken); err != nil {
				return nil, err
			}
		}

		resp, err := h.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("credential request failed: %w", err)
		}

		// Check for DPoP nonce requirement — retry once with server-provided nonce
		if attempt == 0 && isDPoPNonceError(resp) {
			h.updateDPoPNonce(resp)
			_ = resp.Body.Close()
			continue
		}
		h.updateDPoPNonce(resp)

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
			_ = resp.Body.Close()
			h.Logger.Debug("credential endpoint error", zap.Int("status", resp.StatusCode), zap.String("body", string(body)))

			// Check whether the error response contains a refreshed c_nonce so the
			// caller can re-request proofs and retry. Do NOT send a flow error here —
			// that is the caller's responsibility when no retry is possible.
			var errResp struct {
				CNonce string `json:"c_nonce"`
			}
			if json.Unmarshal(body, &errResp) == nil && errResp.CNonce != "" {
				return nil, &CNonceRequiredError{
					NewNonce: errResp.CNonce,
					Err:      parseOAuthError(resp.StatusCode, body),
				}
			}

			_ = h.Error(StepRequestingCredential, ErrCodeCredentialError, ErrCodeCredentialError.UserFacingMessage())
			return nil, parseOAuthError(resp.StatusCode, body)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPResponseBodyBytes))
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read credential response: %w", err)
		}

		// Detect encrypted response (JWE compact serialization)
		contentType := resp.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)
		if encKey != nil && (mediaType == "application/jwt" || mediaType == "application/jose") {
			credResp, err := decryptJWEResponse(string(body), encKey)
			if err != nil {
				return nil, err
			}
			return credResp, nil
		}

		var credResp CredentialResponse
		if err := json.Unmarshal(body, &credResp); err != nil {
			return nil, fmt.Errorf("failed to parse credential response: %w", err)
		}

		return &credResp, nil
	}

	return nil, errors.New("credential request failed after DPoP nonce retry")
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
		if strings.EqualFold(token.TokenType, "DPoP") {
			if err := h.setDPoPHeader(req, deferredEndpoint, token.AccessToken); err != nil {
				return nil, err
			}
		}

		resp, err := h.httpClient.Do(req)
		if err != nil {
			h.Logger.Warn("Deferred polling request failed", zap.Error(err), zap.Int("attempt", attempt+1))
			continue // Retry on network errors
		}

		// Handle DPoP nonce on deferred responses
		h.updateDPoPNonce(resp)
		if isDPoPNonceError(resp) {
			_ = resp.Body.Close()
			continue // Retry immediately with new nonce (counts as one attempt)
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
		case map[string]interface{}:
			if innerCred, ok := v["credential"].(string); ok {
				credStr = innerCred
			} else {
				bytes, _ := json.Marshal(v)
				credStr = string(bytes)
			}
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
		case map[string]interface{}:
			if innerCred, ok := v["credential"].(string); ok {
				credStr = innerCred
			} else {
				bytes, _ := json.Marshal(v)
				credStr = string(bytes)
			}
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
