// Package engine implements the WebSocket v2 protocol engine for wallet operations.
// The engine handles OID4VCI credential issuance and OID4VP credential presentation flows.
package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// Protocol identifies the type of credential flow
type Protocol string

const (
	ProtocolOID4VCI Protocol = "oid4vci"
	ProtocolOID4VP  Protocol = "oid4vp"
	ProtocolVCTM    Protocol = "vctm"
)

// MessageType identifies the type of WebSocket message
type MessageType string

const (
	// Client → Server
	TypeHandshake     MessageType = "handshake"
	TypeFlowStart     MessageType = "flow_start"
	TypeFlowAction    MessageType = "flow_action"
	TypeSignResponse  MessageType = "sign_response"
	TypeMatchResponse MessageType = "match_response"

	// Server → Client
	TypeHandshakeComplete MessageType = "handshake_complete"
	TypeFlowProgress      MessageType = "flow_progress"
	TypeFlowComplete      MessageType = "flow_complete"
	TypeFlowError         MessageType = "flow_error"
	TypeSignRequest       MessageType = "sign_request"
	TypeMatchRequest      MessageType = "match_request"
	TypePush              MessageType = "push"
	TypeError             MessageType = "error"
)

// FlowStep identifies the current step in a flow
type FlowStep string

// Common flow steps
const (
	StepParsingOffer         FlowStep = "parsing_offer"
	StepOfferParsed          FlowStep = "offer_parsed"
	StepFetchingMetadata     FlowStep = "fetching_metadata"
	StepMetadataFetched      FlowStep = "metadata_fetched"
	StepEvaluatingTrust      FlowStep = "evaluating_trust"
	StepTrustEvaluated       FlowStep = "trust_evaluated"
	StepAwaitingSelection    FlowStep = "awaiting_selection"
	StepAuthorizationReq     FlowStep = "authorization_required"
	StepExchangingToken      FlowStep = "exchanging_token"
	StepTokenObtained        FlowStep = "token_obtained"
	StepRequestingCredential FlowStep = "requesting_credential"
	StepDeferred             FlowStep = "deferred"

	// OID4VP specific
	StepParsingRequest          FlowStep = "parsing_request"
	StepRequestParsed           FlowStep = "request_parsed"
	StepEvaluatingVerifierTrust FlowStep = "evaluating_verifier_trust"
	StepMatchCredentials        FlowStep = "match_credentials"
	StepAwaitingConsent         FlowStep = "awaiting_consent"
	StepSubmittingResponse      FlowStep = "submitting_response"
)

// ErrorCode represents a protocol error code
type ErrorCode string

const (
	ErrCodeAuthFailed        ErrorCode = "AUTH_FAILED"
	ErrCodeInvalidMessage    ErrorCode = "INVALID_MESSAGE"
	ErrCodeUnknownFlow       ErrorCode = "UNKNOWN_FLOW"
	ErrCodeFlowTimeout       ErrorCode = "FLOW_TIMEOUT"
	ErrCodeOfferParseError   ErrorCode = "OFFER_PARSE_ERROR"
	ErrCodeOfferFetchError   ErrorCode = "OFFER_FETCH_ERROR"
	ErrCodeMetadataFetchErr  ErrorCode = "METADATA_FETCH_ERROR"
	ErrCodeUntrustedIssuer   ErrorCode = "UNTRUSTED_ISSUER"
	ErrCodeUntrustedVerifier ErrorCode = "UNTRUSTED_VERIFIER"
	ErrCodeAuthorizationFail ErrorCode = "AUTHORIZATION_FAILED"
	ErrCodeTokenError        ErrorCode = "TOKEN_ERROR"
	ErrCodeCredentialError   ErrorCode = "CREDENTIAL_ERROR"
	ErrCodeSignTimeout       ErrorCode = "SIGN_TIMEOUT"
	ErrCodeSignError         ErrorCode = "SIGN_ERROR"
	ErrCodeMatchTimeout      ErrorCode = "MATCH_TIMEOUT"
	ErrCodeMatchError        ErrorCode = "MATCH_ERROR"
	ErrCodePresentationError ErrorCode = "PRESENTATION_ERROR"
	ErrCodeInternalError     ErrorCode = "INTERNAL_ERROR"
	ErrCodeTooManyRequests   ErrorCode = "TOO_MANY_REQUESTS"
)

// UserFacingMessage returns a generic user-facing message for an error code.
// This is used to prevent leaking internal error details to clients.
func (c ErrorCode) UserFacingMessage() string {
	switch c {
	case ErrCodeAuthFailed:
		return "Authentication failed"
	case ErrCodeInvalidMessage:
		return "Invalid message format"
	case ErrCodeUnknownFlow:
		return "Unknown flow"
	case ErrCodeFlowTimeout:
		return "Flow timed out"
	case ErrCodeOfferParseError:
		return "Could not parse credential offer"
	case ErrCodeOfferFetchError:
		return "Could not fetch credential offer"
	case ErrCodeMetadataFetchErr:
		return "Could not fetch issuer metadata"
	case ErrCodeUntrustedIssuer:
		return "Issuer is not trusted"
	case ErrCodeUntrustedVerifier:
		return "Verifier is not trusted"
	case ErrCodeAuthorizationFail:
		return "Authorization failed"
	case ErrCodeTokenError:
		return "Token exchange failed"
	case ErrCodeCredentialError:
		return "Credential issuance failed"
	case ErrCodeSignTimeout:
		return "Signing request timed out"
	case ErrCodeSignError:
		return "Signing failed"
	case ErrCodeMatchTimeout:
		return "Credential matching timed out"
	case ErrCodeMatchError:
		return "Credential matching failed"
	case ErrCodePresentationError:
		return "Presentation failed"
	case ErrCodeInternalError:
		return "Internal server error"
	case ErrCodeTooManyRequests:
		return "Too many requests"
	default:
		return "An error occurred"
	}
}

// SignAction identifies the type of signing operation
type SignAction string

const (
	SignActionGenerateProof    SignAction = "generate_proof"
	SignActionSignPresentation SignAction = "sign_presentation"
)

// Message is the base message envelope for all WebSocket messages
type Message struct {
	Type      MessageType `json:"type"`
	FlowID    string      `json:"flow_id,omitempty"`
	MessageID string      `json:"message_id,omitempty"`
	Timestamp string      `json:"timestamp,omitempty"`
}

// HandshakeMessage is sent by client to authenticate
type HandshakeMessage struct {
	Message
	AppToken string `json:"app_token"`
}

// HandshakeCompleteMessage is sent by server on successful authentication
type HandshakeCompleteMessage struct {
	Message
	SessionID    string   `json:"session_id"`
	Capabilities []string `json:"capabilities"`
}

// FlowStartMessage initiates a credential flow
type FlowStartMessage struct {
	Message
	Protocol           Protocol `json:"protocol"`
	Offer              string   `json:"offer,omitempty"`                // OID4VCI: openid-credential-offer://...
	CredentialOfferURI string   `json:"credential_offer_uri,omitempty"` // OID4VCI: https://...
	RequestURI         string   `json:"request_uri,omitempty"`          // OID4VP: openid4vp://...
	RequestURIRef      string   `json:"request_uri_ref,omitempty"`      // OID4VP: https://...
	VCT                string   `json:"vct,omitempty"`                  // VCTM lookup
	RedirectURI        string   `json:"redirect_uri,omitempty"`         // OAuth redirect URI for authorization code flow
}

// FlowProgressMessage reports flow progress to client
type FlowProgressMessage struct {
	Message
	Step    FlowStep        `json:"step"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// FlowActionMessage is sent by client to provide input during a flow
type FlowActionMessage struct {
	Message
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// FlowAction types
const (
	ActionSelectCredential      = "select_credential"
	ActionAuthorizationComplete = "authorization_complete"
	ActionProvidePin            = "provide_pin"
	ActionCredentialsMatched    = "credentials_matched"
	ActionConsent               = "consent"
	ActionDecline               = "decline"
	ActionTrustResult           = "trust_result" // Frontend reports trust evaluation result
)

// FlowCompleteMessage indicates successful flow completion
type FlowCompleteMessage struct {
	Message
	Credentials  []CredentialResult     `json:"credentials,omitempty"`
	RedirectURI  string                 `json:"redirect_uri,omitempty"`
	TypeMetadata json.RawMessage        `json:"type_metadata,omitempty"`
	ResponseData map[string]interface{} `json:"response_data,omitempty"` // dc_api: VP response for postMessage delivery
}

// FlowErrorMessage indicates a flow error
type FlowErrorMessage struct {
	Message
	Step  FlowStep  `json:"step,omitempty"`
	Error FlowError `json:"error"`
}

// FlowError contains error details
type FlowError struct {
	Code    ErrorCode              `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// SignRequestMessage requests client-side signing
type SignRequestMessage struct {
	Message
	Action SignAction        `json:"action"`
	Params SignRequestParams `json:"params"`
}

// SignRequestParams contains signing parameters
type SignRequestParams struct {
	Audience             string          `json:"audience,omitempty"`
	Nonce                string          `json:"nonce,omitempty"`
	ProofType            string          `json:"proof_type,omitempty"`
	CredentialsToInclude []CredentialRef `json:"credentials_to_include,omitempty"`
}

// CredentialRef references a credential for signing
type CredentialRef struct {
	CredentialID    string   `json:"credential_id"`
	DisclosedClaims []string `json:"disclosed_claims,omitempty"`
}

// SignResponseMessage is the client's signature response
type SignResponseMessage struct {
	Message
	ProofJWT string `json:"proof_jwt,omitempty"`
	VPToken  string `json:"vp_token,omitempty"`
}

// MatchRequestMessage requests client-side credential matching
// This is the privacy-preserving protocol: credentials are matched locally
// and only matching credential IDs/metadata are sent back to the server.
type MatchRequestMessage struct {
	Message
	PresentationDefinition *PresentationDefinition `json:"presentation_definition"`
}

// MatchResponseMessage is the client's matching response
type MatchResponseMessage struct {
	Message
	Matches       []CredentialMatch `json:"matches"`
	NoMatchReason string            `json:"no_match_reason,omitempty"`
	Error         string            `json:"error,omitempty"`
}

// PushMessage is a server-initiated notification
type PushMessage struct {
	Message
	PushType    string             `json:"push_type"`
	Credentials []CredentialResult `json:"credentials,omitempty"`
}

// ErrorMessage is a protocol-level error
type ErrorMessage struct {
	Message
	Code    ErrorCode `json:"code"`
	Details string    `json:"message"`
}

// CredentialResult represents an issued credential
type CredentialResult struct {
	Format       string          `json:"format"`
	Credential   string          `json:"credential"`
	VCT          string          `json:"vct,omitempty"`
	TypeMetadata json.RawMessage `json:"type_metadata,omitempty"`
}

// TrustInfo contains trust evaluation results.
// Deprecated: Use trust.TrustInfo directly when writing new code.
type TrustInfo = trust.TrustInfo

// VerifierInfo contains verifier metadata
type VerifierInfo struct {
	Name           string    `json:"name"`
	Logo           *LogoInfo `json:"logo,omitempty"`
	Trusted        bool      `json:"trusted"`
	TrustedStatus  string    `json:"trusted_status,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Domain         string    `json:"domain,omitempty"`
	Framework      string    `json:"framework,omitempty"`
	ClientIDScheme string    `json:"client_id_scheme,omitempty"`
	ClientID       string    `json:"client_id,omitempty"` // Configured client_id for VP audience
}

// LogoInfo contains logo metadata
type LogoInfo struct {
	URI string `json:"uri"`
}

// CredentialMatch represents a credential that matches a presentation request
type CredentialMatch struct {
	InputDescriptorID string   `json:"input_descriptor_id"`
	CredentialID      string   `json:"credential_id"`
	Format            string   `json:"format"`
	VCT               string   `json:"vct,omitempty"`
	AvailableClaims   []string `json:"available_claims,omitempty"`
}

// MatchedCredential represents a credential with consent info
type MatchedCredential struct {
	InputDescriptorID string          `json:"input_descriptor_id"`
	CredentialID      string          `json:"credential_id"`
	CredentialDisplay json.RawMessage `json:"credential_display,omitempty"`
	DisclosableClaims []string        `json:"disclosable_claims,omitempty"`
	RequiredClaims    []string        `json:"required_claims,omitempty"`
}

// ConsentSelection represents user's disclosure selection
type ConsentSelection struct {
	CredentialID    string   `json:"credential_id"`
	DisclosedClaims []string `json:"disclosed_claims"`
}

// SubjectType constants for trust evaluation
const (
	SubjectTypeCredentialIssuer   = "credential_issuer"
	SubjectTypeCredentialVerifier = "credential_verifier"
)

// KeyMaterialType constants
const (
	KeyMaterialTypeX5C = "x5c"
	KeyMaterialTypeJWK = "jwk"
)

// TrustEvaluationRequest is the payload sent to frontend for trust evaluation.
// The frontend should call POST /v1/evaluate with this data and return the result.
// For DID schemes, the frontend should first call /v1/resolve to get the DID document.
type TrustEvaluationRequest struct {
	// SubjectID is the identifier to evaluate (client_id for verifiers, issuer URL for issuers)
	SubjectID string `json:"subject_id"`
	// SubjectType is "credential_verifier" or "credential_issuer"
	SubjectType string `json:"subject_type"`
	// KeyMaterial contains the cryptographic key for binding validation.
	// For DID schemes, this may be nil - frontend resolves keys via /v1/resolve.
	KeyMaterial *TrustKeyMaterial `json:"key_material,omitempty"`
	// RequiresResolution indicates the frontend should call /v1/resolve first.
	// Set to true for DID schemes where key material must be resolved from DID document.
	RequiresResolution bool `json:"requires_resolution,omitempty"`
	// RequestJWT is the signed request JWT for DID schemes.
	// Frontend should verify this JWT using keys obtained from /v1/resolve.
	RequestJWT string `json:"request_jwt,omitempty"`
	// Context contains additional evaluation context
	Context map[string]interface{} `json:"context,omitempty"`
}

// Validate checks that required fields are present and valid.
// Returns an error if the request is malformed.
func (r *TrustEvaluationRequest) Validate() error {
	if r.SubjectID == "" {
		return errors.New("TrustEvaluationRequest: SubjectID is required")
	}
	if r.SubjectType != SubjectTypeCredentialIssuer && r.SubjectType != SubjectTypeCredentialVerifier {
		return fmt.Errorf("TrustEvaluationRequest: SubjectType must be %q or %q, got %q",
			SubjectTypeCredentialIssuer, SubjectTypeCredentialVerifier, r.SubjectType)
	}
	// RequiresResolution requires RequestJWT for DID schemes
	if r.RequiresResolution && r.RequestJWT == "" {
		return errors.New("TrustEvaluationRequest: RequestJWT is required when RequiresResolution is true")
	}
	// Validate key material if provided
	if r.KeyMaterial != nil {
		if err := r.KeyMaterial.Validate(); err != nil {
			return fmt.Errorf("TrustEvaluationRequest: %w", err)
		}
	}
	return nil
}

// TrustKeyMaterial contains key material for trust evaluation
type TrustKeyMaterial struct {
	// Type is "x5c" or "jwk"
	Type string `json:"type"`
	// X5C contains base64-encoded DER certificates (for x5c type)
	X5C []string `json:"x5c,omitempty"`
	// JWK contains the JWK key data (for jwk type)
	JWK interface{} `json:"jwk,omitempty"`
}

// Validate checks that the key material is well-formed.
func (km *TrustKeyMaterial) Validate() error {
	if km.Type != KeyMaterialTypeX5C && km.Type != KeyMaterialTypeJWK {
		return fmt.Errorf("KeyMaterial: Type must be %q or %q, got %q",
			KeyMaterialTypeX5C, KeyMaterialTypeJWK, km.Type)
	}
	if km.Type == KeyMaterialTypeX5C && len(km.X5C) == 0 {
		return errors.New("KeyMaterial: X5C array is required for x5c type")
	}
	if km.Type == KeyMaterialTypeJWK && km.JWK == nil {
		return errors.New("KeyMaterial: JWK is required for jwk type")
	}
	return nil
}

// TrustResultPayload is sent by frontend after evaluating trust via /v1/evaluate
type TrustResultPayload struct {
	// Trusted indicates whether the subject is trusted
	Trusted bool `json:"trusted"`
	// Name is the display name from trust evaluation
	Name string `json:"name,omitempty"`
	// Logo is the logo URL from trust evaluation
	Logo string `json:"logo,omitempty"`
	// Framework identifies the trust framework (e.g., "etsi_tsl", "openid_federation", "did")
	Framework string `json:"framework,omitempty"`
	// Reason provides additional context for the decision
	Reason string `json:"reason,omitempty"`
	// Metadata contains additional trust-related data
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	// validated marks that this payload has passed validation
	validated bool
}

// MaxNameLength is the maximum allowed length for display names.
const MaxNameLength = 256

// MaxLogoURLLength is the maximum allowed length for logo URLs.
const MaxLogoURLLength = 2048

// MaxReasonLength is the maximum allowed length for reason strings.
const MaxReasonLength = 1024

// Validate checks that the trust result is well-formed.
// Call this after unmarshaling from JSON to detect malformed payloads.
// This includes XSS protection by validating field lengths and URL formats.
func (r *TrustResultPayload) Validate() error {
	// Note: Trusted is a boolean, so JSON will default to false if missing.
	// This is semantically correct (fail-closed).

	// Validate Name length to prevent XSS/DoS via oversized strings
	if len(r.Name) > MaxNameLength {
		return fmt.Errorf("TrustResultPayload: Name exceeds maximum length (%d > %d)", len(r.Name), MaxNameLength)
	}

	// Validate Logo URL length and format
	if r.Logo != "" {
		if len(r.Logo) > MaxLogoURLLength {
			return fmt.Errorf("TrustResultPayload: Logo URL exceeds maximum length (%d > %d)", len(r.Logo), MaxLogoURLLength)
		}
		// Basic URL validation - must start with http://, https://, or data:image/
		if !isValidLogoURL(r.Logo) {
			return errors.New("TrustResultPayload: Logo must be an HTTP(S) URL or data:image/ URI")
		}
	}

	// Validate Reason length
	if len(r.Reason) > MaxReasonLength {
		return fmt.Errorf("TrustResultPayload: Reason exceeds maximum length (%d > %d)", len(r.Reason), MaxReasonLength)
	}

	r.validated = true
	return nil
}

// isValidLogoURL checks if the URL is safe for use as a logo.
// Allows HTTPS/HTTP URLs and data:image/ URIs for embedded images.
// HTTP URLs are allowed for dev/test setups; production PDPs should only
// return HTTPS or data URLs.
// Note: SVG data URIs can contain embedded JavaScript. XSS prevention
// is a frontend responsibility - render SVGs via <img> tags (which don't
// execute scripts) or apply CSP/sanitization.
func isValidLogoURL(url string) bool {
	if len(url) < 7 {
		return false
	}
	// Check for http:// or https:// prefix (case-insensitive)
	if len(url) >= 7 && (url[:7] == "http://" || url[:7] == "HTTP://") {
		return true
	}
	if len(url) >= 8 && (url[:8] == "https://" || url[:8] == "HTTPS://") {
		return true
	}
	// Check for data:image/ prefix for inline images
	if len(url) >= 11 && url[:11] == "data:image/" {
		return true
	}
	return false
}

// IsValidated returns true if Validate() was called successfully.
func (r *TrustResultPayload) IsValidated() bool {
	return r.validated
}

// Now returns current ISO 8601 timestamp
func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ParseMessage parses a raw JSON message into a typed message
func ParseMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// MarshalMessage serializes a message to JSON
func MarshalMessage(msg interface{}) ([]byte, error) {
	return json.Marshal(msg)
}
