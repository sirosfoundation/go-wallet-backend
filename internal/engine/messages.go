// Package engine implements the WebSocket v2 protocol engine for wallet operations.
// The engine handles OID4VCI credential issuance and OID4VP credential presentation flows.
package engine

import (
	"encoding/json"
	"time"
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
	TypeHandshake    MessageType = "handshake"
	TypeFlowStart    MessageType = "flow_start"
	TypeFlowAction   MessageType = "flow_action"
	TypeSignResponse MessageType = "sign_response"

	// Server → Client
	TypeHandshakeComplete MessageType = "handshake_complete"
	TypeFlowProgress      MessageType = "flow_progress"
	TypeFlowComplete      MessageType = "flow_complete"
	TypeFlowError         MessageType = "flow_error"
	TypeSignRequest       MessageType = "sign_request"
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
	StepParsingRequest         FlowStep = "parsing_request"
	StepRequestParsed          FlowStep = "request_parsed"
	StepEvaluatingVerifierTrust FlowStep = "evaluating_verifier_trust"
	StepMatchCredentials       FlowStep = "match_credentials"
	StepAwaitingConsent        FlowStep = "awaiting_consent"
	StepSubmittingResponse     FlowStep = "submitting_response"
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
	ErrCodePresentationError ErrorCode = "PRESENTATION_ERROR"
	ErrCodeInternalError     ErrorCode = "INTERNAL_ERROR"
)

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
	ActionSelectCredential     = "select_credential"
	ActionAuthorizationComplete = "authorization_complete"
	ActionProvidePin           = "provide_pin"
	ActionCredentialsMatched   = "credentials_matched"
	ActionConsent              = "consent"
	ActionDecline              = "decline"
)

// FlowCompleteMessage indicates successful flow completion
type FlowCompleteMessage struct {
	Message
	Credentials  []CredentialResult `json:"credentials,omitempty"`
	RedirectURI  string             `json:"redirect_uri,omitempty"`
	TypeMetadata json.RawMessage    `json:"type_metadata,omitempty"`
}

// FlowErrorMessage indicates a flow error
type FlowErrorMessage struct {
	Message
	Step  FlowStep   `json:"step,omitempty"`
	Error FlowError  `json:"error"`
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
	Action SignAction          `json:"action"`
	Params SignRequestParams   `json:"params"`
}

// SignRequestParams contains signing parameters
type SignRequestParams struct {
	Audience            string             `json:"audience,omitempty"`
	Nonce               string             `json:"nonce,omitempty"`
	ProofType           string             `json:"proof_type,omitempty"`
	CredentialsToInclude []CredentialRef   `json:"credentials_to_include,omitempty"`
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

// TrustInfo contains trust evaluation results
type TrustInfo struct {
	Trusted      bool     `json:"trusted"`
	Framework    string   `json:"framework,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Certificates []string `json:"certificates,omitempty"`
}

// VerifierInfo contains verifier metadata
type VerifierInfo struct {
	Name      string    `json:"name"`
	Logo      *LogoInfo `json:"logo,omitempty"`
	Trusted   bool      `json:"trusted"`
	Framework string    `json:"framework,omitempty"`
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
	InputDescriptorID   string          `json:"input_descriptor_id"`
	CredentialID        string          `json:"credential_id"`
	CredentialDisplay   json.RawMessage `json:"credential_display,omitempty"`
	DisclosableClaims   []string        `json:"disclosable_claims,omitempty"`
	RequiredClaims      []string        `json:"required_claims,omitempty"`
}

// ConsentSelection represents user's disclosure selection
type ConsentSelection struct {
	CredentialID    string   `json:"credential_id"`
	DisclosedClaims []string `json:"disclosed_claims"`
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
