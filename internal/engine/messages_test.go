package engine

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNow(t *testing.T) {
	before := time.Now().UTC()
	result := Now()
	after := time.Now().UTC()

	// Parse the result
	parsed, err := time.Parse(time.RFC3339, result)
	if err != nil {
		t.Fatalf("Now() returned invalid RFC3339: %q, error: %v", result, err)
	}

	// Check it's within reasonable bounds
	if parsed.Before(before.Add(-time.Second)) || parsed.After(after.Add(time.Second)) {
		t.Errorf("Now() = %v, not within expected range [%v, %v]", parsed, before, after)
	}
}

func TestParseMessage_Valid(t *testing.T) {
	raw := `{"type":"handshake","version":"2.0","timestamp":"2024-01-01T00:00:00Z"}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}

	if msg.Type != TypeHandshake {
		t.Errorf("ParseMessage().Type = %q, want %q", msg.Type, TypeHandshake)
	}
}

func TestParseMessage_FlowStart(t *testing.T) {
	raw := `{
		"type":"flow_start",
		"flow_id":"abc123",
		"protocol":"oid4vci",
		"offer":"openid-credential-offer://..."
	}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}

	if msg.Type != TypeFlowStart {
		t.Errorf("ParseMessage().Type = %q, want %q", msg.Type, TypeFlowStart)
	}
}

func TestParseMessage_InvalidJSON(t *testing.T) {
	raw := `{"type": broken json`

	_, err := ParseMessage([]byte(raw))
	if err == nil {
		t.Error("ParseMessage() should return error for invalid JSON")
	}
}

func TestParseMessage_EmptyJSON(t *testing.T) {
	raw := `{}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	if msg.Type != "" {
		t.Errorf("ParseMessage().Type = %q, want empty", msg.Type)
	}
}

func TestMarshalMessage_HandshakeComplete(t *testing.T) {
	msg := &HandshakeCompleteMessage{
		Message: Message{
			Type:      TypeHandshakeComplete,
			Timestamp: "2024-01-01T00:00:00Z",
		},
		SessionID: "session-123",
	}

	data, err := MarshalMessage(msg)
	if err != nil {
		t.Fatalf("MarshalMessage() error = %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("MarshalMessage() produced invalid JSON: %v", err)
	}

	if parsed["type"] != string(TypeHandshakeComplete) {
		t.Errorf("MarshalMessage().type = %v, want %v", parsed["type"], TypeHandshakeComplete)
	}
	if parsed["session_id"] != "session-123" {
		t.Errorf("MarshalMessage().session_id = %v, want session-123", parsed["session_id"])
	}
}

func TestMarshalMessage_FlowProgress(t *testing.T) {
	msg := &FlowProgressMessage{
		Message: Message{
			Type:      TypeFlowProgress,
			FlowID:    "flow-abc",
			Timestamp: Now(),
		},
		Step: StepFetchingMetadata,
	}

	data, err := MarshalMessage(msg)
	if err != nil {
		t.Fatalf("MarshalMessage() error = %v", err)
	}

	if !strings.Contains(string(data), `"step":"fetching_metadata"`) {
		t.Errorf("MarshalMessage() missing expected step field, got: %s", data)
	}
}

func TestMarshalMessage_FlowError(t *testing.T) {
	msg := &FlowErrorMessage{
		Message: Message{
			Type:      TypeFlowError,
			FlowID:    "flow-xyz",
			Timestamp: Now(),
		},
		Step: StepEvaluatingTrust,
		Error: FlowError{
			Code:    ErrCodeUntrustedIssuer,
			Message: "Issuer not in trusted registry",
		},
	}

	data, err := MarshalMessage(msg)
	if err != nil {
		t.Fatalf("MarshalMessage() error = %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("MarshalMessage() produced invalid JSON: %v", err)
	}

	// Check nested error structure
	errorObj, ok := parsed["error"].(map[string]interface{})
	if !ok {
		t.Fatal("error field not found or wrong type")
	}
	if errorObj["code"] != string(ErrCodeUntrustedIssuer) {
		t.Errorf("error.code = %v, want %v", errorObj["code"], ErrCodeUntrustedIssuer)
	}
	if errorObj["message"] != "Issuer not in trusted registry" {
		t.Errorf("error.message = %v, want 'Issuer not in trusted registry'", errorObj["message"])
	}
}

func TestMarshalMessage_SignRequest(t *testing.T) {
	msg := &SignRequestMessage{
		Message: Message{
			Type:      TypeSignRequest,
			FlowID:    "flow-sign",
			Timestamp: Now(),
		},
		Action: SignActionGenerateProof,
		Params: SignRequestParams{
			Nonce: "test-nonce",
		},
	}

	data, err := MarshalMessage(msg)
	if err != nil {
		t.Fatalf("MarshalMessage() error = %v", err)
	}

	if !strings.Contains(string(data), `"action":"generate_proof"`) {
		t.Errorf("MarshalMessage() missing action field, got: %s", data)
	}
}

func TestProtocolConstants(t *testing.T) {
	// Verify protocol constants have expected values
	if ProtocolOID4VCI != "oid4vci" {
		t.Errorf("ProtocolOID4VCI = %q, want 'oid4vci'", ProtocolOID4VCI)
	}
	if ProtocolOID4VP != "oid4vp" {
		t.Errorf("ProtocolOID4VP = %q, want 'oid4vp'", ProtocolOID4VP)
	}
	if ProtocolVCTM != "vctm" {
		t.Errorf("ProtocolVCTM = %q, want 'vctm'", ProtocolVCTM)
	}
}

func TestMessageTypeConstants(t *testing.T) {
	// Verify message type constants
	messageTypes := map[MessageType]string{
		TypeHandshake:         "handshake",
		TypeFlowStart:         "flow_start",
		TypeFlowAction:        "flow_action",
		TypeSignResponse:      "sign_response",
		TypeMatchResponse:     "match_response",
		TypeHandshakeComplete: "handshake_complete",
		TypeFlowProgress:      "flow_progress",
		TypeFlowComplete:      "flow_complete",
		TypeFlowError:         "flow_error",
		TypeSignRequest:       "sign_request",
		TypeMatchRequest:      "match_request",
		TypePush:              "push",
		TypeError:             "error",
	}

	for mt, expected := range messageTypes {
		if string(mt) != expected {
			t.Errorf("MessageType %v = %q, want %q", mt, mt, expected)
		}
	}
}

func TestFlowStepConstants(t *testing.T) {
	// Verify flow step constants
	steps := map[FlowStep]string{
		StepParsingOffer:            "parsing_offer",
		StepOfferParsed:             "offer_parsed",
		StepFetchingMetadata:        "fetching_metadata",
		StepMetadataFetched:         "metadata_fetched",
		StepEvaluatingTrust:         "evaluating_trust",
		StepTrustEvaluated:          "trust_evaluated",
		StepAwaitingSelection:       "awaiting_selection",
		StepAuthorizationReq:        "authorization_required",
		StepExchangingToken:         "exchanging_token",
		StepTokenObtained:           "token_obtained",
		StepRequestingCredential:    "requesting_credential",
		StepDeferred:                "deferred",
		StepParsingRequest:          "parsing_request",
		StepRequestParsed:           "request_parsed",
		StepEvaluatingVerifierTrust: "evaluating_verifier_trust",
		StepMatchCredentials:        "match_credentials",
		StepAwaitingConsent:         "awaiting_consent",
		StepSubmittingResponse:      "submitting_response",
	}

	for step, expected := range steps {
		if string(step) != expected {
			t.Errorf("FlowStep %v = %q, want %q", step, step, expected)
		}
	}
}

func TestErrorCodeConstants(t *testing.T) {
	// Verify error code constants
	codes := map[ErrorCode]string{
		ErrCodeAuthFailed:        "AUTH_FAILED",
		ErrCodeInvalidMessage:    "INVALID_MESSAGE",
		ErrCodeUnknownFlow:       "UNKNOWN_FLOW",
		ErrCodeFlowTimeout:       "FLOW_TIMEOUT",
		ErrCodeOfferParseError:   "OFFER_PARSE_ERROR",
		ErrCodeOfferFetchError:   "OFFER_FETCH_ERROR",
		ErrCodeMetadataFetchErr:  "METADATA_FETCH_ERROR",
		ErrCodeUntrustedIssuer:   "UNTRUSTED_ISSUER",
		ErrCodeUntrustedVerifier: "UNTRUSTED_VERIFIER",
		ErrCodeAuthorizationFail: "AUTHORIZATION_FAILED",
		ErrCodeTokenError:        "TOKEN_ERROR",
		ErrCodeCredentialError:   "CREDENTIAL_ERROR",
		ErrCodeSignTimeout:       "SIGN_TIMEOUT",
		ErrCodeSignError:         "SIGN_ERROR",
		ErrCodeMatchTimeout:      "MATCH_TIMEOUT",
		ErrCodeMatchError:        "MATCH_ERROR",
		ErrCodePresentationError: "PRESENTATION_ERROR",
		ErrCodeInternalError:     "INTERNAL_ERROR",
	}

	for code, expected := range codes {
		if string(code) != expected {
			t.Errorf("ErrorCode %v = %q, want %q", code, code, expected)
		}
	}
}

func TestSignActionConstants(t *testing.T) {
	if SignActionGenerateProof != "generate_proof" {
		t.Errorf("SignActionGenerateProof = %q, want 'generate_proof'", SignActionGenerateProof)
	}
	if SignActionSignPresentation != "sign_presentation" {
		t.Errorf("SignActionSignPresentation = %q, want 'sign_presentation'", SignActionSignPresentation)
	}
}

func TestMarshalMessage_NilInput(t *testing.T) {
	data, err := MarshalMessage(nil)
	if err != nil {
		t.Fatalf("MarshalMessage(nil) error = %v", err)
	}
	if string(data) != "null" {
		t.Errorf("MarshalMessage(nil) = %s, want null", data)
	}
}

func TestMarshalMessage_SimpleStruct(t *testing.T) {
	simple := struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}{
		Name: "Test",
		Age:  42,
	}

	data, err := MarshalMessage(simple)
	if err != nil {
		t.Fatalf("MarshalMessage() error = %v", err)
	}

	expected := `{"name":"Test","age":42}`
	if string(data) != expected {
		t.Errorf("MarshalMessage() = %s, want %s", data, expected)
	}
}

func TestParseMessage_AllFields(t *testing.T) {
	raw := `{
		"type": "flow_start",
		"timestamp": "2024-01-01T00:00:00Z",
		"flow_id": "test-flow"
	}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}

	if msg.Type != TypeFlowStart {
		t.Errorf("Type = %q, want %q", msg.Type, TypeFlowStart)
	}
	if msg.Timestamp != "2024-01-01T00:00:00Z" {
		t.Errorf("Timestamp = %q, want '2024-01-01T00:00:00Z'", msg.Timestamp)
	}
}

// TestCredentialResultJSON verifies CredentialResult marshals correctly
func TestCredentialResultJSON(t *testing.T) {
	result := CredentialResult{
		Format:     "vc+sd-jwt",
		Credential: "eyJ...",
		VCT:        "urn:eu.europa.ec.eudi:pid:1",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed CredentialResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.Format != result.Format {
		t.Errorf("Format = %q, want %q", parsed.Format, result.Format)
	}
	if parsed.Credential != result.Credential {
		t.Errorf("Credential = %q, want %q", parsed.Credential, result.Credential)
	}
	if parsed.VCT != result.VCT {
		t.Errorf("VCT = %q, want %q", parsed.VCT, result.VCT)
	}
}

// TestTrustInfoJSON verifies TrustInfo marshals correctly
func TestTrustInfoJSON(t *testing.T) {
	info := TrustInfo{
		Trusted:   true,
		Framework: "authzen",
		Reason:    "Matched trust anchor",
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed TrustInfo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.Trusted != info.Trusted {
		t.Errorf("Trusted = %v, want %v", parsed.Trusted, info.Trusted)
	}
	if parsed.Framework != info.Framework {
		t.Errorf("Framework = %q, want %q", parsed.Framework, info.Framework)
	}
}

// TestConsentSelectionJSON verifies ConsentSelection marshals correctly
func TestConsentSelectionJSON(t *testing.T) {
	selection := ConsentSelection{
		CredentialID:    "cred-abc",
		DisclosedClaims: []string{"given_name", "family_name"},
	}

	data, err := json.Marshal(selection)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed ConsentSelection
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.CredentialID != selection.CredentialID {
		t.Errorf("CredentialID = %q, want %q", parsed.CredentialID, selection.CredentialID)
	}
	if len(parsed.DisclosedClaims) != 2 {
		t.Errorf("DisclosedClaims len = %d, want 2", len(parsed.DisclosedClaims))
	}
}

// Test FlowError structure
func TestFlowErrorJSON(t *testing.T) {
	flowErr := FlowError{
		Code:    ErrCodeCredentialError,
		Message: "Failed to obtain credential",
		Details: map[string]interface{}{"issuer": "example.com"},
	}

	data, err := json.Marshal(flowErr)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed FlowError
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.Code != flowErr.Code {
		t.Errorf("Code = %q, want %q", parsed.Code, flowErr.Code)
	}
	if parsed.Message != flowErr.Message {
		t.Errorf("Message = %q, want %q", parsed.Message, flowErr.Message)
	}
}

// ============================================================================
// TrustEvaluationRequest Validation Tests
// ============================================================================

func TestTrustEvaluationRequest_Validate_Valid(t *testing.T) {
	tests := []struct {
		name string
		req  TrustEvaluationRequest
	}{
		{
			name: "valid issuer with x5c key material",
			req: TrustEvaluationRequest{
				SubjectID:   "https://issuer.example.com",
				SubjectType: SubjectTypeCredentialIssuer,
				KeyMaterial: &TrustKeyMaterial{
					Type: KeyMaterialTypeX5C,
					X5C:  []string{"base64cert"},
				},
			},
		},
		{
			name: "valid verifier with jwk key material",
			req: TrustEvaluationRequest{
				SubjectID:   "https://verifier.example.com",
				SubjectType: SubjectTypeCredentialVerifier,
				KeyMaterial: &TrustKeyMaterial{
					Type: KeyMaterialTypeJWK,
					JWK:  map[string]interface{}{"kty": "EC"},
				},
			},
		},
		{
			name: "valid DID with requires_resolution",
			req: TrustEvaluationRequest{
				SubjectID:          "did:web:example.com",
				SubjectType:        SubjectTypeCredentialVerifier,
				RequiresResolution: true,
				RequestJWT:         "eyJhbGciOiJFUzI1NiJ9...",
			},
		},
		{
			name: "valid issuer no key material",
			req: TrustEvaluationRequest{
				SubjectID:   "https://issuer.example.com",
				SubjectType: SubjectTypeCredentialIssuer,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.req.Validate(); err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}
}

func TestTrustEvaluationRequest_Validate_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		req         TrustEvaluationRequest
		wantContain string
	}{
		{
			name:        "missing subject_id",
			req:         TrustEvaluationRequest{SubjectType: SubjectTypeCredentialIssuer},
			wantContain: "SubjectID is required",
		},
		{
			name:        "empty subject_type",
			req:         TrustEvaluationRequest{SubjectID: "https://example.com"},
			wantContain: "SubjectType must be",
		},
		{
			name:        "invalid subject_type",
			req:         TrustEvaluationRequest{SubjectID: "https://example.com", SubjectType: "invalid"},
			wantContain: "SubjectType must be",
		},
		{
			name: "requires_resolution without request_jwt",
			req: TrustEvaluationRequest{
				SubjectID:          "did:web:example.com",
				SubjectType:        SubjectTypeCredentialVerifier,
				RequiresResolution: true,
			},
			wantContain: "RequestJWT is required when RequiresResolution is true",
		},
		{
			name: "invalid key material type",
			req: TrustEvaluationRequest{
				SubjectID:   "https://example.com",
				SubjectType: SubjectTypeCredentialIssuer,
				KeyMaterial: &TrustKeyMaterial{Type: "invalid"},
			},
			wantContain: "Type must be",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if err == nil {
				t.Errorf("Validate() error = nil, want error containing %q", tt.wantContain)
				return
			}
			if !strings.Contains(err.Error(), tt.wantContain) {
				t.Errorf("Validate() error = %v, want error containing %q", err, tt.wantContain)
			}
		})
	}
}

// ============================================================================
// TrustKeyMaterial Validation Tests
// ============================================================================

func TestTrustKeyMaterial_Validate_Valid(t *testing.T) {
	tests := []struct {
		name string
		km   TrustKeyMaterial
	}{
		{
			name: "valid x5c",
			km: TrustKeyMaterial{
				Type: KeyMaterialTypeX5C,
				X5C:  []string{"base64cert1", "base64cert2"},
			},
		},
		{
			name: "valid jwk",
			km: TrustKeyMaterial{
				Type: KeyMaterialTypeJWK,
				JWK:  map[string]interface{}{"kty": "EC", "crv": "P-256"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.km.Validate(); err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
		})
	}
}

func TestTrustKeyMaterial_Validate_Invalid(t *testing.T) {
	tests := []struct {
		name        string
		km          TrustKeyMaterial
		wantContain string
	}{
		{
			name:        "invalid type",
			km:          TrustKeyMaterial{Type: "invalid"},
			wantContain: "Type must be",
		},
		{
			name:        "x5c type without x5c array",
			km:          TrustKeyMaterial{Type: KeyMaterialTypeX5C},
			wantContain: "X5C array is required",
		},
		{
			name:        "x5c type with empty x5c array",
			km:          TrustKeyMaterial{Type: KeyMaterialTypeX5C, X5C: []string{}},
			wantContain: "X5C array is required",
		},
		{
			name:        "jwk type without jwk",
			km:          TrustKeyMaterial{Type: KeyMaterialTypeJWK},
			wantContain: "JWK is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.km.Validate()
			if err == nil {
				t.Errorf("Validate() error = nil, want error containing %q", tt.wantContain)
				return
			}
			if !strings.Contains(err.Error(), tt.wantContain) {
				t.Errorf("Validate() error = %v, want error containing %q", err, tt.wantContain)
			}
		})
	}
}

// ============================================================================
// TrustResultPayload Validation Tests
// ============================================================================

func TestTrustResultPayload_Validate_Valid(t *testing.T) {
	tests := []struct {
		name    string
		payload TrustResultPayload
	}{
		{
			name:    "empty payload (fail-closed default)",
			payload: TrustResultPayload{},
		},
		{
			name: "trusted with name and logo",
			payload: TrustResultPayload{
				Trusted:   true,
				Name:      "Trusted Issuer",
				Logo:      "https://example.com/logo.png",
				Framework: "etsi_tsl",
				Reason:    "Matched trust anchor",
			},
		},
		{
			name: "logo with data URI",
			payload: TrustResultPayload{
				Trusted: true,
				Name:    "Issuer",
				Logo:    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
			},
		},
		{
			name: "untrusted with reason",
			payload: TrustResultPayload{
				Trusted: false,
				Reason:  "Not in trust list",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.payload.Validate(); err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
			}
			if !tt.payload.IsValidated() {
				t.Error("IsValidated() = false after successful Validate()")
			}
		})
	}
}

func TestTrustResultPayload_Validate_Invalid(t *testing.T) {
	longString := strings.Repeat("a", 300)
	veryLongURL := "https://example.com/" + strings.Repeat("x", 3000)

	tests := []struct {
		name        string
		payload     TrustResultPayload
		wantContain string
	}{
		{
			name: "name too long",
			payload: TrustResultPayload{
				Trusted: true,
				Name:    longString,
			},
			wantContain: "Name exceeds maximum length",
		},
		{
			name: "logo URL too long",
			payload: TrustResultPayload{
				Trusted: true,
				Logo:    veryLongURL,
			},
			wantContain: "Logo URL exceeds maximum length",
		},
		{
			name: "logo with javascript URL (XSS attempt)",
			payload: TrustResultPayload{
				Trusted: true,
				Logo:    "javascript:alert('xss')",
			},
			wantContain: "Logo must be an HTTP(S) URL",
		},
		{
			name: "reason too long",
			payload: TrustResultPayload{
				Trusted: false,
				Reason:  strings.Repeat("r", 2000),
			},
			wantContain: "Reason exceeds maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.payload.Validate()
			if err == nil {
				t.Errorf("Validate() error = nil, want error containing %q", tt.wantContain)
				return
			}
			if !strings.Contains(err.Error(), tt.wantContain) {
				t.Errorf("Validate() error = %v, want error containing %q", err, tt.wantContain)
			}
			if tt.payload.IsValidated() {
				t.Error("IsValidated() = true after failed Validate()")
			}
		})
	}
}

func TestTrustResultPayload_IsValidated_BeforeValidate(t *testing.T) {
	payload := TrustResultPayload{
		Trusted: true,
		Name:    "Test",
	}
	if payload.IsValidated() {
		t.Error("IsValidated() = true before Validate() called")
	}
}

// ============================================================================
// Type Constants Tests
// ============================================================================

func TestSubjectTypeConstants(t *testing.T) {
	if SubjectTypeCredentialIssuer != "credential_issuer" {
		t.Errorf("SubjectTypeCredentialIssuer = %q, want 'credential_issuer'", SubjectTypeCredentialIssuer)
	}
	if SubjectTypeCredentialVerifier != "credential_verifier" {
		t.Errorf("SubjectTypeCredentialVerifier = %q, want 'credential_verifier'", SubjectTypeCredentialVerifier)
	}
}

func TestKeyMaterialTypeConstants(t *testing.T) {
	if KeyMaterialTypeX5C != "x5c" {
		t.Errorf("KeyMaterialTypeX5C = %q, want 'x5c'", KeyMaterialTypeX5C)
	}
	if KeyMaterialTypeJWK != "jwk" {
		t.Errorf("KeyMaterialTypeJWK = %q, want 'jwk'", KeyMaterialTypeJWK)
	}
}

// ============================================================================
// isValidLogoURL Tests
// ============================================================================

func TestIsValidLogoURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.com/logo.png", true},
		{"HTTPS://EXAMPLE.COM/LOGO.PNG", true},
		{"data:image/png;base64,abc123", true},
		{"data:image/svg+xml;base64,abc123", true},
		{"http://example.com/logo.png", true},
		{"HTTP://EXAMPLE.COM/LOGO.PNG", true},
		{"javascript:alert(1)", false},
		{"ftp://example.com/logo.png", false},
		{"", false},
		{"short", false},
		{"file:///etc/passwd", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := isValidLogoURL(tt.url); got != tt.want {
				t.Errorf("isValidLogoURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Match Request/Response Message Tests
// ============================================================================

func TestMatchRequestMessageJSON(t *testing.T) {
	msg := MatchRequestMessage{
		Message: Message{
			Type:      TypeMatchRequest,
			FlowID:    "flow-123",
			MessageID: "msg-456",
			Timestamp: "2024-01-01T00:00:00Z",
		},
		PresentationDefinition: &PresentationDefinition{
			ID:   "pd-1",
			Name: "Test Presentation",
			InputDescriptors: []InputDescriptor{
				{
					ID:      "id-1",
					Name:    "Identity",
					Purpose: "Verify identity",
				},
			},
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Verify key fields are present
	if !strings.Contains(string(data), `"type":"match_request"`) {
		t.Errorf("Missing type field in JSON: %s", data)
	}
	if !strings.Contains(string(data), `"flow_id":"flow-123"`) {
		t.Errorf("Missing flow_id field in JSON: %s", data)
	}
	if !strings.Contains(string(data), `"message_id":"msg-456"`) {
		t.Errorf("Missing message_id field in JSON: %s", data)
	}
	if !strings.Contains(string(data), `"presentation_definition"`) {
		t.Errorf("Missing presentation_definition field in JSON: %s", data)
	}
}

func TestMatchResponseMessageJSON(t *testing.T) {
	msg := MatchResponseMessage{
		Message: Message{
			Type:      TypeMatchResponse,
			FlowID:    "flow-123",
			MessageID: "msg-456",
			Timestamp: "2024-01-01T00:00:00Z",
		},
		Matches: []CredentialMatch{
			{
				InputDescriptorID: "id-1",
				CredentialID:      "cred-abc",
				Format:            "vc+sd-jwt",
				VCT:               "urn:eu.europa.ec.eudi:pid:1",
				AvailableClaims:   []string{"given_name", "family_name", "birth_date"},
			},
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed MatchResponseMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.Type != TypeMatchResponse {
		t.Errorf("Type = %q, want %q", parsed.Type, TypeMatchResponse)
	}
	if parsed.FlowID != "flow-123" {
		t.Errorf("FlowID = %q, want 'flow-123'", parsed.FlowID)
	}
	if len(parsed.Matches) != 1 {
		t.Fatalf("Matches len = %d, want 1", len(parsed.Matches))
	}
	if parsed.Matches[0].CredentialID != "cred-abc" {
		t.Errorf("CredentialID = %q, want 'cred-abc'", parsed.Matches[0].CredentialID)
	}
	if parsed.Matches[0].VCT != "urn:eu.europa.ec.eudi:pid:1" {
		t.Errorf("VCT = %q, want 'urn:eu.europa.ec.eudi:pid:1'", parsed.Matches[0].VCT)
	}
}

func TestMatchResponseMessageNoMatch(t *testing.T) {
	msg := MatchResponseMessage{
		Message: Message{
			Type:      TypeMatchResponse,
			FlowID:    "flow-123",
			MessageID: "msg-456",
		},
		Matches:       []CredentialMatch{},
		NoMatchReason: "No credentials match descriptors: id-1, id-2",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed MatchResponseMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if len(parsed.Matches) != 0 {
		t.Errorf("Matches len = %d, want 0", len(parsed.Matches))
	}
	if parsed.NoMatchReason != "No credentials match descriptors: id-1, id-2" {
		t.Errorf("NoMatchReason = %q, want 'No credentials match descriptors: id-1, id-2'", parsed.NoMatchReason)
	}
}

func TestMatchResponseMessageError(t *testing.T) {
	msg := MatchResponseMessage{
		Message: Message{
			Type:      TypeMatchResponse,
			FlowID:    "flow-123",
			MessageID: "msg-456",
		},
		Matches: []CredentialMatch{}, // Use empty slice, not nil, to marshal as [] per protocol spec
		Error:   "Credential matching failed: keystore unavailable",
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed MatchResponseMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.Error != "Credential matching failed: keystore unavailable" {
		t.Errorf("Error = %q, want 'Credential matching failed: keystore unavailable'", parsed.Error)
	}
}

func TestMatchMessageTypeConstants(t *testing.T) {
	if TypeMatchRequest != "match_request" {
		t.Errorf("TypeMatchRequest = %q, want 'match_request'", TypeMatchRequest)
	}
	if TypeMatchResponse != "match_response" {
		t.Errorf("TypeMatchResponse = %q, want 'match_response'", TypeMatchResponse)
	}
}

func TestMatchErrorCodeConstants(t *testing.T) {
	if ErrCodeMatchTimeout != "MATCH_TIMEOUT" {
		t.Errorf("ErrCodeMatchTimeout = %q, want 'MATCH_TIMEOUT'", ErrCodeMatchTimeout)
	}
	if ErrCodeMatchError != "MATCH_ERROR" {
		t.Errorf("ErrCodeMatchError = %q, want 'MATCH_ERROR'", ErrCodeMatchError)
	}
}

func TestMatchErrorCodeUserFacingMessage(t *testing.T) {
	tests := []struct {
		code ErrorCode
		want string
	}{
		{ErrCodeMatchTimeout, "Credential matching timed out"},
		{ErrCodeMatchError, "Credential matching failed"},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			got := tt.code.UserFacingMessage()
			if got != tt.want {
				t.Errorf("UserFacingMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}
