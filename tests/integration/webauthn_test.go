package integration

import (
	"encoding/json"
	"net/http"
	"testing"
)

// WebAuthn registration begin response structure (matches frontend expectations)
type BeginRegistrationResponse struct {
	ChallengeID   string                `json:"challengeId"`
	CreateOptions CreateOptionsResponse `json:"createOptions"`
}

type CreateOptionsResponse struct {
	PublicKey PublicKeyCredentialCreationOptions `json:"publicKey"`
}

type PublicKeyCredentialCreationOptions struct {
	RP                     RPEntity                       `json:"rp"`
	User                   UserEntity                     `json:"user"`
	Challenge              interface{}                    `json:"challenge"` // Tagged binary: {$b64u: "..."}
	PubKeyCredParams       []CredentialParameters         `json:"pubKeyCredParams"`
	ExcludeCredentials     []interface{}                  `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelectionCriteria `json:"authenticatorSelection"`
	Attestation            string                         `json:"attestation"`
	Extensions             interface{}                    `json:"extensions"`
}

type RPEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type UserEntity struct {
	ID          interface{} `json:"id"` // Tagged binary
	Name        string      `json:"name"`
	DisplayName string      `json:"displayName"`
}

type CredentialParameters struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}

type AuthenticatorSelectionCriteria struct {
	RequireResidentKey bool   `json:"requireResidentKey"`
	ResidentKey        string `json:"residentKey"`
	UserVerification   string `json:"userVerification"`
}

func TestWebAuthnRegistrationBegin(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.POST("/user/register-webauthn-begin", map[string]interface{}{})
	resp.Status(http.StatusOK)

	var result BeginRegistrationResponse
	resp.JSON(&result)

	// Verify challengeId is present
	if result.ChallengeID == "" {
		t.Error("Expected challengeId to be present")
	}

	// Verify createOptions structure
	if result.CreateOptions.PublicKey.RP.ID != "localhost" {
		t.Errorf("Expected RP ID 'localhost', got %q", result.CreateOptions.PublicKey.RP.ID)
	}

	if result.CreateOptions.PublicKey.RP.Name != "Test Wallet" {
		t.Errorf("Expected RP Name 'Test Wallet', got %q", result.CreateOptions.PublicKey.RP.Name)
	}

	// Verify challenge is in tagged binary format {$b64u: "..."}
	challengeMap, ok := result.CreateOptions.PublicKey.Challenge.(map[string]interface{})
	if !ok {
		t.Errorf("Expected challenge to be tagged binary object, got %T", result.CreateOptions.PublicKey.Challenge)
	} else {
		if _, hasB64u := challengeMap["$b64u"]; !hasB64u {
			t.Error("Expected challenge to have $b64u key for tagged binary format")
		}
	}

	// Verify user.id is in tagged binary format
	userIDMap, ok := result.CreateOptions.PublicKey.User.ID.(map[string]interface{})
	if !ok {
		t.Errorf("Expected user.id to be tagged binary object, got %T", result.CreateOptions.PublicKey.User.ID)
	} else {
		if _, hasB64u := userIDMap["$b64u"]; !hasB64u {
			t.Error("Expected user.id to have $b64u key for tagged binary format")
		}
	}

	// Verify pubKeyCredParams contains expected algorithms
	if len(result.CreateOptions.PublicKey.PubKeyCredParams) == 0 {
		t.Error("Expected pubKeyCredParams to be non-empty")
	}

	foundES256 := false
	for _, param := range result.CreateOptions.PublicKey.PubKeyCredParams {
		if param.Type == "public-key" && param.Alg == -7 {
			foundES256 = true
		}
	}
	if !foundES256 {
		t.Error("Expected pubKeyCredParams to include ES256 (alg: -7)")
	}

	// Verify authenticator selection
	if result.CreateOptions.PublicKey.AuthenticatorSelection.ResidentKey != "required" {
		t.Errorf("Expected residentKey 'required', got %q", result.CreateOptions.PublicKey.AuthenticatorSelection.ResidentKey)
	}

	// Debug output on failure
	if t.Failed() {
		resp.Debug()
	}
}

func TestWebAuthnRegistrationBeginWithDisplayName(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.POST("/user/register-webauthn-begin", map[string]interface{}{
		"display_name": "Test User",
	})
	resp.Status(http.StatusOK)

	var result BeginRegistrationResponse
	resp.JSON(&result)

	// Since display_name is provided, we should see it in the response
	// Note: The actual user.name and user.displayName are set during finish
	// but the user entity should be present in begin response
	if result.CreateOptions.PublicKey.User.DisplayName == "" {
		t.Error("Expected user.displayName to be set")
	}
}

// TestWebAuthnResponseFormat validates the exact JSON structure matches frontend expectations
func TestWebAuthnResponseFormat(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.POST("/user/register-webauthn-begin", map[string]interface{}{})
	resp.Status(http.StatusOK)

	// Parse raw JSON to validate structure
	var raw map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &raw); err != nil {
		t.Fatalf("Failed to parse response as JSON: %v", err)
	}

	// Check top-level keys
	if _, ok := raw["challengeId"]; !ok {
		t.Error("Missing top-level 'challengeId' key")
	}
	if _, ok := raw["createOptions"]; !ok {
		t.Error("Missing top-level 'createOptions' key")
	}

	// Check createOptions.publicKey exists (single level, not double-wrapped)
	createOptions, ok := raw["createOptions"].(map[string]interface{})
	if !ok {
		t.Fatal("createOptions is not an object")
	}

	publicKey, ok := createOptions["publicKey"].(map[string]interface{})
	if !ok {
		t.Fatal("createOptions.publicKey is not an object")
	}

	// Ensure there's no double-wrapping (publicKey.publicKey should not exist)
	if _, hasNested := publicKey["publicKey"]; hasNested {
		t.Error("Detected double-wrapped publicKey - this indicates the bug we previously fixed has regressed")
	}

	// Verify required fields in publicKey
	requiredFields := []string{"rp", "user", "challenge", "pubKeyCredParams", "authenticatorSelection", "attestation"}
	for _, field := range requiredFields {
		if _, ok := publicKey[field]; !ok {
			t.Errorf("Missing required field 'publicKey.%s'", field)
		}
	}
}

// BeginLoginResponse for login flow
type BeginLoginResponse struct {
	ChallengeID string             `json:"challengeId"`
	GetOptions  GetOptionsResponse `json:"getOptions"`
}

type GetOptionsResponse struct {
	PublicKey PublicKeyCredentialRequestOptions `json:"publicKey"`
}

type PublicKeyCredentialRequestOptions struct {
	Challenge        interface{}   `json:"challenge"` // Tagged binary
	Timeout          uint64        `json:"timeout"`
	RPID             string        `json:"rpId"`
	AllowCredentials []interface{} `json:"allowCredentials"`
	UserVerification string        `json:"userVerification"`
}

func TestWebAuthnLoginBegin(t *testing.T) {
	h := NewTestHarness(t)

	resp := h.POST("/user/login-webauthn-begin", map[string]interface{}{})
	resp.Status(http.StatusOK)

	var result BeginLoginResponse
	resp.JSON(&result)

	// Verify challengeId is present
	if result.ChallengeID == "" {
		t.Error("Expected challengeId to be present")
	}

	// Verify getOptions.publicKey structure
	if result.GetOptions.PublicKey.RPID != "localhost" {
		t.Errorf("Expected rpId 'localhost', got %q", result.GetOptions.PublicKey.RPID)
	}

	// Verify challenge is in tagged binary format
	challengeMap, ok := result.GetOptions.PublicKey.Challenge.(map[string]interface{})
	if !ok {
		t.Errorf("Expected challenge to be tagged binary object, got %T", result.GetOptions.PublicKey.Challenge)
	} else {
		if _, hasB64u := challengeMap["$b64u"]; !hasB64u {
			t.Error("Expected challenge to have $b64u key for tagged binary format")
		}
	}

	if t.Failed() {
		resp.Debug()
	}
}
