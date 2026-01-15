package integration

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// TestWebAuthnRequestResponseFormats validates that the request/response formats
// are compatible with what wallet-frontend expects.
// Note: Full WebAuthn flow testing requires browser automation or a proper
// WebAuthn test harness like go-webauthn/webauthn/protocol/attestation test utilities.
func TestWebAuthnRequestResponseFormats(t *testing.T) {
	h := NewTestHarness(t)

	// Begin registration to get a valid challenge
	beginResp := h.POST("/user/register-webauthn-begin", map[string]interface{}{})
	beginResp.Status(http.StatusOK)

	var beginResult BeginRegistrationResponse
	beginResp.JSON(&beginResult)

	// Validate response structure matches wallet-frontend expectations
	t.Run("registration response has correct structure", func(t *testing.T) {
		if beginResult.ChallengeID == "" {
			t.Error("Missing challengeId")
		}

		pk := beginResult.CreateOptions.PublicKey
		if pk.RP.Name == "" {
			t.Error("Missing rp.name")
		}
		if pk.User.Name == "" {
			t.Error("Missing user.name")
		}
		// Note: displayName can be empty string for anonymous registration

		// Check challenge is in tagged binary format
		challengeMap, ok := pk.Challenge.(map[string]interface{})
		if !ok {
			t.Error("Challenge should be an object with $b64u")
		} else if _, hasB64u := challengeMap["$b64u"]; !hasB64u {
			t.Error("Challenge should have $b64u key")
		}

		// Check user.id is in tagged binary format
		userIDMap, ok := pk.User.ID.(map[string]interface{})
		if !ok {
			t.Error("User.id should be an object with $b64u")
		} else if _, hasB64u := userIDMap["$b64u"]; !hasB64u {
			t.Error("User.id should have $b64u key")
		}
	})

	// Test that finish registration request format is accepted
	// (even though the credential data is invalid, the format should parse)
	t.Run("finish request format is accepted", func(t *testing.T) {
		// Create a properly formatted finish request
		// privateData must be in tagged binary format
		privateDataJSON := `{"mainKey":{"unwrappedKeyAlgorithm":{"name":"AES-GCM","length":256}}}`
		privateDataB64 := base64.RawURLEncoding.EncodeToString([]byte(privateDataJSON))

		finishReq := map[string]interface{}{
			"challengeId": beginResult.ChallengeID,
			"displayName": "Test User",
			"privateData": map[string]string{"$b64u": privateDataB64},
			"credential": map[string]interface{}{
				"type":  "public-key",
				"id":    "test-credential-id",
				"rawId": map[string]string{"$b64u": base64.RawURLEncoding.EncodeToString([]byte("test-credential-id"))},
				"response": map[string]interface{}{
					"clientDataJSON":    map[string]string{"$b64u": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"},
					"attestationObject": map[string]string{"$b64u": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YQ"},
					"transports":        []string{"internal"},
				},
				"authenticatorAttachment": "platform",
				"clientExtensionResults":  map[string]interface{}{},
			},
		}

		finishResp := h.POST("/user/register-webauthn-finish", finishReq)

		// We should NOT get:
		// - 500 (internal server error) - indicates format parsing failed
		// - 404/405 - indicates route not found
		// 400 is expected for invalid credential data
		switch status := finishResp.Response.StatusCode; status {
		case http.StatusInternalServerError:
			t.Errorf("Got 500 Internal Server Error - request format may be wrong: %s", finishResp.Pretty())
		case http.StatusNotFound, http.StatusMethodNotAllowed:
			t.Errorf("Got %d - route issue: %s", status, finishResp.Pretty())
		default:
			t.Logf("Finish request accepted with status %d (expected 400 for invalid credential)", status)
		}
	})
}

// TestWebAuthnLoginRequestFormat validates login request format
func TestWebAuthnLoginRequestFormat(t *testing.T) {
	h := NewTestHarness(t)

	// Begin login
	beginResp := h.POST("/user/login-webauthn-begin", map[string]interface{}{})
	beginResp.Status(http.StatusOK)

	var beginResult map[string]interface{}
	beginResp.JSON(&beginResult)

	challengeID, ok := beginResult["challengeId"].(string)
	if !ok || challengeID == "" {
		t.Fatal("Missing challengeId")
	}

	// Validate response structure
	t.Run("login response has correct structure", func(t *testing.T) {
		// Login uses getOptions (not requestOptions)
		getOptions, ok := beginResult["getOptions"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing getOptions")
		}

		publicKey, ok := getOptions["publicKey"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing publicKey")
		}

		// Check challenge is in tagged binary format
		challengeMap, ok := publicKey["challenge"].(map[string]interface{})
		if !ok {
			t.Error("Challenge should be an object with $b64u")
		} else if _, hasB64u := challengeMap["$b64u"]; !hasB64u {
			t.Error("Challenge should have $b64u key")
		}
	})

	// Test that finish login request format is accepted
	t.Run("finish login request format is accepted", func(t *testing.T) {
		finishReq := map[string]interface{}{
			"challengeId": challengeID,
			"credential": map[string]interface{}{
				"type":  "public-key",
				"id":    "test-credential-id",
				"rawId": map[string]string{"$b64u": base64.RawURLEncoding.EncodeToString([]byte("test-credential-id"))},
				"response": map[string]interface{}{
					"clientDataJSON":    map[string]string{"$b64u": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0"},
					"authenticatorData": map[string]string{"$b64u": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA"},
					"signature":         map[string]string{"$b64u": "MEUCIQDf"},
					"userHandle":        map[string]string{"$b64u": "dGVzdC11c2VyLWlk"},
				},
				"authenticatorAttachment": "platform",
				"clientExtensionResults":  map[string]interface{}{},
			},
		}

		finishResp := h.POST("/user/login-webauthn-finish", finishReq)

		switch status := finishResp.Response.StatusCode; status {
		case http.StatusInternalServerError:
			t.Errorf("Got 500 Internal Server Error - request format may be wrong: %s", finishResp.Pretty())
		case http.StatusMethodNotAllowed:
			t.Errorf("Got %d - route issue: %s", status, finishResp.Pretty())
		default:
			// 400, 401, 404 are all valid responses when testing request format:
			// - 400 for invalid credential format
			// - 401 for authentication failure
			// - 404 for user not found (test user doesn't exist)
			t.Logf("Finish login request accepted with status %d (expected 400/401/404 for test data)", status)
		}
	})
}

// TestSessionEndpointFormats validates session-related endpoint request formats
func TestSessionEndpointFormats(t *testing.T) {
	h := NewTestHarness(t)

	// Test /user/session/public-info (public endpoint)
	t.Run("public-info accepts tagged binary user ID", func(t *testing.T) {
		userIDB64 := base64.RawURLEncoding.EncodeToString([]byte("test-user-id"))
		req := map[string]interface{}{
			"userId": map[string]string{"$b64u": userIDB64},
		}

		resp := h.POST("/user/session/public-info", req)

		// 404 is expected (user not found), not 400/500
		switch status := resp.Response.StatusCode; status {
		case http.StatusInternalServerError:
			t.Errorf("Got 500 - format may be wrong: %s", resp.Pretty())
		case http.StatusBadRequest:
			t.Errorf("Got 400 - request format rejected: %s", resp.Pretty())
		}
	})

	// Note: Other session endpoints require authentication.
	// Full testing of those would require completing WebAuthn registration first.
}
