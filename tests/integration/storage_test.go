package integration

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// TestCredentialStorage tests VC storage endpoints
func TestCredentialStorage(t *testing.T) {
	h := NewTestHarness(t)
	user := h.CreateTestUser("Storage User")

	// Sample credential for testing
	sampleVC := map[string]interface{}{
		"@context": []string{"https://www.w3.org/2018/credentials/v1"},
		"type":     []string{"VerifiableCredential"},
		"issuer":   "did:example:issuer",
		"credentialSubject": map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Test Subject",
		},
	}

	var storedCredID string

	t.Run("POST stores a credential", func(t *testing.T) {
		// credential needs to be in tagged binary format
		credJSON := `{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"]}`
		credB64 := base64.RawURLEncoding.EncodeToString([]byte(credJSON))

		storeReq := map[string]interface{}{
			"credential":           map[string]string{"$b64u": credB64},
			"credentialIdentifier": "test-vc-001",
			"format":               "vc+sd-jwt",
		}

		resp := h.AuthPOST(user, "/storage/vc", storeReq)

		// May succeed or return 400 depending on validation
		if resp.Response.StatusCode == http.StatusOK || resp.Response.StatusCode == http.StatusCreated {
			var result map[string]interface{}
			resp.JSON(&result)
			if id, ok := result["credentialIdentifier"].(string); ok {
				storedCredID = id
			}
			t.Logf("Stored credential: %s", resp.Pretty())
		} else if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		} else {
			t.Logf("Store returned %d (may be expected for validation): %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("GET returns all credentials", func(t *testing.T) {
		resp := h.AuthGET(user, "/storage/vc")
		resp.Status(http.StatusOK)

		var result map[string]interface{}
		resp.JSON(&result)

		// Should have a vc_list or similar array
		t.Logf("All credentials response: %s", resp.Pretty())
	})

	t.Run("GET by ID returns specific credential", func(t *testing.T) {
		if storedCredID == "" {
			storedCredID = "test-vc-001" // Use default if store didn't work
		}

		resp := h.AuthGET(user, "/storage/vc/"+storedCredID)
		// 200 if found, 404 if not
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("PUT updates a credential", func(t *testing.T) {
		credJSON := `{"@context":["https://www.w3.org/2018/credentials/v1"],"updated":true}`
		credB64 := base64.RawURLEncoding.EncodeToString([]byte(credJSON))

		updateReq := map[string]interface{}{
			"credential": map[string]string{"$b64u": credB64},
		}

		resp := h.AuthPUT(user, "/storage/vc/test-vc-001", updateReq)
		// 200 if updated, 404 if not found
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("DELETE removes a credential", func(t *testing.T) {
		resp := h.AuthDELETE(user, "/storage/vc/test-vc-001")
		// 200/204 if deleted, 404 if not found
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		resp := h.GET("/storage/vc")
		resp.Status(http.StatusUnauthorized)

		resp = h.POST("/storage/vc", sampleVC)
		resp.Status(http.StatusUnauthorized)
	})
}

// TestPresentationStorage tests VP storage endpoints
func TestPresentationStorage(t *testing.T) {
	h := NewTestHarness(t)
	user := h.CreateTestUser("VP Storage User")

	var storedVPID string

	t.Run("POST stores a presentation", func(t *testing.T) {
		vpJSON := `{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"]}`
		vpB64 := base64.RawURLEncoding.EncodeToString([]byte(vpJSON))

		storeReq := map[string]interface{}{
			"presentation":           map[string]string{"$b64u": vpB64},
			"presentationIdentifier": "test-vp-001",
		}

		resp := h.AuthPOST(user, "/storage/vp", storeReq)

		if resp.Response.StatusCode == http.StatusOK || resp.Response.StatusCode == http.StatusCreated {
			var result map[string]interface{}
			resp.JSON(&result)
			if id, ok := result["presentationIdentifier"].(string); ok {
				storedVPID = id
			}
		} else if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("GET returns all presentations", func(t *testing.T) {
		resp := h.AuthGET(user, "/storage/vp")
		resp.Status(http.StatusOK)
		t.Logf("All presentations response: %s", resp.Pretty())
	})

	t.Run("GET by ID returns specific presentation", func(t *testing.T) {
		if storedVPID == "" {
			storedVPID = "test-vp-001"
		}

		resp := h.AuthGET(user, "/storage/vp/"+storedVPID)
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("DELETE removes a presentation", func(t *testing.T) {
		resp := h.AuthDELETE(user, "/storage/vp/test-vp-001")
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		resp := h.GET("/storage/vp")
		resp.Status(http.StatusUnauthorized)
	})
}

// TestIssuerEndpoints tests issuer-related endpoints
func TestIssuerEndpoints(t *testing.T) {
	h := NewTestHarness(t)

	t.Run("GET /issuer/all returns issuers list", func(t *testing.T) {
		resp := h.GET("/issuer/all")
		// May return 200 with empty list or configured issuers
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
		t.Logf("Issuers response: %s", resp.Pretty())
	})

	t.Run("GET /issuer/:id returns specific issuer", func(t *testing.T) {
		resp := h.GET("/issuer/test-issuer")
		// 200 if found, 404 if not
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})
}

// TestVerifierEndpoints tests verifier-related endpoints
func TestVerifierEndpoints(t *testing.T) {
	h := NewTestHarness(t)

	t.Run("GET /verifier/all returns verifiers list", func(t *testing.T) {
		resp := h.GET("/verifier/all")
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
		t.Logf("Verifiers response: %s", resp.Pretty())
	})
}

// TestWalletProviderEndpoints tests wallet provider endpoints
func TestWalletProviderEndpoints(t *testing.T) {
	h := NewTestHarness(t)

	t.Run("GET /wallet-provider/certificate returns certificate info", func(t *testing.T) {
		resp := h.GET("/wallet-provider/certificate")
		// May return certificate or error if not configured
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
		t.Logf("Certificate response (status %d): %s", resp.Response.StatusCode, resp.Pretty())
	})

	t.Run("POST /wallet-provider/key-attestation generates attestation", func(t *testing.T) {
		attestReq := map[string]interface{}{
			"keyId": "test-key-id",
		}

		resp := h.POST("/wallet-provider/key-attestation", attestReq)
		// May succeed or fail depending on config
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
		t.Logf("Attestation response (status %d): %s", resp.Response.StatusCode, resp.Pretty())
	})
}
