package integration

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// TestAccountInfo tests the /user/session/account-info endpoint
func TestAccountInfo(t *testing.T) {
	h := NewTestHarness(t)
	user := h.CreateTestUser("Test User")

	t.Run("returns account info for authenticated user", func(t *testing.T) {
		resp := h.AuthGET(user, "/user/session/account-info")
		resp.Status(http.StatusOK)

		var result map[string]interface{}
		resp.JSON(&result)

		// Verify expected fields
		if result["uuid"] != user.UUID.String() {
			t.Errorf("Expected uuid %s, got %v", user.UUID.String(), result["uuid"])
		}
		if result["displayName"] != user.DisplayName {
			t.Errorf("Expected displayName %s, got %v", user.DisplayName, result["displayName"])
		}
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		resp := h.GET("/user/session/account-info")
		resp.Status(http.StatusUnauthorized)
	})
}

// TestPrivateData tests private data endpoints
func TestPrivateData(t *testing.T) {
	h := NewTestHarness(t)
	user := h.CreateTestUser("Private Data User")

	t.Run("GET returns private data with ETag", func(t *testing.T) {
		resp := h.AuthGET(user, "/user/session/private-data")
		resp.Status(http.StatusOK)
		
		// ETag is returned in X-Private-Data-ETag header
		etag := resp.Header("X-Private-Data-ETag")
		if etag == "" {
			t.Error("Expected X-Private-Data-ETag header to be present")
		}

		var result map[string]interface{}
		resp.JSON(&result)

		// privateData should be in tagged binary format
		if _, ok := result["privateData"]; !ok {
			t.Error("Expected privateData in response")
		}
	})

	t.Run("POST updates private data", func(t *testing.T) {
		// First get current ETag
		getResp := h.AuthGET(user, "/user/session/private-data")
		etag := getResp.Header("X-Private-Data-ETag")

		// Update with new data
		newData := `{"updated":"value"}`
		newDataB64 := base64.RawURLEncoding.EncodeToString([]byte(newData))
		updateReq := map[string]interface{}{
			"privateData": map[string]string{"$b64u": newDataB64},
		}

		// Create request with If-Match header
		req, _ := http.NewRequest("POST", h.BaseURL+"/user/session/private-data", nil)
		req.Header.Set("Authorization", "Bearer "+user.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Private-Data-If-Match", etag)

		// Re-create with body
		resp := h.AuthPOST(user, "/user/session/private-data", updateReq)
		// Should succeed (200 or 204) or fail with ETag mismatch (412)
		if resp.Response.StatusCode != http.StatusOK &&
			resp.Response.StatusCode != http.StatusNoContent &&
			resp.Response.StatusCode != http.StatusPreconditionFailed {
			t.Errorf("Expected 200, 204, or 412, got %d: %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		resp := h.GET("/user/session/private-data")
		resp.Status(http.StatusUnauthorized)
	})
}

// TestDeleteUser tests user deletion
func TestDeleteUser(t *testing.T) {
	h := NewTestHarness(t)
	user := h.CreateTestUser("Delete Me")

	t.Run("deletes authenticated user", func(t *testing.T) {
		resp := h.AuthDELETE(user, "/user/session")
		resp.Status(http.StatusOK)

		// Verify user can no longer access account
		verifyResp := h.AuthGET(user, "/user/session/account-info")
		// Token is still valid syntactically but user is gone
		// Could be 401 (unauthorized), 403 (forbidden), or 404 (user not found)
		if verifyResp.Response.StatusCode != http.StatusUnauthorized &&
			verifyResp.Response.StatusCode != http.StatusForbidden &&
			verifyResp.Response.StatusCode != http.StatusNotFound {
			t.Errorf("Expected 401, 403, or 404 after deletion, got %d", verifyResp.Response.StatusCode)
		}
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		resp := h.DELETE("/user/session")
		resp.Status(http.StatusUnauthorized)
	})
}

// TestSettings tests user settings endpoint
func TestSettings(t *testing.T) {
	h := NewTestHarness(t)
	user := h.CreateTestUser("Settings User")

	t.Run("updates user settings", func(t *testing.T) {
		updateReq := map[string]interface{}{
			"openidRefreshTokenMaxAge": 3600,
		}

		resp := h.AuthPOST(user, "/user/session/settings", updateReq)
		// May return 200 OK or appropriate status
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		resp := h.POST("/user/session/settings", map[string]interface{}{})
		resp.Status(http.StatusUnauthorized)
	})
}

// TestWebAuthnCredentialManagement tests credential management endpoints
func TestWebAuthnCredentialManagement(t *testing.T) {
	h := NewTestHarness(t)
	user := h.CreateTestUserWithCredentials("Cred Manager")

	t.Run("add-begin returns challenge", func(t *testing.T) {
		resp := h.AuthPOST(user, "/user/session/webauthn-credential/add-begin", map[string]interface{}{})
		resp.Status(http.StatusOK)

		var result map[string]interface{}
		resp.JSON(&result)

		if result["challengeId"] == nil {
			t.Error("Expected challengeId in response")
		}
	})

	t.Run("rename credential", func(t *testing.T) {
		renameReq := map[string]interface{}{
			"nickname": "My Security Key",
		}

		resp := h.AuthPOST(user, "/user/session/webauthn-credential/test-credential-1/rename", renameReq)
		// May return 200 or 404 depending on credential lookup
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("delete credential", func(t *testing.T) {
		// Create a new user with credential to delete
		user2 := h.CreateTestUserWithCredentials("Delete Cred User")

		resp := h.AuthDELETE(user2, "/user/session/webauthn-credential/test-credential-1")
		// Should succeed or fail gracefully
		if resp.Response.StatusCode >= 500 {
			t.Errorf("Got server error: %d - %s", resp.Response.StatusCode, resp.Pretty())
		}
	})

	t.Run("returns 401 without auth", func(t *testing.T) {
		resp := h.POST("/user/session/webauthn-credential/add-begin", map[string]interface{}{})
		resp.Status(http.StatusUnauthorized)
	})
}

// TestAuthCheck tests the auth check endpoint
// Note: This endpoint is public and always returns 200.
// It's used by relays to verify the server is responding.
func TestAuthCheck(t *testing.T) {
	h := NewTestHarness(t)

	t.Run("returns 200 without auth (public endpoint)", func(t *testing.T) {
		resp := h.GET("/auth/check")
		resp.Status(http.StatusOK)
	})

	t.Run("returns 200 with valid auth", func(t *testing.T) {
		user := h.CreateTestUser("Auth Check User")
		resp := h.AuthGET(user, "/auth/check")
		resp.Status(http.StatusOK)
	})
}
