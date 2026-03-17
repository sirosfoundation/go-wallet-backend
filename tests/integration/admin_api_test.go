package integration

import (
	"net/http"
	"testing"
)

func TestAdminStatus(t *testing.T) {
	h := NewAdminTestHarness(t)

	resp := h.GET("/admin/status")
	resp.Status(http.StatusOK)

	var body map[string]interface{}
	resp.JSON(&body)

	if body["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %q", body["status"])
	}
	if body["service"] != "wallet-backend-admin" {
		t.Errorf("Expected service 'wallet-backend-admin', got %q", body["service"])
	}
}

func TestAdminAuthRequired(t *testing.T) {
	h := NewAdminTestHarness(t)

	t.Run("no token returns 401", func(t *testing.T) {
		// Make request without token
		req, _ := http.NewRequest(http.MethodGet, h.BaseURL+"/admin/tenants", nil)
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid token returns 401", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, h.BaseURL+"/admin/tenants", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("status endpoint is public", func(t *testing.T) {
		// Status should work without token
		req, _ := http.NewRequest(http.MethodGet, h.BaseURL+"/admin/status", nil)
		resp, err := h.Client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 for status, got %d", resp.StatusCode)
		}
	})

	t.Run("valid token works", func(t *testing.T) {
		// With the harness-provided token
		resp := h.GET("/admin/tenants")
		resp.Status(http.StatusOK)
	})
}

func TestTenantCRUD(t *testing.T) {
	h := NewAdminTestHarness(t)

	t.Run("list tenants includes default", func(t *testing.T) {
		resp := h.GET("/admin/tenants")
		resp.Status(http.StatusOK)

		var body struct {
			Tenants []map[string]interface{} `json:"tenants"`
		}
		resp.JSON(&body)

		// Memory store initializes with default tenant
		if len(body.Tenants) != 1 {
			t.Errorf("Expected 1 tenant (default), got %d", len(body.Tenants))
		}
	})

	t.Run("create tenant", func(t *testing.T) {
		resp := h.POST("/admin/tenants", map[string]interface{}{
			"id":           "test-tenant",
			"name":         "Test Tenant",
			"display_name": "Test Tenant Display",
			"enabled":      true,
		})
		resp.Status(http.StatusCreated)

		var tenant map[string]interface{}
		resp.JSON(&tenant)

		if tenant["id"] != "test-tenant" {
			t.Errorf("Expected id 'test-tenant', got %v", tenant["id"])
		}
		if tenant["name"] != "Test Tenant" {
			t.Errorf("Expected name 'Test Tenant', got %v", tenant["name"])
		}
		if tenant["display_name"] != "Test Tenant Display" {
			t.Errorf("Expected display_name 'Test Tenant Display', got %v", tenant["display_name"])
		}
		if tenant["enabled"] != true {
			t.Errorf("Expected enabled true, got %v", tenant["enabled"])
		}
	})

	t.Run("create tenant with invalid id", func(t *testing.T) {
		resp := h.POST("/admin/tenants", map[string]interface{}{
			"id":   "Invalid ID!",
			"name": "Test",
		})
		resp.Status(http.StatusBadRequest)
	})

	t.Run("create duplicate tenant", func(t *testing.T) {
		resp := h.POST("/admin/tenants", map[string]interface{}{
			"id":   "test-tenant",
			"name": "Duplicate",
		})
		resp.Status(http.StatusConflict)
	})

	t.Run("get tenant", func(t *testing.T) {
		resp := h.GET("/admin/tenants/test-tenant")
		resp.Status(http.StatusOK)

		var tenant map[string]interface{}
		resp.JSON(&tenant)

		if tenant["id"] != "test-tenant" {
			t.Errorf("Expected id 'test-tenant', got %v", tenant["id"])
		}
	})

	t.Run("get non-existent tenant", func(t *testing.T) {
		resp := h.GET("/admin/tenants/non-existent")
		resp.Status(http.StatusNotFound)
	})

	t.Run("list tenants after create", func(t *testing.T) {
		resp := h.GET("/admin/tenants")
		resp.Status(http.StatusOK)

		var body struct {
			Tenants []map[string]interface{} `json:"tenants"`
		}
		resp.JSON(&body)

		// Default tenant + our new tenant
		if len(body.Tenants) != 2 {
			t.Errorf("Expected 2 tenants, got %d", len(body.Tenants))
		}
	})

	t.Run("update tenant", func(t *testing.T) {
		resp := h.PUT("/admin/tenants/test-tenant", map[string]interface{}{
			"id":           "test-tenant",
			"name":         "Updated Tenant",
			"display_name": "Updated Display",
			"enabled":      false,
		})
		resp.Status(http.StatusOK)

		var tenant map[string]interface{}
		resp.JSON(&tenant)

		if tenant["name"] != "Updated Tenant" {
			t.Errorf("Expected name 'Updated Tenant', got %v", tenant["name"])
		}
		if tenant["enabled"] != false {
			t.Errorf("Expected enabled false, got %v", tenant["enabled"])
		}
	})

	t.Run("update non-existent tenant", func(t *testing.T) {
		resp := h.PUT("/admin/tenants/non-existent", map[string]interface{}{
			"id":   "non-existent",
			"name": "Test",
		})
		resp.Status(http.StatusNotFound)
	})

	t.Run("delete tenant", func(t *testing.T) {
		resp := h.DELETE("/admin/tenants/test-tenant")
		resp.Status(http.StatusOK)

		// Verify deletion
		resp = h.GET("/admin/tenants/test-tenant")
		resp.Status(http.StatusNotFound)
	})

	t.Run("delete non-existent tenant", func(t *testing.T) {
		resp := h.DELETE("/admin/tenants/non-existent")
		resp.Status(http.StatusNotFound)
	})

	t.Run("cannot delete default tenant", func(t *testing.T) {
		// Default tenant already exists (created by memory store)
		resp := h.DELETE("/admin/tenants/default")
		resp.Status(http.StatusForbidden)
	})
}

func TestTenantUserManagement(t *testing.T) {
	h := NewAdminTestHarness(t)

	// Create a tenant first
	h.POST("/admin/tenants", map[string]interface{}{
		"id":   "user-test-tenant",
		"name": "User Test Tenant",
	})

	t.Run("list empty users", func(t *testing.T) {
		resp := h.GET("/admin/tenants/user-test-tenant/users")
		resp.Status(http.StatusOK)

		var body struct {
			Users []string `json:"users"`
		}
		resp.JSON(&body)

		if len(body.Users) != 0 {
			t.Errorf("Expected empty users list, got %d", len(body.Users))
		}
	})

	t.Run("add user to tenant", func(t *testing.T) {
		resp := h.POST("/admin/tenants/user-test-tenant/users", map[string]interface{}{
			"user_id": "user-123",
			"role":    "admin",
		})
		resp.Status(http.StatusOK)
	})

	t.Run("add user to non-existent tenant", func(t *testing.T) {
		resp := h.POST("/admin/tenants/non-existent/users", map[string]interface{}{
			"user_id": "user-123",
		})
		resp.Status(http.StatusNotFound)
	})

	t.Run("list users after add", func(t *testing.T) {
		resp := h.GET("/admin/tenants/user-test-tenant/users")
		resp.Status(http.StatusOK)

		var body struct {
			Users []string `json:"users"`
		}
		resp.JSON(&body)

		if len(body.Users) != 1 {
			t.Errorf("Expected 1 user, got %d", len(body.Users))
		}
	})

	t.Run("remove user from tenant", func(t *testing.T) {
		resp := h.DELETE("/admin/tenants/user-test-tenant/users/user-123")
		resp.Status(http.StatusOK)

		// Verify removal
		resp = h.GET("/admin/tenants/user-test-tenant/users")
		resp.Status(http.StatusOK)

		var body struct {
			Users []string `json:"users"`
		}
		resp.JSON(&body)

		if len(body.Users) != 0 {
			t.Errorf("Expected empty users list after removal, got %d", len(body.Users))
		}
	})

	t.Run("list users for non-existent tenant", func(t *testing.T) {
		resp := h.GET("/admin/tenants/non-existent/users")
		resp.Status(http.StatusNotFound)
	})
}

func TestIssuerCRUD(t *testing.T) {
	h := NewAdminTestHarness(t)

	// Create a tenant first
	h.POST("/admin/tenants", map[string]interface{}{
		"id":   "issuer-test-tenant",
		"name": "Issuer Test Tenant",
	})

	t.Run("list empty issuers", func(t *testing.T) {
		resp := h.GET("/admin/tenants/issuer-test-tenant/issuers")
		resp.Status(http.StatusOK)

		var body struct {
			Issuers []map[string]interface{} `json:"issuers"`
		}
		resp.JSON(&body)

		if len(body.Issuers) != 0 {
			t.Errorf("Expected empty issuers list, got %d", len(body.Issuers))
		}
	})

	var createdIssuerID float64

	t.Run("create issuer", func(t *testing.T) {
		resp := h.POST("/admin/tenants/issuer-test-tenant/issuers", map[string]interface{}{
			"credential_issuer_identifier": "https://issuer.example.com",
			"client_id":                    "test-client",
			"visible":                      true,
		})
		resp.Status(http.StatusCreated)

		var issuer map[string]interface{}
		resp.JSON(&issuer)

		createdIssuerID = issuer["id"].(float64)
		if issuer["credential_issuer_identifier"] != "https://issuer.example.com" {
			t.Errorf("Expected credential_issuer_identifier 'https://issuer.example.com', got %v", issuer["credential_issuer_identifier"])
		}
		if issuer["tenant_id"] != "issuer-test-tenant" {
			t.Errorf("Expected tenant_id 'issuer-test-tenant', got %v", issuer["tenant_id"])
		}
	})

	t.Run("create issuer for non-existent tenant", func(t *testing.T) {
		resp := h.POST("/admin/tenants/non-existent/issuers", map[string]interface{}{
			"credential_issuer_identifier": "https://issuer.example.com",
		})
		resp.Status(http.StatusNotFound)
	})

	t.Run("get issuer", func(t *testing.T) {
		resp := h.GET("/admin/tenants/issuer-test-tenant/issuers/1")
		resp.Status(http.StatusOK)

		var issuer map[string]interface{}
		resp.JSON(&issuer)

		if issuer["credential_issuer_identifier"] != "https://issuer.example.com" {
			t.Errorf("Expected credential_issuer_identifier 'https://issuer.example.com', got %v", issuer["credential_issuer_identifier"])
		}
	})

	t.Run("get non-existent issuer", func(t *testing.T) {
		resp := h.GET("/admin/tenants/issuer-test-tenant/issuers/999")
		resp.Status(http.StatusNotFound)
	})

	t.Run("list issuers after create", func(t *testing.T) {
		resp := h.GET("/admin/tenants/issuer-test-tenant/issuers")
		resp.Status(http.StatusOK)

		var body struct {
			Issuers []map[string]interface{} `json:"issuers"`
		}
		resp.JSON(&body)

		if len(body.Issuers) != 1 {
			t.Errorf("Expected 1 issuer, got %d", len(body.Issuers))
		}
	})

	t.Run("update issuer", func(t *testing.T) {
		resp := h.PUT("/admin/tenants/issuer-test-tenant/issuers/1", map[string]interface{}{
			"credential_issuer_identifier": "https://updated-issuer.example.com",
			"client_id":                    "updated-client",
			"visible":                      false,
		})
		resp.Status(http.StatusOK)

		var issuer map[string]interface{}
		resp.JSON(&issuer)

		if issuer["credential_issuer_identifier"] != "https://updated-issuer.example.com" {
			t.Errorf("Expected updated credential_issuer_identifier, got %v", issuer["credential_issuer_identifier"])
		}
		if issuer["visible"] != false {
			t.Errorf("Expected visible false, got %v", issuer["visible"])
		}
	})

	t.Run("update non-existent issuer", func(t *testing.T) {
		resp := h.PUT("/admin/tenants/issuer-test-tenant/issuers/999", map[string]interface{}{
			"credential_issuer_identifier": "https://test.example.com",
		})
		resp.Status(http.StatusNotFound)
	})

	t.Run("delete issuer", func(t *testing.T) {
		resp := h.DELETE("/admin/tenants/issuer-test-tenant/issuers/1")
		resp.Status(http.StatusOK)

		// Verify deletion
		resp = h.GET("/admin/tenants/issuer-test-tenant/issuers/1")
		resp.Status(http.StatusNotFound)
	})

	// Use the captured issuer ID to avoid unused variable warning
	_ = createdIssuerID
}

func TestVerifierCRUD(t *testing.T) {
	h := NewAdminTestHarness(t)

	// Create a tenant first
	h.POST("/admin/tenants", map[string]interface{}{
		"id":   "verifier-test-tenant",
		"name": "Verifier Test Tenant",
	})

	t.Run("list empty verifiers", func(t *testing.T) {
		resp := h.GET("/admin/tenants/verifier-test-tenant/verifiers")
		resp.Status(http.StatusOK)

		var body struct {
			Verifiers []map[string]interface{} `json:"verifiers"`
		}
		resp.JSON(&body)

		if len(body.Verifiers) != 0 {
			t.Errorf("Expected empty verifiers list, got %d", len(body.Verifiers))
		}
	})

	t.Run("create verifier", func(t *testing.T) {
		resp := h.POST("/admin/tenants/verifier-test-tenant/verifiers", map[string]interface{}{
			"name": "Test Verifier",
			"url":  "https://verifier.example.com",
		})
		resp.Status(http.StatusCreated)

		var verifier map[string]interface{}
		resp.JSON(&verifier)

		if verifier["name"] != "Test Verifier" {
			t.Errorf("Expected name 'Test Verifier', got %v", verifier["name"])
		}
		if verifier["tenant_id"] != "verifier-test-tenant" {
			t.Errorf("Expected tenant_id 'verifier-test-tenant', got %v", verifier["tenant_id"])
		}
	})

	t.Run("create verifier for non-existent tenant", func(t *testing.T) {
		resp := h.POST("/admin/tenants/non-existent/verifiers", map[string]interface{}{
			"name": "Test",
			"url":  "https://test.example.com",
		})
		resp.Status(http.StatusNotFound)
	})

	t.Run("get verifier", func(t *testing.T) {
		resp := h.GET("/admin/tenants/verifier-test-tenant/verifiers/1")
		resp.Status(http.StatusOK)

		var verifier map[string]interface{}
		resp.JSON(&verifier)

		if verifier["name"] != "Test Verifier" {
			t.Errorf("Expected name 'Test Verifier', got %v", verifier["name"])
		}
	})

	t.Run("get non-existent verifier", func(t *testing.T) {
		resp := h.GET("/admin/tenants/verifier-test-tenant/verifiers/999")
		resp.Status(http.StatusNotFound)
	})

	t.Run("list verifiers after create", func(t *testing.T) {
		resp := h.GET("/admin/tenants/verifier-test-tenant/verifiers")
		resp.Status(http.StatusOK)

		var body struct {
			Verifiers []map[string]interface{} `json:"verifiers"`
		}
		resp.JSON(&body)

		if len(body.Verifiers) != 1 {
			t.Errorf("Expected 1 verifier, got %d", len(body.Verifiers))
		}
	})

	t.Run("update verifier", func(t *testing.T) {
		resp := h.PUT("/admin/tenants/verifier-test-tenant/verifiers/1", map[string]interface{}{
			"name": "Updated Verifier",
			"url":  "https://updated-verifier.example.com",
		})
		resp.Status(http.StatusOK)

		var verifier map[string]interface{}
		resp.JSON(&verifier)

		if verifier["name"] != "Updated Verifier" {
			t.Errorf("Expected updated name, got %v", verifier["name"])
		}
	})

	t.Run("update non-existent verifier", func(t *testing.T) {
		resp := h.PUT("/admin/tenants/verifier-test-tenant/verifiers/999", map[string]interface{}{
			"name": "Test",
			"url":  "https://test.example.com",
		})
		resp.Status(http.StatusNotFound)
	})

	t.Run("delete verifier", func(t *testing.T) {
		resp := h.DELETE("/admin/tenants/verifier-test-tenant/verifiers/1")
		resp.Status(http.StatusOK)

		// Verify deletion
		resp = h.GET("/admin/tenants/verifier-test-tenant/verifiers/1")
		resp.Status(http.StatusNotFound)
	})
}

func TestTenantValidation(t *testing.T) {
	h := NewAdminTestHarness(t)

	testCases := []struct {
		name     string
		tenantID string
		wantOK   bool
	}{
		{"valid lowercase", "my-tenant", true},
		{"valid with numbers", "tenant-123", true},
		{"valid short", "ab", true},
		{"valid single char", "a", true},
		{"valid starts with number", "1-tenant", true},
		{"valid underscores", "my_tenant", true},
		{"invalid uppercase", "MyTenant", false},
		{"invalid spaces", "my tenant", false},
		{"invalid special chars", "my@tenant", false},
		{"invalid starts with hyphen", "-tenant", false},
		{"invalid colon", "my:tenant", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := h.POST("/admin/tenants", map[string]interface{}{
				"id":   tc.tenantID,
				"name": "Test",
			})

			if tc.wantOK {
				resp.Status(http.StatusCreated)
				// Clean up
				h.DELETE("/admin/tenants/" + tc.tenantID)
			} else {
				resp.Status(http.StatusBadRequest)
			}
		})
	}
}

func TestMultipleTenants(t *testing.T) {
	h := NewAdminTestHarness(t)

	// Create multiple tenants
	tenants := []string{"tenant-a", "tenant-b", "tenant-c"}
	for _, id := range tenants {
		resp := h.POST("/admin/tenants", map[string]interface{}{
			"id":   id,
			"name": "Tenant " + id,
		})
		resp.Status(http.StatusCreated)
	}

	// List all tenants (including default)
	resp := h.GET("/admin/tenants")
	resp.Status(http.StatusOK)

	var body struct {
		Tenants []map[string]interface{} `json:"tenants"`
	}
	resp.JSON(&body)

	// Default tenant + 3 created tenants = 4
	if len(body.Tenants) != len(tenants)+1 {
		t.Errorf("Expected %d tenants, got %d", len(tenants)+1, len(body.Tenants))
	}

	// Each tenant should have its own issuers/verifiers
	for _, id := range tenants {
		// Add issuer to each tenant
		resp := h.POST("/admin/tenants/"+id+"/issuers", map[string]interface{}{
			"credential_issuer_identifier": "https://issuer." + id + ".example.com",
		})
		resp.Status(http.StatusCreated)

		// Verify isolation
		resp = h.GET("/admin/tenants/" + id + "/issuers")
		resp.Status(http.StatusOK)

		var issuers struct {
			Issuers []map[string]interface{} `json:"issuers"`
		}
		resp.JSON(&issuers)

		if len(issuers.Issuers) != 1 {
			t.Errorf("Expected 1 issuer for %s, got %d", id, len(issuers.Issuers))
		}
	}
}
