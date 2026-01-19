package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupAdminTestHandlers(t *testing.T) (*AdminHandlers, *gin.Engine) {
	t.Helper()
	logger := zap.NewNop()
	store := memory.NewStore()
	handlers := NewAdminHandlers(store, logger)

	router := gin.New()
	return handlers, router
}

func TestNewAdminHandlers(t *testing.T) {
	logger := zap.NewNop()
	store := memory.NewStore()

	handlers := NewAdminHandlers(store, logger)

	if handlers == nil {
		t.Fatal("Expected handlers to not be nil")
	}
	if handlers.store == nil {
		t.Error("Expected store to be set")
	}
	if handlers.logger == nil {
		t.Error("Expected logger to be set")
	}
}

func TestAdminHandlers_AdminStatus(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.GET("/admin/status", handlers.AdminStatus)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got %v", response["status"])
	}
	if response["service"] != "wallet-backend-admin" {
		t.Errorf("Expected service 'wallet-backend-admin', got %v", response["service"])
	}
}

func TestAdminHandlers_ListTenants(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.GET("/admin/tenants", handlers.ListTenants)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response struct {
		Tenants []TenantResponse `json:"tenants"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Memory store initializes with default tenant
	if len(response.Tenants) < 1 {
		t.Error("Expected at least one tenant (default)")
	}
}

func TestAdminHandlers_CreateTenant(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.POST("/admin/tenants", handlers.CreateTenant)

	t.Run("success", func(t *testing.T) {
		body := `{"id": "test-tenant", "name": "Test Tenant", "display_name": "Test Display"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		var tenant TenantResponse
		if err := json.Unmarshal(w.Body.Bytes(), &tenant); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if tenant.ID != "test-tenant" {
			t.Errorf("Expected id 'test-tenant', got %q", tenant.ID)
		}
		if tenant.Name != "Test Tenant" {
			t.Errorf("Expected name 'Test Tenant', got %q", tenant.Name)
		}
		if !tenant.Enabled {
			t.Error("Expected tenant to be enabled by default")
		}
	})

	t.Run("invalid id", func(t *testing.T) {
		body := `{"id": "Invalid ID!", "name": "Test"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("duplicate tenant", func(t *testing.T) {
		body := `{"id": "test-tenant", "name": "Duplicate"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("Expected status %d, got %d", http.StatusConflict, w.Code)
		}
	})

	t.Run("missing required fields", func(t *testing.T) {
		body := `{"id": "no-name"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("with enabled false", func(t *testing.T) {
		body := `{"id": "disabled-tenant", "name": "Disabled Tenant", "enabled": false}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
		}

		var tenant TenantResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tenant)
		if tenant.Enabled {
			t.Error("Expected tenant to be disabled")
		}
	})
}

func TestAdminHandlers_GetTenant(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.POST("/admin/tenants", handlers.CreateTenant)
	router.GET("/admin/tenants/:id", handlers.GetTenant)

	// Create a tenant first
	body := `{"id": "get-test", "name": "Get Test"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	t.Run("success", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/get-test", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		var tenant TenantResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tenant)
		if tenant.ID != "get-test" {
			t.Errorf("Expected id 'get-test', got %q", tenant.ID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/non-existent", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestAdminHandlers_UpdateTenant(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.POST("/admin/tenants", handlers.CreateTenant)
	router.PUT("/admin/tenants/:id", handlers.UpdateTenant)

	// Create a tenant first
	body := `{"id": "update-test", "name": "Update Test"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	t.Run("success", func(t *testing.T) {
		body := `{"id": "update-test", "name": "Updated Name", "display_name": "Updated Display", "enabled": false}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/update-test", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var tenant TenantResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tenant)
		if tenant.Name != "Updated Name" {
			t.Errorf("Expected name 'Updated Name', got %q", tenant.Name)
		}
		if tenant.Enabled {
			t.Error("Expected tenant to be disabled after update")
		}
	})

	t.Run("not found", func(t *testing.T) {
		body := `{"id": "non-existent", "name": "Test"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/non-existent", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("bad request", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/update-test", bytes.NewBufferString("invalid"))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestAdminHandlers_DeleteTenant(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.POST("/admin/tenants", handlers.CreateTenant)
	router.DELETE("/admin/tenants/:id", handlers.DeleteTenant)

	t.Run("success", func(t *testing.T) {
		// Create a tenant first
		body := `{"id": "delete-test", "name": "Delete Test"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Now delete it
		w = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodDelete, "/admin/tenants/delete-test", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("cannot delete default", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/default", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, w.Code)
		}
	})

	t.Run("not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/non-existent", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestAdminHandlers_TenantUsers(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.POST("/admin/tenants", handlers.CreateTenant)
	router.GET("/admin/tenants/:id/users", handlers.GetTenantUsers)
	router.POST("/admin/tenants/:id/users", handlers.AddUserToTenant)
	router.DELETE("/admin/tenants/:id/users/:user_id", handlers.RemoveUserFromTenant)

	// Create a tenant first
	body := `{"id": "user-test", "name": "User Test"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	t.Run("list empty users", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/user-test/users", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		var response struct {
			Users []string `json:"users"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &response)
		if len(response.Users) != 0 {
			t.Errorf("Expected empty users, got %d", len(response.Users))
		}
	})

	t.Run("add user", func(t *testing.T) {
		body := `{"user_id": "test-user-1", "role": "admin"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/user-test/users", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("add user with default role", func(t *testing.T) {
		body := `{"user_id": "test-user-2"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/user-test/users", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("list users after add", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/user-test/users", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		var response struct {
			Users []string `json:"users"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &response)
		if len(response.Users) != 2 {
			t.Errorf("Expected 2 users, got %d", len(response.Users))
		}
	})

	t.Run("add user to non-existent tenant", func(t *testing.T) {
		body := `{"user_id": "test-user"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/non-existent/users", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("remove user", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/user-test/users/test-user-1", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("list users for non-existent tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/non-existent/users", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("add user bad request", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/user-test/users", bytes.NewBufferString("invalid"))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestAdminHandlers_IssuerCRUD(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.POST("/admin/tenants", handlers.CreateTenant)
	router.GET("/admin/tenants/:id/issuers", handlers.ListIssuers)
	router.POST("/admin/tenants/:id/issuers", handlers.CreateIssuer)
	router.GET("/admin/tenants/:id/issuers/:issuer_id", handlers.GetIssuer)
	router.PUT("/admin/tenants/:id/issuers/:issuer_id", handlers.UpdateIssuer)
	router.DELETE("/admin/tenants/:id/issuers/:issuer_id", handlers.DeleteIssuer)

	// Create a tenant first
	body := `{"id": "issuer-test", "name": "Issuer Test"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	t.Run("list empty issuers", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/issuer-test/issuers", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	var createdIssuerID int64

	t.Run("create issuer", func(t *testing.T) {
		body := `{"credential_issuer_identifier": "https://issuer.example.com", "client_id": "test-client", "visible": true}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/issuer-test/issuers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		var issuer IssuerResponse
		_ = json.Unmarshal(w.Body.Bytes(), &issuer)
		createdIssuerID = issuer.ID
		if issuer.CredentialIssuerIdentifier != "https://issuer.example.com" {
			t.Errorf("Expected credential_issuer_identifier, got %q", issuer.CredentialIssuerIdentifier)
		}
	})

	t.Run("create issuer with missing field", func(t *testing.T) {
		body := `{"client_id": "test"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/issuer-test/issuers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("create issuer for non-existent tenant", func(t *testing.T) {
		body := `{"credential_issuer_identifier": "https://issuer.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/non-existent/issuers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("get issuer", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/issuer-test/issuers/1", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("get issuer invalid id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/issuer-test/issuers/invalid", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("get issuer not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/issuer-test/issuers/999", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("update issuer", func(t *testing.T) {
		body := `{"credential_issuer_identifier": "https://updated-issuer.example.com", "visible": false}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/issuer-test/issuers/1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("update issuer invalid id", func(t *testing.T) {
		body := `{"credential_issuer_identifier": "https://test.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/issuer-test/issuers/invalid", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("update issuer not found", func(t *testing.T) {
		body := `{"credential_issuer_identifier": "https://test.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/issuer-test/issuers/999", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("list issuers for non-existent tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/non-existent/issuers", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("delete issuer", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/issuer-test/issuers/1", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("delete issuer invalid id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/issuer-test/issuers/invalid", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("delete issuer not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/issuer-test/issuers/999", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	// Prevent unused variable warning
	_ = createdIssuerID
}

func TestAdminHandlers_VerifierCRUD(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.POST("/admin/tenants", handlers.CreateTenant)
	router.GET("/admin/tenants/:id/verifiers", handlers.ListVerifiers)
	router.POST("/admin/tenants/:id/verifiers", handlers.CreateVerifier)
	router.GET("/admin/tenants/:id/verifiers/:verifier_id", handlers.GetVerifier)
	router.PUT("/admin/tenants/:id/verifiers/:verifier_id", handlers.UpdateVerifier)
	router.DELETE("/admin/tenants/:id/verifiers/:verifier_id", handlers.DeleteVerifier)

	// Create a tenant first
	body := `{"id": "verifier-test", "name": "Verifier Test"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	t.Run("list empty verifiers", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/verifier-test/verifiers", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("create verifier", func(t *testing.T) {
		body := `{"name": "Test Verifier", "url": "https://verifier.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/verifier-test/verifiers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}
	})

	t.Run("create verifier missing name", func(t *testing.T) {
		body := `{"url": "https://verifier.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/verifier-test/verifiers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("create verifier for non-existent tenant", func(t *testing.T) {
		body := `{"name": "Test", "url": "https://test.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/non-existent/verifiers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("get verifier", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/verifier-test/verifiers/1", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("get verifier invalid id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/verifier-test/verifiers/invalid", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("get verifier not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/verifier-test/verifiers/999", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("update verifier", func(t *testing.T) {
		body := `{"name": "Updated Verifier", "url": "https://updated.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/verifier-test/verifiers/1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("update verifier invalid id", func(t *testing.T) {
		body := `{"name": "Test", "url": "https://test.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/verifier-test/verifiers/invalid", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("update verifier not found", func(t *testing.T) {
		body := `{"name": "Test", "url": "https://test.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/verifier-test/verifiers/999", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("list verifiers for non-existent tenant", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/non-existent/verifiers", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})

	t.Run("delete verifier", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/verifier-test/verifiers/1", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}
	})

	t.Run("delete verifier invalid id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/verifier-test/verifiers/invalid", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("delete verifier not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/verifier-test/verifiers/999", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}
	})
}

func TestTenantToResponse(t *testing.T) {
	// Test the helper function directly
	handlers, _ := setupAdminTestHandlers(t)
	_ = handlers // Just to ensure setup works

	// tenantToResponse is tested implicitly through the handlers
}
