package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/r2ps"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupAdminTestHandlers(t *testing.T) (*AdminHandlers, *gin.Engine) {
	t.Helper()
	logger := zap.NewNop()
	store := memory.NewStore()
	handlers := NewAdminHandlers(store, logger, nil, nil)

	router := gin.New()
	return handlers, router
}

// errStore wraps a storage.Store so tests can inject failures on specific
// sub-store methods that are otherwise unreachable through the in-memory
// store (which never fails on its own). Only the sub-stores actually needed
// by a given test are set; everything else delegates to the embedded real
// store.
type errStore struct {
	storage.Store
	tenants         *errTenantStore
	userTenants     *errUserTenantStore
	issuers         *errIssuerStore
	verifiers       *errVerifierStore
	walletInstances *errWalletInstanceStore
	users           *errUserStore
}

func (s *errStore) Tenants() storage.TenantStore {
	if s.tenants != nil {
		return s.tenants
	}
	return s.Store.Tenants()
}

func (s *errStore) UserTenants() storage.UserTenantStore {
	if s.userTenants != nil {
		return s.userTenants
	}
	return s.Store.UserTenants()
}

func (s *errStore) Issuers() storage.IssuerStore {
	if s.issuers != nil {
		return s.issuers
	}
	return s.Store.Issuers()
}

func (s *errStore) Verifiers() storage.VerifierStore {
	if s.verifiers != nil {
		return s.verifiers
	}
	return s.Store.Verifiers()
}

func (s *errStore) WalletInstances() storage.WalletInstanceStore {
	if s.walletInstances != nil {
		return s.walletInstances
	}
	return s.Store.WalletInstances()
}

func (s *errStore) Users() storage.UserStore {
	if s.users != nil {
		return s.users
	}
	return s.Store.Users()
}

type errTenantStore struct {
	storage.TenantStore
	getAllErr  error
	getByIDErr error
	deleteErr  error
}

func (s *errTenantStore) GetAll(ctx context.Context) ([]*domain.Tenant, error) {
	if s.getAllErr != nil {
		return nil, s.getAllErr
	}
	return s.TenantStore.GetAll(ctx)
}

func (s *errTenantStore) GetByID(ctx context.Context, id domain.TenantID) (*domain.Tenant, error) {
	if s.getByIDErr != nil {
		return nil, s.getByIDErr
	}
	return s.TenantStore.GetByID(ctx, id)
}

func (s *errTenantStore) Delete(ctx context.Context, id domain.TenantID) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.TenantStore.Delete(ctx, id)
}

type errUserTenantStore struct {
	storage.UserTenantStore
	addErr      error
	removeErr   error
	getUsersErr error
	isMemberErr error
}

func (s *errUserTenantStore) AddMembership(ctx context.Context, m *domain.UserTenantMembership) error {
	if s.addErr != nil {
		return s.addErr
	}
	return s.UserTenantStore.AddMembership(ctx, m)
}

func (s *errUserTenantStore) RemoveMembership(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) error {
	if s.removeErr != nil {
		return s.removeErr
	}
	return s.UserTenantStore.RemoveMembership(ctx, userID, tenantID)
}

func (s *errUserTenantStore) GetTenantUsers(ctx context.Context, tenantID domain.TenantID) ([]domain.UserID, error) {
	if s.getUsersErr != nil {
		return nil, s.getUsersErr
	}
	return s.UserTenantStore.GetTenantUsers(ctx, tenantID)
}

func (s *errUserTenantStore) IsMember(ctx context.Context, userID domain.UserID, tenantID domain.TenantID) (bool, error) {
	if s.isMemberErr != nil {
		return false, s.isMemberErr
	}
	return s.UserTenantStore.IsMember(ctx, userID, tenantID)
}

type errIssuerStore struct {
	storage.IssuerStore
	getAllErr error
}

func (s *errIssuerStore) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.CredentialIssuer, error) {
	if s.getAllErr != nil {
		return nil, s.getAllErr
	}
	return s.IssuerStore.GetAll(ctx, tenantID)
}

type errVerifierStore struct {
	storage.VerifierStore
	getAllErr error
	createErr error
}

func (s *errVerifierStore) GetAll(ctx context.Context, tenantID domain.TenantID) ([]*domain.Verifier, error) {
	if s.getAllErr != nil {
		return nil, s.getAllErr
	}
	return s.VerifierStore.GetAll(ctx, tenantID)
}

func (s *errVerifierStore) Create(ctx context.Context, v *domain.Verifier) error {
	if s.createErr != nil {
		return s.createErr
	}
	return s.VerifierStore.Create(ctx, v)
}

type errWalletInstanceStore struct {
	storage.WalletInstanceStore
	getAllByTenantErr error
	getByIDErr        error
	getByUserErr      error
	deleteErr         error
}

func (s *errWalletInstanceStore) GetAllByTenant(ctx context.Context, tenantID domain.TenantID) ([]*domain.WalletInstance, error) {
	if s.getAllByTenantErr != nil {
		return nil, s.getAllByTenantErr
	}
	return s.WalletInstanceStore.GetAllByTenant(ctx, tenantID)
}

func (s *errWalletInstanceStore) GetByID(ctx context.Context, id string) (*domain.WalletInstance, error) {
	if s.getByIDErr != nil {
		return nil, s.getByIDErr
	}
	return s.WalletInstanceStore.GetByID(ctx, id)
}

func (s *errWalletInstanceStore) GetByUser(ctx context.Context, tenantID domain.TenantID, userID domain.UserID) ([]*domain.WalletInstance, error) {
	if s.getByUserErr != nil {
		return nil, s.getByUserErr
	}
	return s.WalletInstanceStore.GetByUser(ctx, tenantID, userID)
}

func (s *errWalletInstanceStore) Delete(ctx context.Context, id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.WalletInstanceStore.Delete(ctx, id)
}

type errUserStore struct {
	storage.UserStore
	getByIDErr error
}

func (s *errUserStore) GetByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	if s.getByIDErr != nil {
		return nil, s.getByIDErr
	}
	return s.UserStore.GetByID(ctx, id)
}

func TestNewAdminHandlers(t *testing.T) {
	logger := zap.NewNop()
	store := memory.NewStore()

	handlers := NewAdminHandlers(store, logger, nil, nil)

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

	t.Run("with require_invite true", func(t *testing.T) {
		body := `{"id": "invite-tenant", "name": "Invite Tenant", "require_invite": true}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		var tenant TenantResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tenant)
		if !tenant.RequireInvite {
			t.Error("Expected require_invite to be true")
		}
	})

	t.Run("default require_invite is false", func(t *testing.T) {
		body := `{"id": "no-invite-tenant", "name": "No Invite Tenant"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		var tenant TenantResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tenant)
		if tenant.RequireInvite {
			t.Error("Expected require_invite to default to false")
		}
	})

	t.Run("create with trust_config pdp_url", func(t *testing.T) {
		body := `{"id": "pdp-tenant", "name": "PDP Tenant", "trust_config": {"pdp_url": "https://pdp.example.com"}}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		var tenant TenantResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tenant)
		if tenant.TrustConfig == nil {
			t.Fatal("Expected trust_config to be set")
		}
		if tenant.TrustConfig.PDPURL != "https://pdp.example.com" {
			t.Errorf("Expected pdp_url 'https://pdp.example.com', got %q", tenant.TrustConfig.PDPURL)
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

	t.Run("update require_invite", func(t *testing.T) {
		body := `{"id": "update-test", "name": "Updated Name", "require_invite": true}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/update-test", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var tenant TenantResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tenant)
		if !tenant.RequireInvite {
			t.Error("Expected require_invite to be true after update")
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

	t.Run("update trust_config with pdp_url", func(t *testing.T) {
		body := `{"id": "update-test", "name": "Updated Name", "trust_config": {"trust_ttl": 300, "pdp_url": "https://pdp.example.com"}}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/update-test", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		var tenant TenantResponse
		_ = json.Unmarshal(w.Body.Bytes(), &tenant)
		if tenant.TrustConfig == nil {
			t.Fatal("Expected trust_config to be set")
		}
		if tenant.TrustConfig.PDPURL != "https://pdp.example.com" {
			t.Errorf("Expected pdp_url 'https://pdp.example.com', got %q", tenant.TrustConfig.PDPURL)
		}
		if tenant.TrustConfig.TrustTTL != 300 {
			t.Errorf("Expected trust_ttl 300, got %d", tenant.TrustConfig.TrustTTL)
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

func TestAdminHandlers_VerifierClientID(t *testing.T) {
	handlers, router := setupAdminTestHandlers(t)
	router.POST("/admin/tenants", handlers.CreateTenant)
	router.POST("/admin/tenants/:id/verifiers", handlers.CreateVerifier)
	router.GET("/admin/tenants/:id/verifiers/:verifier_id", handlers.GetVerifier)
	router.PUT("/admin/tenants/:id/verifiers/:verifier_id", handlers.UpdateVerifier)

	// Create a tenant first
	body := `{"id": "clientid-test", "name": "ClientID Test"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	t.Run("create verifier with client_id and scheme", func(t *testing.T) {
		body := `{"name": "Pre-registered Verifier", "url": "https://verifier.example.com", "client_id": "custom-client-123", "client_id_scheme": "pre-registered"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/clientid-test/verifiers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Expected status %d, got %d: %s", http.StatusCreated, w.Code, w.Body.String())
		}

		// Verify response includes client_id fields
		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}
		if resp["client_id"] != "custom-client-123" {
			t.Errorf("Expected client_id 'custom-client-123', got %v", resp["client_id"])
		}
		if resp["client_id_scheme"] != "pre-registered" {
			t.Errorf("Expected client_id_scheme 'pre-registered', got %v", resp["client_id_scheme"])
		}
	})

	t.Run("create verifier invalid scheme", func(t *testing.T) {
		body := `{"name": "Invalid Scheme", "url": "https://invalid.example.com", "client_id": "test", "client_id_scheme": "invalid-scheme"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/clientid-test/verifiers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
		}
	})

	t.Run("create verifier scheme without client_id", func(t *testing.T) {
		body := `{"name": "Missing ClientID", "url": "https://missing-clientid.example.com", "client_id_scheme": "pre-registered"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/clientid-test/verifiers", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
		}
	})

	t.Run("update verifier preserves client_id when not provided", func(t *testing.T) {
		// Update with only name/url, should preserve existing client_id
		body := `{"name": "Updated Name", "url": "https://verifier.example.com"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/clientid-test/verifiers/1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		// Verify client_id fields are preserved
		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}
		if resp["client_id"] != "custom-client-123" {
			t.Errorf("Expected client_id 'custom-client-123' to be preserved, got %v", resp["client_id"])
		}
		if resp["client_id_scheme"] != "pre-registered" {
			t.Errorf("Expected client_id_scheme 'pre-registered' to be preserved, got %v", resp["client_id_scheme"])
		}
	})

	t.Run("update verifier with new client_id", func(t *testing.T) {
		body := `{"name": "Updated Name", "url": "https://verifier.example.com", "client_id": "new-client-456", "client_id_scheme": "x509_san_dns"}`
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/admin/tenants/clientid-test/verifiers/1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
		}

		// Verify client_id fields are updated
		var resp map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}
		if resp["client_id"] != "new-client-456" {
			t.Errorf("Expected client_id 'new-client-456', got %v", resp["client_id"])
		}
		if resp["client_id_scheme"] != "x509_san_dns" {
			t.Errorf("Expected client_id_scheme 'x509_san_dns', got %v", resp["client_id_scheme"])
		}
	})
}

func TestTenantToResponse(t *testing.T) {
	// Test the helper function directly
	handlers, _ := setupAdminTestHandlers(t)
	_ = handlers // Just to ensure setup works

	// tenantToResponse is tested implicitly through the handlers
}

func TestAdminHandlers_RegisterRoutes(t *testing.T) {
	t.Run("without r2ps client", func(t *testing.T) {
		handlers, _ := setupAdminTestHandlers(t)
		router := gin.New()
		group := router.Group("/admin")
		handlers.RegisterRoutes(group)

		routeSet := make(map[string]bool)
		for _, r := range router.Routes() {
			routeSet[r.Method+" "+r.Path] = true
		}

		expected := []string{
			"GET /admin/tenants",
			"POST /admin/tenants",
			"GET /admin/tenants/:id",
			"PUT /admin/tenants/:id",
			"DELETE /admin/tenants/:id",
			"GET /admin/tenants/:id/users",
			"POST /admin/tenants/:id/users",
			"DELETE /admin/tenants/:id/users/:user_id",
			"GET /admin/tenants/:id/issuers",
			"POST /admin/tenants/:id/issuers",
			"GET /admin/tenants/:id/issuers/:issuer_id",
			"PUT /admin/tenants/:id/issuers/:issuer_id",
			"DELETE /admin/tenants/:id/issuers/:issuer_id",
			"GET /admin/tenants/:id/verifiers",
			"POST /admin/tenants/:id/verifiers",
			"GET /admin/tenants/:id/verifiers/:verifier_id",
			"PUT /admin/tenants/:id/verifiers/:verifier_id",
			"DELETE /admin/tenants/:id/verifiers/:verifier_id",
			"GET /admin/tenants/:id/invites",
			"POST /admin/tenants/:id/invites",
			"GET /admin/tenants/:id/invites/:invite_id",
			"PUT /admin/tenants/:id/invites/:invite_id",
			"DELETE /admin/tenants/:id/invites/:invite_id",
			"GET /admin/tenants/:id/instances",
			"GET /admin/tenants/:id/instances/:instance_id",
			"PUT /admin/tenants/:id/instances/:instance_id/status",
			"DELETE /admin/tenants/:id/instances/:instance_id",
			"GET /admin/tenants/:id/users/:user_id/instances",
			"GET /admin/tenants/:id/users/:user_id/detail",
			"GET /admin/tenants/:id/stats",
		}
		for _, e := range expected {
			if !routeSet[e] {
				t.Errorf("expected route %q to be registered", e)
			}
		}

		for _, r := range router.Routes() {
			if strings.HasPrefix(r.Path, "/admin/r2ps") {
				t.Errorf("did not expect r2ps route %s to be registered when r2psClient is nil", r.Path)
			}
		}
	})

	t.Run("with r2ps client", func(t *testing.T) {
		store := memory.NewStore()
		handlers := NewAdminHandlers(store, zap.NewNop(), nil, r2ps.NewClient("https://r2ps.example.com"))
		router := gin.New()
		group := router.Group("/admin")
		handlers.RegisterRoutes(group)

		routeSet := make(map[string]bool)
		for _, r := range router.Routes() {
			routeSet[r.Method+" "+r.Path] = true
		}

		expected := []string{
			"GET /admin/r2ps/keys",
			"GET /admin/r2ps/keys/:kid",
			"GET /admin/r2ps/statuses/:category",
			"GET /admin/r2ps/status/:category/:idx",
			"PUT /admin/r2ps/status/:category/:idx",
		}
		for _, e := range expected {
			if !routeSet[e] {
				t.Errorf("expected r2ps route %q to be registered when r2psClient is set", e)
			}
		}
	})
}

func TestAdminHandlers_ListTenants_StoreError(t *testing.T) {
	base := memory.NewStore()
	store := &errStore{
		Store:   base,
		tenants: &errTenantStore{TenantStore: base.Tenants(), getAllErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants", handlers.ListTenants)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestAdminHandlers_GetTenant_StoreError(t *testing.T) {
	base := memory.NewStore()
	store := &errStore{
		Store:   base,
		tenants: &errTenantStore{TenantStore: base.Tenants(), getByIDErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id", handlers.GetTenant)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/whatever", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestAdminHandlers_DeleteTenant_DeleteError(t *testing.T) {
	base := memory.NewStore()
	tenant := &domain.Tenant{ID: "del-err-test", Name: "Del Err"}
	if err := base.Tenants().Create(context.Background(), tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	store := &errStore{
		Store:   base,
		tenants: &errTenantStore{TenantStore: base.Tenants(), deleteErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.DELETE("/admin/tenants/:id", handlers.DeleteTenant)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/del-err-test", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestAdminHandlers_AddUserToTenant_StoreError(t *testing.T) {
	base := memory.NewStore()
	tenant := &domain.Tenant{ID: "add-err-test", Name: "Add Err"}
	if err := base.Tenants().Create(context.Background(), tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	store := &errStore{
		Store:       base,
		userTenants: &errUserTenantStore{UserTenantStore: base.UserTenants(), addErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.POST("/admin/tenants/:id/users", handlers.AddUserToTenant)

	body := `{"user_id": "u1"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/add-err-test/users", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestAdminHandlers_RemoveUserFromTenant_StoreError(t *testing.T) {
	base := memory.NewStore()
	store := &errStore{
		Store:       base,
		userTenants: &errUserTenantStore{UserTenantStore: base.UserTenants(), removeErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.DELETE("/admin/tenants/:id/users/:user_id", handlers.RemoveUserFromTenant)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/rm-err-test/users/u1", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestAdminHandlers_GetTenantUsers_StoreError(t *testing.T) {
	base := memory.NewStore()
	tenant := &domain.Tenant{ID: "gtu-err-test", Name: "GTU Err"}
	if err := base.Tenants().Create(context.Background(), tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	store := &errStore{
		Store:       base,
		userTenants: &errUserTenantStore{UserTenantStore: base.UserTenants(), getUsersErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users", handlers.GetTenantUsers)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/gtu-err-test/users", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestIssuerToResponse_WithTrustEvaluatedAt(t *testing.T) {
	evaluatedAt := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	issuer := &domain.CredentialIssuer{
		ID:                         42,
		TenantID:                   "acme",
		CredentialIssuerIdentifier: "https://issuer.example.com",
		ClientID:                   "client-1",
		ClientJWK:                  `{"kty":"EC"}`,
		Visible:                    true,
		TrustStatus:                domain.TrustStatus("trusted"),
		TrustFramework:             "eudi",
		TrustEvaluatedAt:           &evaluatedAt,
	}

	resp := issuerToResponse(issuer)

	if resp.TrustEvaluatedAt == nil {
		t.Fatal("expected TrustEvaluatedAt to be set")
	}
	if *resp.TrustEvaluatedAt != evaluatedAt.Format(time.RFC3339) {
		t.Errorf("expected %s, got %s", evaluatedAt.Format(time.RFC3339), *resp.TrustEvaluatedAt)
	}
	if !resp.HasClientJWK {
		t.Error("expected HasClientJWK to be true when ClientJWK is set")
	}
	if resp.TrustStatus != "trusted" {
		t.Errorf("expected trust_status 'trusted', got %q", resp.TrustStatus)
	}
}

func TestAdminHandlers_ListIssuers_StoreError(t *testing.T) {
	base := memory.NewStore()
	tenant := &domain.Tenant{ID: "li-err-test", Name: "LI Err"}
	if err := base.Tenants().Create(context.Background(), tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	store := &errStore{
		Store:   base,
		issuers: &errIssuerStore{IssuerStore: base.Issuers(), getAllErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/issuers", handlers.ListIssuers)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/li-err-test/issuers", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestAdminHandlers_ListVerifiers_StoreError(t *testing.T) {
	base := memory.NewStore()
	tenant := &domain.Tenant{ID: "lv-err-test", Name: "LV Err"}
	if err := base.Tenants().Create(context.Background(), tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	store := &errStore{
		Store:     base,
		verifiers: &errVerifierStore{VerifierStore: base.Verifiers(), getAllErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/verifiers", handlers.ListVerifiers)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/lv-err-test/verifiers", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestAdminHandlers_CreateVerifier_StoreError(t *testing.T) {
	base := memory.NewStore()
	tenant := &domain.Tenant{ID: "cv-err-test", Name: "CV Err"}
	if err := base.Tenants().Create(context.Background(), tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	store := &errStore{
		Store:     base,
		verifiers: &errVerifierStore{VerifierStore: base.Verifiers(), createErr: errors.New("boom")},
	}
	handlers := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.POST("/admin/tenants/:id/verifiers", handlers.CreateVerifier)

	body := `{"name": "Test", "url": "https://verifier.example.com"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/cv-err-test/verifiers", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected %d, got %d: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}
