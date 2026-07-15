package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func seedTenant(t *testing.T, store *memory.Store, id string) {
	t.Helper()
	tenant := &domain.Tenant{ID: domain.TenantID(id), Name: "Test Tenant"}
	if err := store.Tenants().Create(nil, tenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
}

func TestCreateInvite_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	seedTenant(t, store, "acme")

	body := `{"expires_in": 3600}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["tenant_id"] != "acme" {
		t.Errorf("expected tenant_id acme, got %v", resp["tenant_id"])
	}
	if resp["status"] != "active" {
		t.Errorf("expected status active, got %v", resp["status"])
	}
	// Code should be returned on create
	if resp["code"] == nil || resp["code"] == "" {
		t.Error("expected code to be returned on create")
	}
}

func TestCreateInvite_WithCustomCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	seedTenant(t, store, "acme")

	body := `{"code": "MY-CUSTOM-CODE"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["code"] != "MY-CUSTOM-CODE" {
		t.Errorf("expected custom code, got %v", resp["code"])
	}
}

func TestCreateInvite_EmptyBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	seedTenant(t, store, "acme")

	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 with empty body, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateInvite_TenantNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)

	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/nonexistent/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListInvites_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.GET("/admin/tenants/:id/invites", h.ListInvites)
	seedTenant(t, store, "acme")

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	invites, ok := resp["invites"].([]interface{})
	if !ok {
		t.Fatal("invites field missing or not an array")
	}
	if len(invites) != 0 {
		t.Errorf("expected 0 invites, got %d", len(invites))
	}
}

func TestListInvites_TenantNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.GET("/admin/tenants/:id/invites", h.ListInvites)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/nonexistent/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListInvites_WithData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	router.GET("/admin/tenants/:id/invites", h.ListInvites)
	seedTenant(t, store, "acme")

	// Create two invites
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("create invite %d: got %d", i, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	invites, ok := resp["invites"].([]interface{})
	if !ok {
		t.Fatal("invites field missing or not an array")
	}
	if len(invites) != 2 {
		t.Errorf("expected 2 invites, got %d", len(invites))
	}
}

func TestGetInvite_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.GET("/admin/tenants/:id/invites/:invite_id", h.GetInvite)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/invites/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetInvite_WrongTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	router.GET("/admin/tenants/:id/invites/:invite_id", h.GetInvite)
	seedTenant(t, store, "acme")
	seedTenant(t, store, "other")

	// Create invite in acme
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var created map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	inviteID := created["id"].(string)

	// Try to get it from "other" tenant
	req = httptest.NewRequest(http.MethodGet, "/admin/tenants/other/invites/"+inviteID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong tenant, got %d", w.Code)
	}
}

func TestUpdateInvite_Revoke(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	router.PUT("/admin/tenants/:id/invites/:invite_id", h.UpdateInvite)
	seedTenant(t, store, "acme")

	// Create invite
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var created map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	inviteID := created["id"].(string)

	// Revoke it
	body := `{"action": "revoke"}`
	req = httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/invites/"+inviteID, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["status"] != "revoked" {
		t.Errorf("expected status revoked, got %v", resp["status"])
	}
}

func TestUpdateInvite_Renew(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	router.PUT("/admin/tenants/:id/invites/:invite_id", h.UpdateInvite)
	seedTenant(t, store, "acme")

	// Create and revoke
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var created map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	inviteID := created["id"].(string)

	// Renew with custom expiry
	body := `{"action": "renew", "expires_in": 7200}`
	req = httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/invites/"+inviteID, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["status"] != "active" {
		t.Errorf("expected status active, got %v", resp["status"])
	}
}

func TestUpdateInvite_InvalidAction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	router.PUT("/admin/tenants/:id/invites/:invite_id", h.UpdateInvite)
	seedTenant(t, store, "acme")

	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var created map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	inviteID := created["id"].(string)

	body := `{"action": "invalid"}`
	req = httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/invites/"+inviteID, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestUpdateInvite_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.PUT("/admin/tenants/:id/invites/:invite_id", h.UpdateInvite)

	body := `{"action": "revoke"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/invites/nonexistent", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUpdateInvite_MissingAction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.PUT("/admin/tenants/:id/invites/:invite_id", h.UpdateInvite)

	body := `{}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/invites/someid", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDeleteInvite_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	router.DELETE("/admin/tenants/:id/invites/:invite_id", h.DeleteInvite)
	seedTenant(t, store, "acme")

	// Create invite
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var created map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	inviteID := created["id"].(string)

	// Delete it
	req = httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/invites/"+inviteID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteInvite_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.DELETE("/admin/tenants/:id/invites/:invite_id", h.DeleteInvite)

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/invites/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDeleteInvite_WrongTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.POST("/admin/tenants/:id/invites", h.CreateInvite)
	router.DELETE("/admin/tenants/:id/invites/:invite_id", h.DeleteInvite)
	seedTenant(t, store, "acme")
	seedTenant(t, store, "other")

	// Create in acme
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/acme/invites", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	var created map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	inviteID := created["id"].(string)

	// Try delete from other
	req = httptest.NewRequest(http.MethodDelete, "/admin/tenants/other/invites/"+inviteID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for wrong tenant, got %d", w.Code)
	}
}
