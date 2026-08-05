package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
)

func testAuditEmitter(t *testing.T) *audit.Emitter {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return audit.New("test-issuer", signer, nil)
}

func seedInstance(t *testing.T, h *AdminHandlers, id string, tenantID domain.TenantID, userID *domain.UserID) {
	t.Helper()
	inst := &domain.WalletInstance{
		ID:       id,
		TenantID: tenantID,
		UserID:   userID,
		Status:   domain.InstanceStatusActive,
	}
	if err := h.store.WalletInstances().Upsert(nil, inst); err != nil {
		t.Fatalf("seed instance: %v", err)
	}
}

func TestListWalletInstances_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/instances", h.ListWalletInstances)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); body != "[]" {
		t.Errorf("expected empty array, got %s", body)
	}
}

func TestListWalletInstances_WithData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/instances", h.ListWalletInstances)

	seedInstance(t, h, "inst-1", "acme", nil)
	seedInstance(t, h, "inst-2", "acme", nil)
	seedInstance(t, h, "inst-other", "other-tenant", nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var instances []domain.WalletInstance
	if err := json.Unmarshal(w.Body.Bytes(), &instances); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(instances) != 2 {
		t.Errorf("expected 2 instances for acme, got %d", len(instances))
	}
}

func TestGetWalletInstance_Found(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/instances/:instance_id", h.GetWalletInstance)

	seedInstance(t, h, "inst-1", "acme", nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances/inst-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var inst domain.WalletInstance
	if err := json.Unmarshal(w.Body.Bytes(), &inst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if inst.ID != "inst-1" {
		t.Errorf("expected id inst-1, got %s", inst.ID)
	}
}

func TestGetWalletInstance_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/instances/:instance_id", h.GetWalletInstance)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// TestGetWalletInstance_CrossTenant_NotFound guards against a cross-tenant
// data access bug: an instance belonging to tenant "other" must not be
// fetchable via a different tenant's ("acme") path.
func TestGetWalletInstance_CrossTenant_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/instances/:instance_id", h.GetWalletInstance)

	seedInstance(t, h, "inst-1", "other", nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances/inst-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-tenant access, got %d: %s", w.Code, w.Body.String())
	}
}

// TestUpdateWalletInstanceStatus_CrossTenant_NotFound guards against a
// cross-tenant data access bug: an instance belonging to tenant "other"
// must not be modifiable via a different tenant's ("acme") path.
func TestUpdateWalletInstanceStatus_CrossTenant_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	seedInstance(t, h, "inst-1", "other", nil)

	body := `{"status":"suspended","reason":"compliance review"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/inst-1/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-tenant access, got %d: %s", w.Code, w.Body.String())
	}

	inst, err := store.WalletInstances().GetByID(nil, "inst-1")
	if err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if inst.Status != domain.InstanceStatusActive {
		t.Errorf("expected status to remain active after rejected cross-tenant update, got %s", inst.Status)
	}
}

// TestDeleteWalletInstance_CrossTenant_NotFound guards against a cross-tenant
// data access bug: an instance belonging to tenant "other" must not be
// deletable via a different tenant's ("acme") path.
func TestDeleteWalletInstance_CrossTenant_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.DELETE("/admin/tenants/:id/instances/:instance_id", h.DeleteWalletInstance)

	seedInstance(t, h, "inst-1", "other", nil)

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/instances/inst-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for cross-tenant access, got %d: %s", w.Code, w.Body.String())
	}

	if _, err := store.WalletInstances().GetByID(nil, "inst-1"); err != nil {
		t.Errorf("expected instance to still exist after rejected cross-tenant delete, got err: %v", err)
	}
}

func TestUpdateWalletInstanceStatus_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	seedInstance(t, h, "inst-1", "acme", nil)

	body := `{"status":"suspended","reason":"compliance review"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/inst-1/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["status"] != "suspended" {
		t.Errorf("expected status suspended, got %s", resp["status"])
	}
}

func TestUpdateWalletInstanceStatus_InvalidStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	body := `{"status":"invalid"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/inst-1/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestUpdateWalletInstanceStatus_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	body := `{"status":"revoked"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/nonexistent/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDeleteWalletInstance_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.DELETE("/admin/tenants/:id/instances/:instance_id", h.DeleteWalletInstance)

	seedInstance(t, h, "inst-1", "acme", nil)

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/instances/inst-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify deleted
	req2 := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances/inst-1", nil)
	w2 := httptest.NewRecorder()
	router2 := gin.New()
	router2.GET("/admin/tenants/:id/instances/:instance_id", h.GetWalletInstance)
	router2.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", w2.Code)
	}
}

func TestDeleteWalletInstance_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.DELETE("/admin/tenants/:id/instances/:instance_id", h.DeleteWalletInstance)

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/instances/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListWalletInstancesByUser_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/instances", h.ListWalletInstancesByUser)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/users/user-1/instances", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); body != "[]" {
		t.Errorf("expected empty array, got %s", body)
	}
}

func TestListWalletInstancesByUser_WithData(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/instances", h.ListWalletInstancesByUser)

	uid := domain.UserIDFromString("user-1")
	seedInstance(t, h, "inst-u1", "acme", &uid)
	seedInstance(t, h, "inst-u2", "acme", &uid)

	uid2 := domain.UserIDFromString("user-2")
	seedInstance(t, h, "inst-other", "acme", &uid2)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/users/user-1/instances", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var instances []domain.WalletInstance
	if err := json.Unmarshal(w.Body.Bytes(), &instances); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(instances) != 2 {
		t.Errorf("expected 2 instances for user-1, got %d", len(instances))
	}
}

func TestUpdateWalletInstanceStatus_WithAudit_Revoked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	auditor := testAuditEmitter(t)
	h := NewAdminHandlers(store, zap.NewNop(), auditor, nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	seedInstance(t, h, "audit-inst", "acme", nil)

	body := `{"status":"revoked","reason":"policy violation"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/audit-inst/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateWalletInstanceStatus_WithAudit_Suspended(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	auditor := testAuditEmitter(t)
	h := NewAdminHandlers(store, zap.NewNop(), auditor, nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	seedInstance(t, h, "suspend-inst", "acme", nil)

	body := `{"status":"suspended","reason":"under review"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/suspend-inst/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateWalletInstanceStatus_WithAudit_Reactivate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	auditor := testAuditEmitter(t)
	h := NewAdminHandlers(store, zap.NewNop(), auditor, nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	seedInstance(t, h, "reactivate-inst", "acme", nil)

	body := `{"status":"active"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/reactivate-inst/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListWalletInstances_StoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := memory.NewStore()
	store := &errStore{
		Store:           base,
		walletInstances: &errWalletInstanceStore{WalletInstanceStore: base.WalletInstances(), getAllByTenantErr: errors.New("boom")},
	}
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/instances", h.ListWalletInstances)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetWalletInstance_StoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := memory.NewStore()
	store := &errStore{
		Store:           base,
		walletInstances: &errWalletInstanceStore{WalletInstanceStore: base.WalletInstances(), getByIDErr: errors.New("boom")},
	}
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/instances/:instance_id", h.GetWalletInstance)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances/inst-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteWalletInstance_StoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := memory.NewStore()
	store := &errStore{
		Store:           base,
		walletInstances: &errWalletInstanceStore{WalletInstanceStore: base.WalletInstances(), deleteErr: errors.New("boom")},
	}
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.DELETE("/admin/tenants/:id/instances/:instance_id", h.DeleteWalletInstance)

	// Seed via the underlying (non-erroring) store so the handler's tenant
	// ownership check (GetByID, not overridden here) succeeds and the
	// request reaches the injected Delete error.
	seedInstance(t, h, "inst-1", "acme", nil)

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/instances/inst-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestListWalletInstancesByUser_StoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := memory.NewStore()
	store := &errStore{
		Store:           base,
		walletInstances: &errWalletInstanceStore{WalletInstanceStore: base.WalletInstances(), getByUserErr: errors.New("boom")},
	}
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/instances", h.ListWalletInstancesByUser)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/users/user-1/instances", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDeleteWalletInstance_WithAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	auditor := testAuditEmitter(t)
	h := NewAdminHandlers(store, zap.NewNop(), auditor, nil)
	router := gin.New()
	router.DELETE("/admin/tenants/:id/instances/:instance_id", h.DeleteWalletInstance)

	seedInstance(t, h, "del-audit", "acme", nil)

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/instances/del-audit", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}
