package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
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
	if err := h.store.WalletInstances().Upsert(context.Background(), inst); err != nil {
		t.Fatalf("seed instance: %v", err)
	}
}

func TestListWalletInstances_Empty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/instances/:instance_id", h.GetWalletInstance)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/instances/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUpdateWalletInstanceStatus_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	seedInstance(t, h, "inst-1", "acme", nil)

	body := `{"status":"revoked","reason":"compliance review"}`
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
	if resp["status"] != "revoked" {
		t.Errorf("expected status revoked, got %s", resp["status"])
	}
}

func TestUpdateWalletInstanceStatus_InvalidStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), auditor)
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

// "active" is not a status this endpoint accepts. Revocation is the only
// lifecycle change a wallet instance has and it cannot be undone, so a
// request to reactivate one is a 400 at the binding, never a state change.
func TestUpdateWalletInstanceStatus_RejectsReactivation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	auditor := testAuditEmitter(t)
	h := NewAdminHandlers(store, zap.NewNop(), auditor)
	router := gin.New()
	router.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)

	seedInstance(t, h, "reactivate-inst", "acme", nil)

	body := `{"status":"active"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/reactivate-inst/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	got, err := store.WalletInstances().GetByID(context.Background(), "reactivate-inst")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != domain.InstanceStatusActive {
		t.Errorf("status = %s, want it untouched", got.Status)
	}
}

func TestDeleteWalletInstance_WithAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	auditor := testAuditEmitter(t)
	h := NewAdminHandlers(store, zap.NewNop(), auditor)
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

// With the shared lifecycle service wired (as BackendProvider does), an admin
// revocation of the user's last instance runs the SID-AUTH-06 cascade.
func TestUpdateWalletInstanceStatus_LifecycleCascade(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), testAuditEmitter(t))
	h.SetLifecycle(service.NewWalletLifecycleService(store, zap.NewNop(), nil))
	userID := domain.NewUserID()
	if err := store.Users().Create(context.Background(), &domain.User{UUID: userID, PrivateData: []byte("vault")}); err != nil {
		t.Fatal(err)
	}
	seedInstance(t, h, "inst-1", "acme", &userID)

	r := gin.New()
	r.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/inst-1/status", strings.NewReader(`{"status":"revoked","reason":"compromised"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d %s", w.Code, w.Body.String())
	}
	inst, err := store.WalletInstances().GetByID(context.Background(), "inst-1")
	if err != nil || inst.Status != domain.InstanceStatusRevoked {
		t.Fatalf("expected revoked, got %v %v", err, inst)
	}
	user, err := store.Users().GetByID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.PrivateData != nil {
		t.Errorf("revoking the last instance must erase the wallet's private data")
	}

	// Revoked is terminal: reactivation is refused at the binding, before it
	// is even a transition question, because "revoked" is the only status
	// this endpoint accepts.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/admin/tenants/acme/instances/inst-1/status", strings.NewReader(`{"status":"active"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	inst, err = store.WalletInstances().GetByID(context.Background(), "inst-1")
	if err != nil || inst.Status != domain.InstanceStatusRevoked {
		t.Fatalf("status must still be revoked, got %v %v", err, inst)
	}
}

// SID-AUTH-06: a revoked instance of a user is the tombstone that keeps the
// login gate and WIA guard refusing the wallet; the admin API must not delete
// it. Stray records without a user can still be removed.
func TestDeleteWalletInstance_RevokedInstanceIsRetained(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil)
	userID := domain.NewUserID()
	seedInstance(t, h, "owned-revoked", "acme", &userID)
	seedInstance(t, h, "stray-revoked", "acme", nil)
	for _, id := range []string{"owned-revoked", "stray-revoked"} {
		if err := store.WalletInstances().UpdateStatus(context.Background(), id, domain.InstanceStatusRevoked, "test"); err != nil {
			t.Fatal(err)
		}
	}
	router := gin.New()
	router.DELETE("/admin/tenants/:id/instances/:instance_id", h.DeleteWalletInstance)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/instances/owned-revoked", nil))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), errCodeRevokedInstanceRetained) {
		t.Fatalf("expected 409 %s, got %d %s", errCodeRevokedInstanceRetained, w.Code, w.Body.String())
	}
	if _, err := store.WalletInstances().GetByID(context.Background(), "owned-revoked"); err != nil {
		t.Fatalf("the tombstone must still exist: %v", err)
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/admin/tenants/acme/instances/stray-revoked", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("a revoked record without a user may be deleted, got %d %s", w.Code, w.Body.String())
	}
}
