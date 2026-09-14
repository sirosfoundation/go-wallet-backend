package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var errStoreDown = errors.New("store down")

// brokenInstanceStore is the memory store with a wallet-instance store whose
// reads and status updates fail, to drive the handlers' 500 branches.
type brokenInstanceStore struct {
	storage.Store
	failReads, failUpdates bool
}

func (b *brokenInstanceStore) WalletInstances() storage.WalletInstanceStore {
	return &brokenInstances{b.Store.WalletInstances(), b}
}

type brokenInstances struct {
	storage.WalletInstanceStore
	b *brokenInstanceStore
}

func (s *brokenInstances) GetByUser(ctx context.Context, t domain.TenantID, u domain.UserID) ([]*domain.WalletInstance, error) {
	if s.b.failReads {
		return nil, errStoreDown
	}
	return s.WalletInstanceStore.GetByUser(ctx, t, u)
}

func (s *brokenInstances) UpdateStatus(ctx context.Context, id string, st domain.InstanceStatus, reason string) error {
	if s.b.failUpdates {
		return errStoreDown
	}
	return s.WalletInstanceStore.UpdateStatus(ctx, id, st, reason)
}

func lifecycleTestConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{Host: "localhost", Port: 8080, RPID: "localhost", RPOrigin: "http://localhost:8080", RPName: "Test Wallet"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
}

func instanceRoutes(h *Handlers, mw ...gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.GET("/user/session/instances", append(mw, h.ListMyWalletInstances)...)
	r.PUT("/user/session/instances/:instance_id/status", append(mw, h.UpdateMyWalletInstanceStatus)...)
	r.POST("/user/session/instances/revoke-all", append(mw, h.RevokeAllMyWalletInstances)...)
	return r
}

func doJSON(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestMyWalletInstances_LifecycleNotSupported(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	services := service.NewServices(store, lifecycleTestConfig(), zap.NewNop())
	services.WalletLifecycle = nil
	h := NewHandlersWithStore(services, store, lifecycleTestConfig(), zap.NewNop(), []string{"test"})
	r := instanceRoutes(h, authMiddleware("user-1", "did:example:1"))

	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/user/session/instances", ""},
		{http.MethodPut, "/user/session/instances/x/status", `{"status":"suspended"}`},
		{http.MethodPost, "/user/session/instances/revoke-all", ""},
	} {
		w := doJSON(r, c.method, c.path, c.body)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "LIFECYCLE_NOT_SUPPORTED") {
			t.Errorf("%s %s: expected 503 LIFECYCLE_NOT_SUPPORTED, got %d %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
}

func TestMyWalletInstances_Unauthorized(t *testing.T) {
	handlers, _ := setupLifecycleHandlers(t)
	r := instanceRoutes(handlers) // no auth middleware: no user_id in the context

	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/user/session/instances", ""},
		{http.MethodPut, "/user/session/instances/x/status", `{"status":"suspended"}`},
		{http.MethodPost, "/user/session/instances/revoke-all", ""},
	} {
		w := doJSON(r, c.method, c.path, c.body)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: expected 401, got %d %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
}

func TestMyWalletInstances_StoreFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	broken := &brokenInstanceStore{Store: memory.NewStore()}
	services := service.NewServices(broken, lifecycleTestConfig(), zap.NewNop())
	h := NewHandlersWithStore(services, broken, lifecycleTestConfig(), zap.NewNop(), []string{"test"})
	me := domain.UserIDFromString("user-123")
	seedUserInstance(t, h, "mine-1", me)
	r := instanceRoutes(h, authMiddleware("user-123", "did:example:123"))

	// Bad body is rejected before touching the store.
	if w := doJSON(r, http.MethodPut, "/user/session/instances/mine-1/status", `{"status":"nonsense"}`); w.Code != http.StatusBadRequest {
		t.Errorf("bad status: expected 400, got %d %s", w.Code, w.Body.String())
	}

	broken.failUpdates = true
	if w := doJSON(r, http.MethodPut, "/user/session/instances/mine-1/status", `{"status":"suspended"}`); w.Code != http.StatusInternalServerError {
		t.Errorf("update with failing store: expected 500, got %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(r, http.MethodPost, "/user/session/instances/revoke-all", ""); w.Code != http.StatusInternalServerError {
		t.Errorf("revoke-all with failing store: expected 500, got %d %s", w.Code, w.Body.String())
	}

	broken.failReads = true
	if w := doJSON(r, http.MethodGet, "/user/session/instances", ""); w.Code != http.StatusInternalServerError {
		t.Errorf("list with failing store: expected 500, got %d %s", w.Code, w.Body.String())
	}
}

// The admin path through the shared lifecycle service maps a storage failure
// to 500 after the transition itself was validated.
func TestUpdateWalletInstanceStatus_LifecycleStoreFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	broken := &brokenInstanceStore{Store: memory.NewStore()}
	h := NewAdminHandlers(broken, zap.NewNop(), nil)
	h.SetLifecycle(service.NewWalletLifecycleService(broken, zap.NewNop(), nil))
	seedInstance(t, h, "inst-1", "acme", nil)

	r := gin.New()
	r.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)
	broken.failUpdates = true
	w := doJSON(r, http.MethodPut, "/admin/tenants/acme/instances/inst-1/status", `{"status":"suspended"}`)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), errMsgInstanceUpdateFailed) {
		t.Fatalf("expected 500 %q, got %d %s", errMsgInstanceUpdateFailed, w.Code, w.Body.String())
	}
}
