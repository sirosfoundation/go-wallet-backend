package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	failReads, failUpdates, failEraseWalletData bool
}

func (b *brokenInstanceStore) Users() storage.UserStore { return &brokenUsers{b.Store.Users(), b} }

type brokenUsers struct {
	storage.UserStore
	b *brokenInstanceStore
}

func (u *brokenUsers) EraseWalletData(ctx context.Context, id domain.UserID, fence time.Time) error {
	if u.b.failEraseWalletData {
		return errStoreDown
	}
	return u.UserStore.EraseWalletData(ctx, id, fence)
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
	r.POST("/user/session/logout-all", append(mw, h.LogoutEverywhere)...)
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

func TestUpdateWalletInstanceStatus_LifecycleStoreFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	broken := &brokenInstanceStore{Store: memory.NewStore()}
	h := NewAdminHandlers(broken, zap.NewNop(), nil)
	h.SetLifecycle(service.NewWalletLifecycleService(broken, zap.NewNop(), nil))
	seedInstance(t, h, "inst-1", "acme", nil)

	r := gin.New()
	r.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)
	broken.failUpdates = true
	w := doJSON(r, http.MethodPut, "/admin/tenants/acme/instances/inst-1/status", `{"status":"revoked"}`)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), errMsgInstanceUpdateFailed) {
		t.Fatalf("expected 500 %q, got %d %s", errMsgInstanceUpdateFailed, w.Code, w.Body.String())
	}
}

func TestUpdateWalletInstanceStatus_LifecycleErasureIncompleteIs409(t *testing.T) {
	gin.SetMode(gin.TestMode)
	broken := &brokenInstanceStore{Store: memory.NewStore()}
	h := NewAdminHandlers(broken, zap.NewNop(), nil)
	h.SetLifecycle(service.NewWalletLifecycleService(broken, zap.NewNop(), nil))
	userID := domain.NewUserID()
	if err := broken.Store.Users().Create(context.Background(), &domain.User{UUID: userID, PrivateData: []byte("vault")}); err != nil {
		t.Fatal(err)
	}
	seedInstance(t, h, "inst-1", "acme", &userID)

	r := gin.New()
	r.PUT("/admin/tenants/:id/instances/:instance_id/status", h.UpdateWalletInstanceStatus)
	broken.failEraseWalletData = true
	w := doJSON(r, http.MethodPut, "/admin/tenants/acme/instances/inst-1/status", `{"status":"revoked","reason":"compromised"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), errCodeErasureIncomplete) {
		t.Fatalf("expected 409 %s, got %d %s", errCodeErasureIncomplete, w.Code, w.Body.String())
	}
	inst, err := broken.Store.WalletInstances().GetByID(context.Background(), "inst-1")
	if err != nil || inst.Status != domain.InstanceStatusRevoked {
		t.Fatalf("the revocation itself must be persisted: %v %v", err, inst)
	}
}
