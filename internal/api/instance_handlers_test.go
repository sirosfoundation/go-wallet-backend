package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// setupLifecycleHandlers is setupTestHandlers with the store exposed on the
// Handlers (NewHandlersWithStore) so the test can seed instances directly.
func setupLifecycleHandlers(t *testing.T) (*Handlers, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	logger := zap.NewNop()
	cfg := &config.Config{
		Server: config.ServerConfig{Host: "localhost", Port: 8080, RPID: "localhost", RPOrigin: "http://localhost:8080", RPName: "Test Wallet"},
		JWT:    config.JWTConfig{Secret: "test-secret", ExpiryHours: 24, Issuer: "test-wallet"},
	}
	store := memory.NewStore()
	services := service.NewServices(store, cfg, logger)
	return NewHandlersWithStore(services, store, cfg, logger, []string{"test"}), gin.New()
}

func seedUserInstance(t *testing.T, h *Handlers, id string, userID domain.UserID) {
	t.Helper()
	if err := h.store.WalletInstances().Upsert(context.Background(), &domain.WalletInstance{
		ID: id, TenantID: domain.DefaultTenantID, UserID: &userID, Status: domain.InstanceStatusActive,
	}); err != nil {
		t.Fatalf("seed instance: %v", err)
	}
}

func TestMyWalletInstances_ListUpdateRevokeAll(t *testing.T) {
	handlers, router := setupLifecycleHandlers(t)
	me := domain.UserIDFromString("user-123")
	other := domain.UserIDFromString("user-456")
	if err := handlers.store.Users().Create(context.Background(), &domain.User{UUID: me, PrivateData: []byte("vault")}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	seedUserInstance(t, handlers, "mine-1", me)
	seedUserInstance(t, handlers, "mine-2", me)
	seedUserInstance(t, handlers, "theirs", other)

	auth := authMiddleware("user-123", "did:example:123")
	router.GET("/user/session/instances", auth, handlers.ListMyWalletInstances)
	router.PUT("/user/session/instances/:instance_id/status", auth, handlers.UpdateMyWalletInstanceStatus)
	router.POST("/user/session/instances/revoke-all", auth, handlers.RevokeAllMyWalletInstances)

	// List: only my instances.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/user/session/instances", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var listed struct {
		Instances []domain.WalletInstance `json:"instances"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Instances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(listed.Instances))
	}

	// Suspend my own instance.
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/user/session/instances/mine-1/status", strings.NewReader(`{"status":"suspended","reason":"lost"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"suspended"`) {
		t.Fatalf("suspend: %d %s", w.Code, w.Body.String())
	}

	// Someone else's instance reads as not found.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/user/session/instances/theirs/status", strings.NewReader(`{"status":"revoked"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("not owned: expected 404, got %d %s", w.Code, w.Body.String())
	}

	// Invalid status value is a 400.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/user/session/instances/mine-1/status", strings.NewReader(`{"status":"deleted"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad status: expected 400, got %d", w.Code)
	}

	// Deactivate the wallet: everything of mine revoked, data erased, theirs untouched.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/user/session/instances/revoke-all", strings.NewReader(`{"reason":"device stolen"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"revoked":2`) {
		t.Fatalf("revoke-all: %d %s", w.Code, w.Body.String())
	}
	user, err := handlers.store.Users().GetByID(context.Background(), me)
	if err != nil {
		t.Fatal(err)
	}
	if user.PrivateData != nil {
		t.Errorf("private data must be erased once every instance is revoked")
	}
	theirs, err := handlers.store.WalletInstances().GetByID(context.Background(), "theirs")
	if err != nil || theirs.Status != domain.InstanceStatusActive {
		t.Errorf("another user's instance must be untouched: %v %v", err, theirs)
	}

	// Revoked is terminal.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/user/session/instances/mine-1/status", strings.NewReader(`{"status":"active"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("reactivate revoked: expected 409, got %d %s", w.Code, w.Body.String())
	}
}
