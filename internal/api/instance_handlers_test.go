package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/internal/tokengate"
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

// A user sees their own instances and nobody else's. Listing is all the
// self-service surface does with them: changing a status is a provider
// action (SID-AUTH-06), because it is reversible only by a provider.
func TestListMyWalletInstances_OnlyMine(t *testing.T) {
	handlers, _ := setupLifecycleHandlers(t)
	me := domain.UserIDFromString("user-123")
	other := domain.UserIDFromString("user-456")
	seedUserInstance(t, handlers, "mine-1", me)
	seedUserInstance(t, handlers, "mine-2", me)
	seedUserInstance(t, handlers, "theirs", other)

	r := instanceRoutes(handlers, authMiddleware("user-123", "did:example:123"))
	w := doJSON(r, http.MethodGet, "/user/session/instances", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Instances []domain.WalletInstance `json:"instances"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Instances) != 2 {
		t.Fatalf("expected my two instances, got %d", len(body.Instances))
	}
	for _, inst := range body.Instances {
		if inst.ID == "theirs" {
			t.Fatal("another user's instance must not be listed")
		}
	}
}

// The self-service routes no longer offer a status change or a revoke-all:
// a user who revoked the instance behind their last passkey
// could not undo it without an administrator. What a user can do to
// themselves is log out everywhere, which a new login undoes, and remove the
// account, which is meant to be final.
func TestSelfServiceOffersNoInstanceStatusChange(t *testing.T) {
	handlers, _ := setupLifecycleHandlers(t)
	r := instanceRoutes(handlers, authMiddleware("user-123", "did:example:123"))

	for _, c := range []struct{ method, path string }{
		{http.MethodPut, "/user/session/instances/mine-1/status"},
		{http.MethodPost, "/user/session/instances/revoke-all"},
	} {
		w := doJSON(r, c.method, c.path, `{"status":"revoked"}`)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s: expected the route to be gone (404), got %d", c.method, c.path, w.Code)
		}
	}
}

// Logging out everywhere ends the user's sessions and refuses the tokens
// already issued to them, including the one that asked.
func TestLogoutEverywhere(t *testing.T) {
	handlers, _ := setupLifecycleHandlers(t)
	ctx := context.Background()
	me := domain.NewUserID()
	if err := handlers.store.Users().Create(ctx, &domain.User{UUID: me, PrivateData: []byte("vault")}); err != nil {
		t.Fatal(err)
	}
	cleaner := &recordingCleaner{}
	handlers.services.User.SetSessionCleaner(cleaner)

	r := instanceRoutes(handlers, authMiddleware(me.String(), "did:example:1"))
	w := doJSON(r, http.MethodPost, "/user/session/logout-all", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout-all: %d %s", w.Code, w.Body.String())
	}
	if len(cleaner.users) != 1 || cleaner.users[0] != me.String() {
		t.Fatalf("the user's sessions must be dropped, got %v", cleaner.users)
	}

	gate := tokengate.New(handlers.store.Users())
	issued := time.Now().Add(-time.Minute)
	if err := gate.Check(ctx, me.String(), issued); err == nil {
		t.Fatal("a token issued before the logout must be refused afterwards")
	}
	if err := gate.Check(ctx, me.String(), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("a token issued after it must still work: %v", err)
	}

	// Nothing is erased: logging in again restores the account as it was.
	user, err := handlers.store.Users().GetByID(ctx, me)
	if err != nil {
		t.Fatal(err)
	}
	if user.PrivateData == nil {
		t.Fatal("logging out everywhere must not erase the wallet data")
	}
}

func TestLogoutEverywhere_Unauthorized(t *testing.T) {
	handlers, _ := setupLifecycleHandlers(t)
	r := instanceRoutes(handlers) // no auth middleware
	if w := doJSON(r, http.MethodPost, "/user/session/logout-all", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestLogoutEverywhere_UnknownUser(t *testing.T) {
	handlers, _ := setupLifecycleHandlers(t)
	r := instanceRoutes(handlers, authMiddleware(domain.NewUserID().String(), "did:example:gone"))
	if w := doJSON(r, http.MethodPost, "/user/session/logout-all", ""); w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

type recordingCleaner struct{ users []string }

func (r *recordingCleaner) DeleteByUser(_ context.Context, userID string) error {
	r.users = append(r.users, userID)
	return nil
}

var _ service.SessionCleaner = (*recordingCleaner)(nil)
