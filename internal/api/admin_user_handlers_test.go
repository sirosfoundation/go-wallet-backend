package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func TestGetUserDetail_NotMember(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/detail", h.GetUserDetail)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/users/nonexistent/detail", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetUserDetail_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/detail", h.GetUserDetail)

	// Create tenant
	tenant := &domain.Tenant{ID: "acme", Name: "Acme Corp"}
	if err := store.Tenants().Create(nil, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// Create user
	user := &domain.User{
		UUID:       domain.NewUserID(),
		DID:        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		WalletType: "web",
	}
	if err := store.Users().Create(nil, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Add membership
	membership := &domain.UserTenantMembership{
		UserID:   user.UUID,
		TenantID: "acme",
		Role:     "user",
	}
	if err := store.UserTenants().AddMembership(nil, membership); err != nil {
		t.Fatalf("add membership: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/users/"+user.UUID.String()+"/detail", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp UserDetailResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.UUID != user.UUID.String() {
		t.Errorf("expected UUID %s, got %s", user.UUID.String(), resp.UUID)
	}
	if resp.DID != user.DID {
		t.Errorf("expected DID %s, got %s", user.DID, resp.DID)
	}
}

func TestGetTenantStats_NotImplemented(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop())
	router := gin.New()
	router.GET("/admin/tenants/:id/stats", h.GetTenantStats)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", w.Code)
	}
}
