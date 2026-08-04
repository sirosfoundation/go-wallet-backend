package api

import (
	"encoding/json"
	"errors"
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
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
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
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
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

func TestGetUserDetail_MemberButUserRecordMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/detail", h.GetUserDetail)

	tenant := &domain.Tenant{ID: "acme", Name: "Acme Corp"}
	if err := store.Tenants().Create(nil, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// Membership exists but no corresponding user record in the Users() store.
	userID := domain.NewUserID()
	membership := &domain.UserTenantMembership{
		UserID:   userID,
		TenantID: "acme",
		Role:     "user",
	}
	if err := store.UserTenants().AddMembership(nil, membership); err != nil {
		t.Fatalf("add membership: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/users/"+userID.String()+"/detail", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetUserDetail_NonDidKeyDIDNotExposed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/detail", h.GetUserDetail)

	tenant := &domain.Tenant{ID: "acme", Name: "Acme Corp"}
	if err := store.Tenants().Create(nil, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// DID is a did:web (not did:key), which is considered PII and must not
	// be exposed to admins.
	user := &domain.User{
		UUID:       domain.NewUserID(),
		DID:        "did:web:example.com",
		WalletType: "web",
	}
	if err := store.Users().Create(nil, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

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
	if resp.DID != "" {
		t.Errorf("expected DID to be withheld for non-did:key DID, got %q", resp.DID)
	}
}

func TestGetUserDetail_PasskeysFilteredByTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/detail", h.GetUserDetail)

	for _, id := range []domain.TenantID{"acme", "other"} {
		tenant := &domain.Tenant{ID: id, Name: string(id)}
		if err := store.Tenants().Create(nil, tenant); err != nil {
			t.Fatalf("create tenant %s: %v", id, err)
		}
	}

	nickname := "my passkey"
	user := &domain.User{
		UUID:       domain.NewUserID(),
		DID:        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		WalletType: "web",
		WebauthnCredentials: []domain.WebauthnCredential{
			{
				ID:              "cred-acme",
				TenantID:        "acme",
				CredentialID:    []byte{0x01, 0x02, 0x03},
				AttestationType: "none",
				Transport:       []string{"internal"},
				PRFCapable:      true,
				Nickname:        &nickname,
				Authenticator:   domain.Authenticator{SignCount: 7},
			},
			{
				ID:              "cred-other",
				TenantID:        "other",
				CredentialID:    []byte{0x04, 0x05, 0x06},
				AttestationType: "none",
				Authenticator:   domain.Authenticator{SignCount: 1},
			},
		},
	}
	if err := store.Users().Create(nil, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

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
	if len(resp.Passkeys) != 1 {
		t.Fatalf("expected 1 passkey scoped to tenant 'acme', got %d", len(resp.Passkeys))
	}
	pk := resp.Passkeys[0]
	if pk.ID != "cred-acme" {
		t.Errorf("expected passkey id 'cred-acme', got %q", pk.ID)
	}
	if pk.TenantID != "acme" {
		t.Errorf("expected passkey tenant_id 'acme', got %q", pk.TenantID)
	}
	if pk.SignCount != 7 {
		t.Errorf("expected sign_count 7, got %d", pk.SignCount)
	}
	if pk.Nickname == nil || *pk.Nickname != nickname {
		t.Errorf("expected nickname %q, got %v", nickname, pk.Nickname)
	}
}

func TestGetUserDetail_IsMemberStoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := memory.NewStore()
	store := &errStore{
		Store:       base,
		userTenants: &errUserTenantStore{UserTenantStore: base.UserTenants(), isMemberErr: errors.New("boom")},
	}
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/detail", h.GetUserDetail)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/users/user-1/detail", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetUserDetail_UsersGetByIDStoreError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	base := memory.NewStore()
	tenant := &domain.Tenant{ID: "acme", Name: "Acme Corp"}
	if err := base.Tenants().Create(nil, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	userID := domain.NewUserID()
	membership := &domain.UserTenantMembership{
		UserID:   userID,
		TenantID: "acme",
		Role:     "user",
	}
	if err := base.UserTenants().AddMembership(nil, membership); err != nil {
		t.Fatalf("add membership: %v", err)
	}

	store := &errStore{
		Store: base,
		users: &errUserStore{UserStore: base.Users(), getByIDErr: errors.New("boom")},
	}
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/users/:user_id/detail", h.GetUserDetail)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/users/"+userID.String()+"/detail", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetTenantStats_NotImplemented(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := memory.NewStore()
	h := NewAdminHandlers(store, zap.NewNop(), nil, nil)
	router := gin.New()
	router.GET("/admin/tenants/:id/stats", h.GetTenantStats)

	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/acme/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", w.Code)
	}
}
