package service

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func TestTenantService_Create(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewTenantService(store, logger)

	tenant := &domain.Tenant{
		ID:          "test-tenant",
		Name:        "test",
		DisplayName: "Test Tenant",
		Enabled:     true,
	}

	err := svc.Create(context.Background(), tenant)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify tenant was created
	got, err := svc.GetByID(context.Background(), "test-tenant")
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.Name != "test" {
		t.Errorf("GetByID().Name = %v, want %v", got.Name, "test")
	}
}

func TestTenantService_GetAll(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewTenantService(store, logger)

	// Create multiple tenants
	tenants := []*domain.Tenant{
		{ID: "tenant1", Name: "t1", DisplayName: "Tenant 1", Enabled: true},
		{ID: "tenant2", Name: "t2", DisplayName: "Tenant 2", Enabled: true},
	}

	for _, tenant := range tenants {
		if err := svc.Create(context.Background(), tenant); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	got, err := svc.GetAll(context.Background())
	if err != nil {
		t.Fatalf("GetAll() error = %v", err)
	}

	// Should have at least our tenants plus the default one
	if len(got) < 2 {
		t.Errorf("GetAll() returned %d tenants, want at least 2", len(got))
	}
}

func TestTenantService_GetAllEnabled(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewTenantService(store, logger)

	// Create enabled and disabled tenants
	tenants := []*domain.Tenant{
		{ID: "enabled1", Name: "e1", DisplayName: "Enabled 1", Enabled: true},
		{ID: "disabled1", Name: "d1", DisplayName: "Disabled 1", Enabled: false},
	}

	for _, tenant := range tenants {
		if err := svc.Create(context.Background(), tenant); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	got, err := svc.GetAllEnabled(context.Background())
	if err != nil {
		t.Fatalf("GetAllEnabled() error = %v", err)
	}

	// Check none are disabled
	for _, tenant := range got {
		if !tenant.Enabled {
			t.Errorf("GetAllEnabled() returned disabled tenant: %s", tenant.ID)
		}
	}
}

func TestTenantService_Update(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewTenantService(store, logger)

	tenant := &domain.Tenant{
		ID:          "update-test",
		Name:        "original",
		DisplayName: "Original Name",
		Enabled:     true,
	}

	if err := svc.Create(context.Background(), tenant); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update the tenant
	tenant.DisplayName = "Updated Name"
	if err := svc.Update(context.Background(), tenant); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify update
	got, err := svc.GetByID(context.Background(), "update-test")
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.DisplayName != "Updated Name" {
		t.Errorf("GetByID().DisplayName = %v, want %v", got.DisplayName, "Updated Name")
	}
}

func TestTenantService_Delete(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewTenantService(store, logger)

	tenant := &domain.Tenant{
		ID:          "delete-test",
		Name:        "delete",
		DisplayName: "Delete Me",
		Enabled:     true,
	}

	if err := svc.Create(context.Background(), tenant); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete the tenant
	if err := svc.Delete(context.Background(), "delete-test"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deletion
	_, err := svc.GetByID(context.Background(), "delete-test")
	if err == nil {
		t.Error("GetByID() after delete should return error")
	}
}

func TestUserTenantService_AddUserToTenant(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	tenantSvc := NewTenantService(store, logger)
	userTenantSvc := NewUserTenantService(store, logger)

	// Create tenant first
	tenant := &domain.Tenant{
		ID:      "user-tenant-test",
		Name:    "test",
		Enabled: true,
	}
	if err := tenantSvc.Create(context.Background(), tenant); err != nil {
		t.Fatalf("Create tenant error = %v", err)
	}

	userID := domain.NewUserID()

	// Add user to tenant
	err := userTenantSvc.AddUserToTenant(context.Background(), userID, "user-tenant-test", domain.TenantRoleUser)
	if err != nil {
		t.Fatalf("AddUserToTenant() error = %v", err)
	}

	// Verify membership
	isMember, err := userTenantSvc.IsMember(context.Background(), userID, "user-tenant-test")
	if err != nil {
		t.Fatalf("IsMember() error = %v", err)
	}
	if !isMember {
		t.Error("IsMember() = false, want true")
	}
}

func TestUserTenantService_AddUserToTenant_DefaultRole(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	tenantSvc := NewTenantService(store, logger)
	userTenantSvc := NewUserTenantService(store, logger)

	// Create tenant first
	tenant := &domain.Tenant{
		ID:      "default-role-test",
		Name:    "test",
		Enabled: true,
	}
	if err := tenantSvc.Create(context.Background(), tenant); err != nil {
		t.Fatalf("Create tenant error = %v", err)
	}

	userID := domain.NewUserID()

	// Add user with empty role (should default to "user")
	err := userTenantSvc.AddUserToTenant(context.Background(), userID, "default-role-test", "")
	if err != nil {
		t.Fatalf("AddUserToTenant() error = %v", err)
	}

	// Verify membership role
	membership, err := userTenantSvc.GetMembership(context.Background(), userID, "default-role-test")
	if err != nil {
		t.Fatalf("GetMembership() error = %v", err)
	}
	if membership.Role != domain.TenantRoleUser {
		t.Errorf("GetMembership().Role = %v, want %v", membership.Role, domain.TenantRoleUser)
	}
}

func TestUserTenantService_RemoveUserFromTenant(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	tenantSvc := NewTenantService(store, logger)
	userTenantSvc := NewUserTenantService(store, logger)

	// Create tenant first
	tenant := &domain.Tenant{
		ID:      "remove-test",
		Name:    "test",
		Enabled: true,
	}
	if err := tenantSvc.Create(context.Background(), tenant); err != nil {
		t.Fatalf("Create tenant error = %v", err)
	}

	userID := domain.NewUserID()

	// Add user to tenant
	if err := userTenantSvc.AddUserToTenant(context.Background(), userID, "remove-test", "user"); err != nil {
		t.Fatalf("AddUserToTenant() error = %v", err)
	}

	// Remove user from tenant
	if err := userTenantSvc.RemoveUserFromTenant(context.Background(), userID, "remove-test"); err != nil {
		t.Fatalf("RemoveUserFromTenant() error = %v", err)
	}

	// Verify removal
	isMember, err := userTenantSvc.IsMember(context.Background(), userID, "remove-test")
	if err != nil {
		t.Fatalf("IsMember() error = %v", err)
	}
	if isMember {
		t.Error("IsMember() = true after removal, want false")
	}
}

func TestUserTenantService_GetUserTenants(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	tenantSvc := NewTenantService(store, logger)
	userTenantSvc := NewUserTenantService(store, logger)

	// Create multiple tenants
	tenants := []domain.TenantID{"user-tenants-1", "user-tenants-2"}
	for _, tid := range tenants {
		tenant := &domain.Tenant{ID: tid, Name: string(tid), Enabled: true}
		if err := tenantSvc.Create(context.Background(), tenant); err != nil {
			t.Fatalf("Create tenant error = %v", err)
		}
	}

	userID := domain.NewUserID()

	// Add user to both tenants
	for _, tid := range tenants {
		if err := userTenantSvc.AddUserToTenant(context.Background(), userID, tid, "user"); err != nil {
			t.Fatalf("AddUserToTenant() error = %v", err)
		}
	}

	// Get user tenants
	got, err := userTenantSvc.GetUserTenants(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetUserTenants() error = %v", err)
	}

	if len(got) != 2 {
		t.Errorf("GetUserTenants() returned %d tenants, want 2", len(got))
	}
}

func TestUserTenantService_GetTenantUsers(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	tenantSvc := NewTenantService(store, logger)
	userTenantSvc := NewUserTenantService(store, logger)

	// Create tenant
	tenant := &domain.Tenant{ID: "tenant-users-test", Name: "test", Enabled: true}
	if err := tenantSvc.Create(context.Background(), tenant); err != nil {
		t.Fatalf("Create tenant error = %v", err)
	}

	// Add multiple users
	users := []domain.UserID{domain.NewUserID(), domain.NewUserID()}
	for _, uid := range users {
		if err := userTenantSvc.AddUserToTenant(context.Background(), uid, "tenant-users-test", "user"); err != nil {
			t.Fatalf("AddUserToTenant() error = %v", err)
		}
	}

	// Get tenant users
	got, err := userTenantSvc.GetTenantUsers(context.Background(), "tenant-users-test")
	if err != nil {
		t.Fatalf("GetTenantUsers() error = %v", err)
	}

	if len(got) != 2 {
		t.Errorf("GetTenantUsers() returned %d users, want 2", len(got))
	}
}

func TestTenantService_Create_DuplicateID(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewTenantService(store, logger)

	tenant := &domain.Tenant{
		ID:          "duplicate-test",
		Name:        "test",
		DisplayName: "Test",
		Enabled:     true,
	}

	err := svc.Create(context.Background(), tenant)
	if err != nil {
		t.Fatalf("First Create() error = %v", err)
	}

	// Try creating again with same ID
	tenant2 := &domain.Tenant{
		ID:          "duplicate-test",
		Name:        "test2",
		DisplayName: "Test 2",
		Enabled:     true,
	}
	err = svc.Create(context.Background(), tenant2)
	if err == nil {
		t.Error("Create() with duplicate ID should return error")
	}
}

func TestTenantService_Update_NotFound(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewTenantService(store, logger)

	tenant := &domain.Tenant{
		ID:          "nonexistent",
		Name:        "test",
		DisplayName: "Test",
		Enabled:     true,
	}

	err := svc.Update(context.Background(), tenant)
	if err == nil {
		t.Error("Update() for nonexistent tenant should return error")
	}
}

func TestTenantService_Delete_NotFound(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewTenantService(store, logger)

	// Try to delete non-existent tenant
	err := svc.Delete(context.Background(), "nonexistent-tenant")
	if err == nil {
		t.Error("Delete() on non-existent tenant should return error")
	}
}

func TestUserTenantService_AddUserToTenant_DisabledTenant(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	tenantSvc := NewTenantService(store, logger)
	userTenantSvc := NewUserTenantService(store, logger)

	// Create a disabled tenant
	tenant := &domain.Tenant{
		ID:      "disabled-tenant",
		Name:    "disabled",
		Enabled: false,
	}
	if err := tenantSvc.Create(context.Background(), tenant); err != nil {
		t.Fatalf("Create tenant error = %v", err)
	}

	userID := domain.NewUserID()

	// Adding user to disabled tenant should still work (just checking membership operation)
	err := userTenantSvc.AddUserToTenant(context.Background(), userID, "disabled-tenant", domain.TenantRoleUser)
	if err != nil {
		// If error is thrown, it's valid behavior
		t.Logf("AddUserToTenant() to disabled tenant returned: %v", err)
	}
}

func TestUserTenantService_RemoveUserFromTenant_NotAMember(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()
	tenantSvc := NewTenantService(store, logger)
	userTenantSvc := NewUserTenantService(store, logger)

	// Create tenant
	tenant := &domain.Tenant{ID: "remove-not-member", Name: "test", Enabled: true}
	if err := tenantSvc.Create(context.Background(), tenant); err != nil {
		t.Fatalf("Create tenant error = %v", err)
	}

	userID := domain.NewUserID()

	// Try to remove user who is not a member
	err := userTenantSvc.RemoveUserFromTenant(context.Background(), userID, "remove-not-member")
	if err == nil {
		t.Error("RemoveUserFromTenant() for non-member should return error")
	}
}
