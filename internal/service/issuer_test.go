package service

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func setupIssuerService(t *testing.T) (*IssuerService, storage.Store) {
	store := memory.NewStore()
	logger := zap.NewNop()
	return NewIssuerService(store, logger), store
}

func TestNewIssuerService(t *testing.T) {
	svc, _ := setupIssuerService(t)

	if svc == nil {
		t.Fatal("Expected non-nil service")
	}
	if svc.store == nil {
		t.Error("Expected store to be set")
	}
	if svc.logger == nil {
		t.Error("Expected logger to be set")
	}
}

func TestIssuerService_Create(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.DefaultTenantID

	t.Run("creates issuer successfully", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "https://issuer.example.com",
			ClientID:                   "client123",
			Visible:                    true,
		}

		err := svc.Create(ctx, tenantID, issuer)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		// Verify issuer was created
		retrieved, err := svc.Get(ctx, tenantID, issuer.CredentialIssuerIdentifier)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if retrieved.CredentialIssuerIdentifier != issuer.CredentialIssuerIdentifier {
			t.Errorf("Expected identifier %s, got %s", issuer.CredentialIssuerIdentifier, retrieved.CredentialIssuerIdentifier)
		}
	})

	t.Run("returns error for empty identifier", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "",
			ClientID:                   "client123",
		}

		err := svc.Create(ctx, tenantID, issuer)
		if err == nil {
			t.Error("Expected error for empty identifier")
		}
	})

	t.Run("returns error for duplicate issuer", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "https://issuer.example.com",
			ClientID:                   "client123",
		}

		err := svc.Create(ctx, tenantID, issuer)
		if err != nil {
			t.Fatalf("First Create() error = %v", err)
		}

		// Try to create again
		issuer2 := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "https://issuer.example.com",
			ClientID:                   "client456",
		}
		err = svc.Create(ctx, tenantID, issuer2)
		if err == nil {
			t.Error("Expected error for duplicate issuer")
		}
	})

	t.Run("sets tenant ID on issuer", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "https://tenant-issuer.example.com",
			ClientID:                   "client123",
		}

		err := svc.Create(ctx, tenantID, issuer)
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		if issuer.TenantID != tenantID {
			t.Errorf("Expected tenant ID %s, got %s", tenantID, issuer.TenantID)
		}
	})
}

func TestIssuerService_Get(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.DefaultTenantID

	t.Run("returns issuer by identifier", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "https://issuer.example.com",
			ClientID:                   "client123",
			Visible:                    true,
		}
		if err := svc.Create(ctx, tenantID, issuer); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		retrieved, err := svc.Get(ctx, tenantID, issuer.CredentialIssuerIdentifier)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if retrieved.ClientID != issuer.ClientID {
			t.Errorf("Expected client ID %s, got %s", issuer.ClientID, retrieved.ClientID)
		}
	})

	t.Run("returns ErrNotFound for nonexistent issuer", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		_, err := svc.Get(ctx, tenantID, "https://nonexistent.example.com")
		if err != storage.ErrNotFound {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}
	})
}

func TestIssuerService_GetByID(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.DefaultTenantID

	t.Run("returns issuer by ID", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "https://issuer.example.com",
			ClientID:                   "client123",
		}
		if err := svc.Create(ctx, tenantID, issuer); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		retrieved, err := svc.GetByID(ctx, tenantID, issuer.ID)
		if err != nil {
			t.Fatalf("GetByID() error = %v", err)
		}
		if retrieved.CredentialIssuerIdentifier != issuer.CredentialIssuerIdentifier {
			t.Errorf("Expected identifier %s, got %s", issuer.CredentialIssuerIdentifier, retrieved.CredentialIssuerIdentifier)
		}
	})

	t.Run("returns ErrNotFound for nonexistent ID", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		_, err := svc.GetByID(ctx, tenantID, 99999)
		if err != storage.ErrNotFound {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}
	})
}

func TestIssuerService_GetAll(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.DefaultTenantID

	t.Run("returns empty list when no issuers", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuers, err := svc.GetAll(ctx, tenantID)
		if err != nil {
			t.Fatalf("GetAll() error = %v", err)
		}
		if issuers == nil {
			issuers = []*domain.CredentialIssuer{}
		}
		if len(issuers) != 0 {
			t.Errorf("Expected 0 issuers, got %d", len(issuers))
		}
	})

	t.Run("returns all issuers for tenant", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		for i := 0; i < 3; i++ {
			issuer := &domain.CredentialIssuer{
				CredentialIssuerIdentifier: "https://issuer" + string(rune('0'+i)) + ".example.com",
				ClientID:                   "client" + string(rune('0'+i)),
			}
			if err := svc.Create(ctx, tenantID, issuer); err != nil {
				t.Fatalf("Create() error = %v", err)
			}
		}

		issuers, err := svc.GetAll(ctx, tenantID)
		if err != nil {
			t.Fatalf("GetAll() error = %v", err)
		}
		if len(issuers) != 3 {
			t.Errorf("Expected 3 issuers, got %d", len(issuers))
		}
	})
}

func TestIssuerService_Update(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.DefaultTenantID

	t.Run("updates issuer successfully", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "https://issuer.example.com",
			ClientID:                   "original-client",
			Visible:                    false,
		}
		if err := svc.Create(ctx, tenantID, issuer); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		// Update the issuer
		issuer.ClientID = "updated-client"
		issuer.Visible = true
		if err := svc.Update(ctx, issuer); err != nil {
			t.Fatalf("Update() error = %v", err)
		}

		// Verify update
		retrieved, err := svc.GetByID(ctx, tenantID, issuer.ID)
		if err != nil {
			t.Fatalf("GetByID() error = %v", err)
		}
		if retrieved.ClientID != "updated-client" {
			t.Errorf("Expected client ID updated-client, got %s", retrieved.ClientID)
		}
		if !retrieved.Visible {
			t.Error("Expected Visible to be true")
		}
	})

	t.Run("returns ErrNotFound for nonexistent issuer", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			ID:                         99999,
			CredentialIssuerIdentifier: "https://nonexistent.example.com",
		}
		err := svc.Update(ctx, issuer)
		if err != storage.ErrNotFound {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}
	})
}

func TestIssuerService_Delete(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.DefaultTenantID

	t.Run("deletes issuer successfully", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		issuer := &domain.CredentialIssuer{
			CredentialIssuerIdentifier: "https://issuer.example.com",
			ClientID:                   "client123",
		}
		if err := svc.Create(ctx, tenantID, issuer); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		if err := svc.Delete(ctx, tenantID, issuer.ID); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}

		// Verify deletion
		_, err := svc.GetByID(ctx, tenantID, issuer.ID)
		if err != storage.ErrNotFound {
			t.Error("Expected issuer to be deleted")
		}
	})

	t.Run("returns ErrNotFound for nonexistent issuer", func(t *testing.T) {
		svc, _ := setupIssuerService(t)

		err := svc.Delete(ctx, tenantID, 99999)
		if err != storage.ErrNotFound {
			t.Errorf("Expected ErrNotFound, got %v", err)
		}
	})
}
