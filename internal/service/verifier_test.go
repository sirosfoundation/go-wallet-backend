package service

import (
	"context"
	"testing"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

func TestNewVerifierService(t *testing.T) {
	store := memory.NewStore()
	logger := zap.NewNop()

	svc := NewVerifierService(store, logger)

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

func TestVerifierService_GetAll(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	logger := zap.NewNop()
	svc := NewVerifierService(store, logger)
	tenantID := domain.DefaultTenantID

	t.Run("returns empty list when no verifiers", func(t *testing.T) {
		verifiers, err := svc.GetAll(ctx, tenantID)
		if err != nil {
			t.Fatalf("GetAll() error = %v", err)
		}
		if verifiers == nil {
			// nil is acceptable for empty result
			verifiers = []*domain.Verifier{}
		}
		if len(verifiers) != 0 {
			t.Errorf("Expected 0 verifiers, got %d", len(verifiers))
		}
	})

	t.Run("returns verifiers for tenant", func(t *testing.T) {
		// Create some verifiers
		for i := 0; i < 3; i++ {
			v := &domain.Verifier{
				TenantID: tenantID,
				Name:     "Verifier " + string(rune('A'+i)),
				URL:      "https://verifier" + string(rune('0'+i)) + ".example.com",
			}
			if err := store.Verifiers().Create(ctx, v); err != nil {
				t.Fatalf("Failed to create verifier: %v", err)
			}
		}

		verifiers, err := svc.GetAll(ctx, tenantID)
		if err != nil {
			t.Fatalf("GetAll() error = %v", err)
		}
		if len(verifiers) != 3 {
			t.Errorf("Expected 3 verifiers, got %d", len(verifiers))
		}
	})

	t.Run("isolates verifiers by tenant", func(t *testing.T) {
		// Create a different tenant
		otherTenant := domain.TenantID("other-tenant")
		tenant := &domain.Tenant{
			ID:      otherTenant,
			Name:    "other",
			Enabled: true,
		}
		if err := store.Tenants().Create(ctx, tenant); err != nil {
			t.Fatalf("Failed to create tenant: %v", err)
		}

		// Create a verifier in the other tenant
		v := &domain.Verifier{
			TenantID: otherTenant,
			Name:     "Other Verifier",
			URL:      "https://other.example.com",
		}
		if err := store.Verifiers().Create(ctx, v); err != nil {
			t.Fatalf("Failed to create verifier: %v", err)
		}

		// Should only return verifiers from other tenant
		verifiers, err := svc.GetAll(ctx, otherTenant)
		if err != nil {
			t.Fatalf("GetAll() error = %v", err)
		}
		if len(verifiers) != 1 {
			t.Errorf("Expected 1 verifier in other tenant, got %d", len(verifiers))
		}
	})
}
