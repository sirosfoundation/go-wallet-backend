package engine

import (
	"context"
	"testing"
)

func TestContextWithTenant(t *testing.T) {
	ctx := context.Background()
	tenantID := "test-tenant"

	newCtx := ContextWithTenant(ctx, tenantID)
	if newCtx == nil {
		t.Fatal("ContextWithTenant() returned nil context")
	}

	// Verify the tenant ID is set
	got := TenantFromContext(newCtx)
	if got != tenantID {
		t.Errorf("TenantFromContext() = %q, want %q", got, tenantID)
	}
}

func TestTenantFromContext_Empty(t *testing.T) {
	ctx := context.Background()

	got := TenantFromContext(ctx)
	if got != "" {
		t.Errorf("TenantFromContext() on empty context = %q, want empty", got)
	}
}

func TestContextWithTenant_Override(t *testing.T) {
	ctx := context.Background()

	// Set first tenant
	ctx = ContextWithTenant(ctx, "tenant1")

	// Override with second tenant
	ctx = ContextWithTenant(ctx, "tenant2")

	got := TenantFromContext(ctx)
	if got != "tenant2" {
		t.Errorf("TenantFromContext() after override = %q, want %q", got, "tenant2")
	}
}
