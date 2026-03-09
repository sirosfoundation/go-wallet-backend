// Package engine provides WebSocket v2 protocol implementation.
package engine

import (
	"context"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// ContextWithTenant returns a context with the tenant ID set.
// Delegates to trust.ContextWithTenant so the tenant ID is propagated
// to both trust evaluation and registry client requests.
func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return trust.ContextWithTenant(ctx, tenantID)
}

// TenantFromContext extracts the tenant ID from context.
// Delegates to trust.TenantFromContext for consistent key usage.
func TenantFromContext(ctx context.Context) string {
	return trust.TenantFromContext(ctx)
}
