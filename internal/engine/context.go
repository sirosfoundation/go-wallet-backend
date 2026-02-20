// Package engine provides WebSocket v2 protocol implementation.
package engine

import "context"

// Context keys for tenant propagation
type contextKey string

const (
	// TenantIDKey is the context key for tenant ID
	TenantIDKey contextKey = "tenant_id"
)

// ContextWithTenant returns a context with the tenant ID set.
func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}

// TenantFromContext extracts the tenant ID from context.
func TenantFromContext(ctx context.Context) string {
	if tenantID, ok := ctx.Value(TenantIDKey).(string); ok {
		return tenantID
	}
	return ""
}
