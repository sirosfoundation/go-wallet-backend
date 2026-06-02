// Package audit provides structured audit logging for admin API mutations.
//
// Audit events are emitted on a zap logger named "audit", enabling operators
// to configure a dedicated log sink for compliance archiving (e.g., by routing
// messages from the "audit" named logger to a separate channel).
//
// No personal information (PII) or credentials are ever included in audit log entries.
// Operator identity is represented by the client IP address only.
package audit

import (
	"go.uber.org/zap"
)

// Result constants for audit event outcomes.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Logger is a structured audit logger for admin API mutations.
// It wraps a zap.Logger named "audit" to allow independent routing
// and archival of audit events.
type Logger struct {
	logger *zap.Logger
}

// New creates a new audit Logger derived from the provided base logger.
// Audit events are emitted on a child logger named "audit".
func New(base *zap.Logger) *Logger {
	return &Logger{logger: base.Named("audit")}
}

// Event represents a structured audit log entry for an admin mutation.
// All fields must be free of PII and sensitive data.
type Event struct {
	// Operation is the admin operation performed (e.g., "tenant.create").
	Operation string
	// ResourceType is the category of resource affected (e.g., "tenant", "issuer").
	ResourceType string
	// ResourceID is the opaque identifier of the affected resource.
	ResourceID string
	// TenantID is the tenant context for the operation (empty for tenant-level ops).
	TenantID string
	// OperatorIP is the client IP address of the authenticated admin operator.
	// This serves as the operator identity since the admin API uses a static bearer token.
	OperatorIP string
	// Result is ResultSuccess or ResultFailure.
	Result string
}

// Log emits a structured audit event at Info level.
// The log message is always "admin.mutation" to enable consistent filtering.
func (l *Logger) Log(event Event) {
	fields := []zap.Field{
		zap.String("operation", event.Operation),
		zap.String("resource_type", event.ResourceType),
		zap.String("resource_id", event.ResourceID),
		zap.String("operator_ip", event.OperatorIP),
		zap.String("result", event.Result),
	}
	if event.TenantID != "" {
		fields = append(fields, zap.String("tenant_id", event.TenantID))
	}
	l.logger.Info("admin.mutation", fields...)
}
