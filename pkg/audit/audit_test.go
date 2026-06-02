package audit_test

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
)

func newObservedAuditLogger() (*audit.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.InfoLevel)
	base := zap.New(core)
	return audit.New(base), logs
}

func TestNew(t *testing.T) {
	base := zap.NewNop()
	l := audit.New(base)
	if l == nil {
		t.Fatal("New() returned nil")
	}
}

func TestLog_Success(t *testing.T) {
	l, logs := newObservedAuditLogger()

	l.Log(audit.Event{
		Operation:    "tenant.create",
		ResourceType: "tenant",
		ResourceID:   "my-tenant",
		TenantID:     "",
		OperatorIP:   "10.0.0.1",
		Result:       audit.ResultSuccess,
	})

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	entry := logs.All()[0]
	if entry.Message != "admin.mutation" {
		t.Errorf("Expected message %q, got %q", "admin.mutation", entry.Message)
	}

	fields := entry.ContextMap()
	assertField(t, fields, "operation", "tenant.create")
	assertField(t, fields, "resource_type", "tenant")
	assertField(t, fields, "resource_id", "my-tenant")
	assertField(t, fields, "operator_ip", "10.0.0.1")
	assertField(t, fields, "result", audit.ResultSuccess)
}

func TestLog_Failure(t *testing.T) {
	l, logs := newObservedAuditLogger()

	l.Log(audit.Event{
		Operation:    "tenant.delete",
		ResourceType: "tenant",
		ResourceID:   "some-tenant",
		OperatorIP:   "192.168.1.5",
		Result:       audit.ResultFailure,
	})

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	entry := logs.All()[0]
	fields := entry.ContextMap()
	assertField(t, fields, "result", audit.ResultFailure)
}

func TestLog_WithTenantID(t *testing.T) {
	l, logs := newObservedAuditLogger()

	l.Log(audit.Event{
		Operation:    "issuer.create",
		ResourceType: "issuer",
		ResourceID:   "42",
		TenantID:     "acme",
		OperatorIP:   "10.1.2.3",
		Result:       audit.ResultSuccess,
	})

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	fields := logs.All()[0].ContextMap()
	assertField(t, fields, "tenant_id", "acme")
	assertField(t, fields, "resource_id", "42")
}

func TestLog_WithoutTenantID_NoTenantIDField(t *testing.T) {
	l, logs := newObservedAuditLogger()

	l.Log(audit.Event{
		Operation:    "tenant.create",
		ResourceType: "tenant",
		ResourceID:   "new-tenant",
		TenantID:     "",
		OperatorIP:   "10.0.0.1",
		Result:       audit.ResultSuccess,
	})

	fields := logs.All()[0].ContextMap()
	if _, ok := fields["tenant_id"]; ok {
		t.Error("Expected no tenant_id field when TenantID is empty")
	}
}

func TestLog_NamedAuditLogger(t *testing.T) {
	// Verify audit events are emitted on a logger named "audit"
	core, logs := observer.New(zapcore.InfoLevel)
	base := zap.New(core)
	l := audit.New(base)

	l.Log(audit.Event{
		Operation:    "tenant.update",
		ResourceType: "tenant",
		ResourceID:   "t1",
		OperatorIP:   "1.2.3.4",
		Result:       audit.ResultSuccess,
	})

	if logs.Len() != 1 {
		t.Fatalf("Expected 1 log entry, got %d", logs.Len())
	}

	entry := logs.All()[0]
	// zap Named loggers include the name in the LoggerName field
	if entry.LoggerName != "audit" {
		t.Errorf("Expected logger name %q, got %q", "audit", entry.LoggerName)
	}
}

// assertField is a helper to check a string field in log context.
func assertField(t *testing.T, fields map[string]interface{}, key, want string) {
	t.Helper()
	got, ok := fields[key]
	if !ok {
		t.Errorf("Expected field %q to be present", key)
		return
	}
	if got != want {
		t.Errorf("Field %q: expected %q, got %v", key, want, got)
	}
}
