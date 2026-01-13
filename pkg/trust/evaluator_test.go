package trust

import (
	"context"
	"testing"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

func TestEvaluatorManager_NoEvaluators(t *testing.T) {
	manager := NewEvaluatorManager()

	resp, err := manager.Evaluate(context.Background(), &EvaluationRequest{
		Subject:  Subject{Type: SubjectTypeKey, ID: "test"},
		Resource: Resource{Type: ResourceTypeX5C},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision {
		t.Error("expected Decision=false when no evaluators available")
	}
	if resp.Reason == "" {
		t.Error("expected reason to be set")
	}
}

func TestEvaluatorManager_Healthy(t *testing.T) {
	// Empty manager is healthy
	manager := NewEvaluatorManager()
	if !manager.Healthy() {
		t.Error("empty manager should be healthy")
	}

	// With unhealthy evaluator
	mock := &mockEvaluator{healthy: false}
	manager.AddEvaluator(mock)
	if manager.Healthy() {
		t.Error("manager with unhealthy evaluator should not be healthy")
	}

	// With at least one healthy evaluator
	mock.healthy = true
	if !manager.Healthy() {
		t.Error("manager with healthy evaluator should be healthy")
	}
}

func TestEvaluatorManager_AllHealthy(t *testing.T) {
	manager := NewEvaluatorManager()

	// Add two evaluators
	mock1 := &mockEvaluator{healthy: true}
	mock2 := &mockEvaluator{healthy: true}
	manager.AddEvaluator(mock1)
	manager.AddEvaluator(mock2)

	if !manager.AllHealthy() {
		t.Error("all evaluators should be healthy")
	}

	// Make one unhealthy
	mock2.healthy = false
	if manager.AllHealthy() {
		t.Error("not all evaluators are healthy")
	}
}

func TestEvaluatorManager_Routing(t *testing.T) {
	manager := NewEvaluatorManager()

	x5cEval := &mockEvaluator{
		name:     "x5c-evaluator",
		types:    []ResourceType{ResourceTypeX5C},
		decision: true,
	}
	jwkEval := &mockEvaluator{
		name:     "jwk-evaluator",
		types:    []ResourceType{ResourceTypeJWK},
		decision: false,
	}

	manager.AddEvaluator(x5cEval)
	manager.AddEvaluator(jwkEval)

	// Test X5C routing
	resp, err := manager.Evaluate(context.Background(), &EvaluationRequest{
		Subject:  Subject{Type: SubjectTypeKey, ID: "test"},
		Resource: Resource{Type: ResourceTypeX5C},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected X5C request to be routed to x5c-evaluator (decision=true)")
	}

	// Test JWK routing
	resp, err = manager.Evaluate(context.Background(), &EvaluationRequest{
		Subject:  Subject{Type: SubjectTypeKey, ID: "test"},
		Resource: Resource{Type: ResourceTypeJWK},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision {
		t.Error("expected JWK request to be routed to jwk-evaluator (decision=false)")
	}
}

// mockEvaluator is a test helper
type mockEvaluator struct {
	name     string
	types    []ResourceType
	decision bool
	healthy  bool
	reason   string
}

func (m *mockEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
	return &EvaluationResponse{
		Decision: m.decision,
		Reason:   m.reason,
	}, nil
}

func (m *mockEvaluator) Name() string {
	if m.name == "" {
		return "mock"
	}
	return m.name
}

func (m *mockEvaluator) SupportedResourceTypes() []ResourceType {
	if m.types == nil {
		return []ResourceType{ResourceTypeX5C}
	}
	return m.types
}

func (m *mockEvaluator) Healthy() bool {
	return m.healthy
}

func TestEvaluationRequest_GetSubjectID(t *testing.T) {
	tests := []struct {
		name string
		req  EvaluationRequest
		want string
	}{
		{
			name: "prefers new SubjectID",
			req:  EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{SubjectID: "new-id"}, Subject: Subject{ID: "legacy-id"}},
			want: "new-id",
		},
		{
			name: "falls back to legacy Subject.ID",
			req:  EvaluationRequest{Subject: Subject{ID: "legacy-id"}},
			want: "legacy-id",
		},
		{
			name: "empty if both empty",
			req:  EvaluationRequest{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.GetSubjectID(); got != tt.want {
				t.Errorf("GetSubjectID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluationRequest_GetKeyType(t *testing.T) {
	tests := []struct {
		name string
		req  EvaluationRequest
		want KeyType
	}{
		{
			name: "prefers new KeyType",
			req:  EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{KeyType: KeyTypeJWK}, Resource: Resource{Type: KeyTypeX5C}},
			want: KeyTypeJWK,
		},
		{
			name: "falls back to legacy Resource.Type",
			req:  EvaluationRequest{Resource: Resource{Type: KeyTypeX5C}},
			want: KeyTypeX5C,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.GetKeyType(); got != tt.want {
				t.Errorf("GetKeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluationRequest_GetKey(t *testing.T) {
	tests := []struct {
		name     string
		req      EvaluationRequest
		wantType string
	}{
		{
			name:     "prefers new Key",
			req:      EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Key: "new-key"}, Resource: Resource{Key: "legacy-key"}},
			wantType: "string",
		},
		{
			name:     "falls back to legacy Resource.Key",
			req:      EvaluationRequest{Resource: Resource{Key: "legacy-key"}},
			wantType: "string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.req.GetKey()
			if got == nil && tt.wantType != "" {
				t.Errorf("GetKey() = nil, want non-nil")
			}
		})
	}
}

func TestEvaluationRequest_GetAction(t *testing.T) {
	tests := []struct {
		name string
		req  EvaluationRequest
		want string
	}{
		{
			name: "prefers new Action",
			req:  EvaluationRequest{EvaluationRequest: trustapi.EvaluationRequest{Action: "new-action"}, LegacyAction: &Action{Name: "legacy-action"}},
			want: "new-action",
		},
		{
			name: "falls back to legacy LegacyAction",
			req:  EvaluationRequest{LegacyAction: &Action{Name: "legacy-action"}},
			want: "legacy-action",
		},
		{
			name: "empty if both nil/empty",
			req:  EvaluationRequest{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.GetAction(); got != tt.want {
				t.Errorf("GetAction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluationResponse_ToTrustDecision(t *testing.T) {
	resp := &EvaluationResponse{
		Decision:      true,
		Reason:        "test reason",
		TrustMetadata: map[string]string{"key": "value"},
	}

	decision := resp.ToTrustDecision()
	if decision == nil {
		t.Fatal("ToTrustDecision() returned nil")
	}
	if !decision.Trusted {
		t.Error("ToTrustDecision().Trusted = false, want true")
	}
	if decision.Reason != "test reason" {
		t.Errorf("ToTrustDecision().Reason = %v, want test reason", decision.Reason)
	}
}

func TestFromTrustDecision(t *testing.T) {
	decision := &trustapi.TrustDecision{
		Trusted:  true,
		Reason:   "trusted reason",
		Metadata: map[string]string{"foo": "bar"},
	}

	resp := FromTrustDecision(decision)
	if resp == nil {
		t.Fatal("FromTrustDecision() returned nil")
	}
	if !resp.Decision {
		t.Error("FromTrustDecision().Decision = false, want true")
	}
	if resp.Reason != "trusted reason" {
		t.Errorf("FromTrustDecision().Reason = %v, want trusted reason", resp.Reason)
	}
}

func TestEvaluatorManager_Name(t *testing.T) {
	manager := NewEvaluatorManager()
	if name := manager.Name(); name != "composite" {
		t.Errorf("Name() = %v, want composite", name)
	}
}

func TestEvaluatorManager_SupportedResourceTypes(t *testing.T) {
	manager := NewEvaluatorManager()

	// Empty manager supports nothing
	types := manager.SupportedResourceTypes()
	if len(types) != 0 {
		t.Errorf("Empty manager SupportedResourceTypes() = %v, want []", types)
	}

	// Add evaluators with different types
	manager.AddEvaluator(&mockEvaluator{types: []ResourceType{ResourceTypeX5C}})
	manager.AddEvaluator(&mockEvaluator{types: []ResourceType{ResourceTypeJWK}})

	types = manager.SupportedResourceTypes()
	if len(types) != 2 {
		t.Errorf("SupportedResourceTypes() has %d types, want 2", len(types))
	}
}
