package trust

import (
	"context"
	"testing"
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
