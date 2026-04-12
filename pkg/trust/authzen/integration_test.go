package authzen

import (
	"context"
	"sync"
	"testing"

	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// safeCapture provides thread-safe capture of AuthZEN requests in test decision functions.
type safeCapture struct {
	mu  sync.Mutex
	req *gotrust.EvaluationRequest
}

func (c *safeCapture) set(req *gotrust.EvaluationRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.req = req
}

func (c *safeCapture) get() *gotrust.EvaluationRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.req
}

// ---------------------------------------------------------------------------
// Integration tests using embedded go-trust testserver
// ---------------------------------------------------------------------------

func TestIntegration_Evaluator_AcceptAll(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	eval, err := NewEvaluator(&Config{BaseURL: srv.URL()})
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
		Subject:  trust.Subject{Type: trust.SubjectTypeKey, ID: "https://issuer.example.com"},
		Resource: trust.Resource{Type: trust.ResourceTypeX5C, ID: "https://issuer.example.com", Key: []string{"MIIBxxx"}},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Errorf("expected Decision=true, got false (reason: %s)", resp.Reason)
	}
}

func TestIntegration_Evaluator_RejectAll(t *testing.T) {
	srv := testserver.New(testserver.WithRejectAll())
	defer srv.Close()

	eval, err := NewEvaluator(&Config{BaseURL: srv.URL()})
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
		Subject:  trust.Subject{Type: trust.SubjectTypeKey, ID: "https://issuer.example.com"},
		Resource: trust.Resource{Type: trust.ResourceTypeX5C, ID: "https://issuer.example.com", Key: []string{"MIIBxxx"}},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if resp.Decision {
		t.Error("expected Decision=false with reject-all PDP")
	}
}

func TestIntegration_Evaluator_DecisionFunc_CredentialIssuer(t *testing.T) {
	capture := &safeCapture{}

	srv := testserver.New(testserver.WithDecisionFunc(
		func(req *gotrust.EvaluationRequest) (*gotrust.EvaluationResponse, error) {
			capture.set(req)
			if req.Action != nil && req.Action.Name == "credential-issuer" {
				return &gotrust.EvaluationResponse{
					Decision: true,
					Context: &gotrust.EvaluationResponseContext{
						Reason: map[string]interface{}{
							"registry": "etsi-tsl",
							"message":  "validated against TSL",
						},
					},
				}, nil
			}
			return &gotrust.EvaluationResponse{Decision: false}, nil
		},
	))
	defer srv.Close()

	eval, err := NewEvaluator(&Config{BaseURL: srv.URL()})
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	req := &trust.EvaluationRequest{
		Subject:  trust.Subject{Type: trust.SubjectTypeKey, ID: "https://pid-issuer.eudiw.dev"},
		Resource: trust.Resource{Type: trust.ResourceTypeX5C, ID: "https://pid-issuer.eudiw.dev", Key: []string{"MIIBleaf", "MIIBintermediate"}},
	}
	req.Role = trust.RoleCredentialIssuer

	resp, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Errorf("expected Decision=true, got false (reason: %s)", resp.Reason)
	}
	if resp.Reason != "validated against TSL" {
		t.Errorf("Reason = %q, want 'validated against TSL'", resp.Reason)
	}

	// Verify wire format
	capturedReq := capture.get()
	if capturedReq == nil {
		t.Fatal("DecisionFunc was not called")
	}
	if capturedReq.Subject.Type != "key" {
		t.Errorf("Subject.Type = %q, want key", capturedReq.Subject.Type)
	}
	if capturedReq.Resource.Type != "x5c" {
		t.Errorf("Resource.Type = %q, want x5c", capturedReq.Resource.Type)
	}
	if capturedReq.Action == nil || capturedReq.Action.Name != "credential-issuer" {
		t.Errorf("Action.Name should be credential-issuer")
	}
}

func TestIntegration_Evaluator_DecisionFunc_CredentialVerifier(t *testing.T) {
	capture := &safeCapture{}

	srv := testserver.New(testserver.WithDecisionFunc(
		func(req *gotrust.EvaluationRequest) (*gotrust.EvaluationResponse, error) {
			capture.set(req)
			if req.Action != nil && req.Action.Name == "credential-verifier" {
				return &gotrust.EvaluationResponse{
					Decision: true,
					Context: &gotrust.EvaluationResponseContext{
						Reason: map[string]interface{}{
							"registry":     "etsi-tsl",
							"service_type": "http://uri.etsi.org/TrstSvc/Svctype/QCertForESig",
							"message":      "WRP access certificate validated",
						},
					},
				}, nil
			}
			return &gotrust.EvaluationResponse{Decision: false}, nil
		},
	))
	defer srv.Close()

	eval, err := NewEvaluator(&Config{BaseURL: srv.URL()})
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	req := &trust.EvaluationRequest{
		Subject:  trust.Subject{Type: trust.SubjectTypeKey, ID: "https://rp.eudiw.dev"},
		Resource: trust.Resource{Type: trust.ResourceTypeX5C, ID: "https://rp.eudiw.dev", Key: []string{"MIIBrpcert"}},
	}
	req.Role = trust.RoleCredentialVerifier

	resp, err := eval.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Errorf("expected Decision=true, got false (reason: %s)", resp.Reason)
	}
	if resp.Reason != "WRP access certificate validated" {
		t.Errorf("Reason = %q, want 'WRP access certificate validated'", resp.Reason)
	}

	// Verify wire format
	capturedReq := capture.get()
	if capturedReq == nil {
		t.Fatal("DecisionFunc was not called")
	}
	if capturedReq.Action == nil || capturedReq.Action.Name != "credential-verifier" {
		t.Errorf("Action.Name should be credential-verifier")
	}
}

func TestIntegration_Evaluator_HealthRecovery(t *testing.T) {
	callCount := 0
	srv := testserver.New(testserver.WithDecisionFunc(
		func(req *gotrust.EvaluationRequest) (*gotrust.EvaluationResponse, error) {
			callCount++
			return &gotrust.EvaluationResponse{Decision: true}, nil
		},
	))
	defer srv.Close()

	eval, err := NewEvaluator(&Config{BaseURL: srv.URL()})
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	// Mark as unhealthy
	eval.SetHealthy(false)
	if eval.Healthy() {
		t.Error("expected unhealthy after SetHealthy(false)")
	}

	// Evaluate still works (health is advisory, not blocking)
	resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
		Subject:  trust.Subject{Type: trust.SubjectTypeKey, ID: "test"},
		Resource: trust.Resource{Type: trust.ResourceTypeX5C, ID: "test", Key: []string{"cert"}},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Error("expected Decision=true")
	}

	// Should be healthy again after successful call
	if !eval.Healthy() {
		t.Error("expected healthy after successful evaluation")
	}
}

func TestIntegration_EvaluateX5C_WithAction(t *testing.T) {
	capture := &safeCapture{}

	srv := testserver.New(testserver.WithDecisionFunc(
		func(req *gotrust.EvaluationRequest) (*gotrust.EvaluationResponse, error) {
			capture.set(req)
			return &gotrust.EvaluationResponse{Decision: true}, nil
		},
	))
	defer srv.Close()

	eval, err := NewEvaluator(&Config{BaseURL: srv.URL()})
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	resp, err := eval.EvaluateX5C(context.Background(), "https://rp.example.com", []string{"cert1", "cert2"}, "credential-verifier")
	if err != nil {
		t.Fatalf("EvaluateX5C() error = %v", err)
	}
	if !resp.Decision {
		t.Errorf("expected Decision=true, got false (reason: %s)", resp.Reason)
	}

	capturedReq := capture.get()
	if capturedReq == nil {
		t.Fatal("DecisionFunc was not called")
	}
	if capturedReq.Action == nil || capturedReq.Action.Name != "credential-verifier" {
		t.Error("Action.Name should be credential-verifier")
	}
	if capturedReq.Resource.Type != "x5c" {
		t.Errorf("Resource.Type = %q, want x5c", capturedReq.Resource.Type)
	}
}

func TestIntegration_Resolve_DID(t *testing.T) {
	srv := testserver.New(testserver.WithDecisionFunc(
		func(req *gotrust.EvaluationRequest) (*gotrust.EvaluationResponse, error) {
			return &gotrust.EvaluationResponse{
				Decision: true,
				Context: &gotrust.EvaluationResponseContext{
					TrustMetadata: map[string]interface{}{
						"id":                 req.Subject.ID,
						"verificationMethod": []interface{}{},
					},
				},
			}, nil
		},
	))
	defer srv.Close()

	eval, err := NewEvaluator(&Config{BaseURL: srv.URL()})
	if err != nil {
		t.Fatalf("NewEvaluator() error = %v", err)
	}

	resp, err := eval.Resolve(context.Background(), "did:web:issuer.example.com")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !resp.Decision {
		t.Error("expected Decision=true for DID resolution")
	}
	if resp.TrustMetadata == nil {
		t.Error("expected TrustMetadata to be set")
	}
}

func TestIntegration_Evaluator_Discovery(t *testing.T) {
	srv := testserver.New(testserver.WithAcceptAll())
	defer srv.Close()

	eval, err := NewEvaluatorWithDiscovery(context.Background(), srv.URL(), 0)
	if err != nil {
		t.Fatalf("NewEvaluatorWithDiscovery() error = %v", err)
	}

	resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
		Subject:  trust.Subject{Type: trust.SubjectTypeKey, ID: "https://issuer.example.com"},
		Resource: trust.Resource{Type: trust.ResourceTypeX5C, ID: "https://issuer.example.com", Key: []string{"MIIBxxx"}},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !resp.Decision {
		t.Errorf("expected Decision=true from discovered PDP, got false (reason: %s)", resp.Reason)
	}
}
