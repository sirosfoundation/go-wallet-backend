package authzen

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

func TestNewEvaluator(t *testing.T) {
	t.Run("nil config returns error", func(t *testing.T) {
		_, err := NewEvaluator(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("empty BaseURL returns error", func(t *testing.T) {
		_, err := NewEvaluator(&Config{})
		if err == nil {
			t.Error("expected error for empty BaseURL")
		}
	})

	t.Run("valid config creates evaluator", func(t *testing.T) {
		cfg := &Config{
			BaseURL: "https://pdp.example.com",
		}
		eval, err := NewEvaluator(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if eval == nil {
			t.Error("expected evaluator to be created")
		}
	})
}

func TestEvaluator_Name(t *testing.T) {
	eval, _ := NewEvaluator(&Config{BaseURL: "https://pdp.example.com"})
	if eval.Name() != "authzen" {
		t.Errorf("expected name 'authzen', got '%s'", eval.Name())
	}
}

func TestEvaluator_SupportedResourceTypes(t *testing.T) {
	eval, _ := NewEvaluator(&Config{BaseURL: "https://pdp.example.com"})
	types := eval.SupportedResourceTypes()

	hasX5C := false
	hasJWK := false
	for _, rt := range types {
		if rt == trust.ResourceTypeX5C {
			hasX5C = true
		}
		if rt == trust.ResourceTypeJWK {
			hasJWK = true
		}
	}

	if !hasX5C || !hasJWK {
		t.Errorf("expected both x5c and jwk support, got %v", types)
	}
}

func TestEvaluator_Healthy(t *testing.T) {
	eval, _ := NewEvaluator(&Config{BaseURL: "https://pdp.example.com"})

	// Initially healthy
	if !eval.Healthy() {
		t.Error("expected evaluator to be healthy initially")
	}

	// Set unhealthy
	eval.SetHealthy(false)
	if eval.Healthy() {
		t.Error("expected evaluator to be unhealthy after SetHealthy(false)")
	}

	// Set healthy again
	eval.SetHealthy(true)
	if !eval.Healthy() {
		t.Error("expected evaluator to be healthy after SetHealthy(true)")
	}
}

func TestEvaluator_Evaluate(t *testing.T) {
	t.Run("successful evaluation - decision true", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/evaluation" {
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			}

			var req gotrust.EvaluationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("failed to decode request: %v", err)
			}

			if req.Subject.Type != "key" || req.Subject.ID != "did:example:issuer" {
				t.Errorf("unexpected subject: %+v", req.Subject)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(gotrust.EvaluationResponse{
				Decision: true,
				Context: &gotrust.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"message": "trust chain verified",
					},
				},
			})
		}))
		defer server.Close()

		eval, _ := NewEvaluator(&Config{
			BaseURL: server.URL,
			Timeout: 5 * time.Second,
		})

		resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
			Subject: trust.Subject{
				Type: trust.SubjectTypeKey,
				ID:   "did:example:issuer",
			},
			Resource: trust.Resource{
				Type: trust.ResourceTypeX5C,
				ID:   "did:example:issuer",
				Key:  []string{"base64cert"},
			},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Decision {
			t.Error("expected Decision=true")
		}
		if resp.Reason == "" {
			t.Error("expected reason to be set")
		}
	})

	t.Run("successful evaluation - decision false", func(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(gotrust.EvaluationResponse{
				Decision: false,
				Context: &gotrust.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error": "certificate not trusted",
					},
				},
			})
		}))
		defer server.Close()

		eval, _ := NewEvaluator(&Config{BaseURL: server.URL})

		resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
			Subject:  trust.Subject{Type: trust.SubjectTypeKey, ID: "test"},
			Resource: trust.Resource{Type: trust.ResourceTypeX5C, ID: "test", Key: []string{"cert"}},
		})

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected Decision=false")
		}
		if resp.Reason != "certificate not trusted" {
			t.Errorf("unexpected reason: %s", resp.Reason)
		}
	})

	t.Run("connection error marks evaluator unhealthy", func(t *testing.T) {
		eval, _ := NewEvaluator(&Config{
			BaseURL: "http://localhost:99999", // Invalid port
			Timeout: 1 * time.Second,
		})

		resp, err := eval.Evaluate(context.Background(), &trust.EvaluationRequest{
			Subject:  trust.Subject{Type: trust.SubjectTypeKey, ID: "test"},
			Resource: trust.Resource{Type: trust.ResourceTypeX5C, ID: "test", Key: []string{"cert"}},
		})

		// Should not return an error, but decision=false
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Decision {
			t.Error("expected Decision=false on connection error")
		}
		if eval.Healthy() {
			t.Error("expected evaluator to be marked unhealthy")
		}
	})
}

func TestEvaluator_Resolve(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req gotrust.EvaluationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		// Verify it's a resolution-only request (no key)
		if req.Subject.ID != "did:web:example.com" {
			t.Errorf("unexpected subject ID: %s", req.Subject.ID)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gotrust.EvaluationResponse{
			Decision: true,
			Context: &gotrust.EvaluationResponseContext{
				TrustMetadata: map[string]interface{}{
					"id":                 "did:web:example.com",
					"verificationMethod": []interface{}{},
				},
			},
		})
	}))
	defer server.Close()

	eval, _ := NewEvaluator(&Config{BaseURL: server.URL})

	resp, err := eval.Resolve(context.Background(), "did:web:example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected Decision=true for resolution")
	}
	if resp.TrustMetadata == nil {
		t.Error("expected TrustMetadata to be set")
	}
}

func TestEvaluator_EvaluateX5C(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req gotrust.EvaluationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)

		if req.Resource.Type != "x5c" {
			t.Errorf("expected resource type 'x5c', got '%s'", req.Resource.Type)
		}
		if req.Action == nil || req.Action.Name != "tls-server" {
			t.Error("expected action to be set")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gotrust.EvaluationResponse{Decision: true})
	}))
	defer server.Close()

	eval, _ := NewEvaluator(&Config{BaseURL: server.URL})

	resp, err := eval.EvaluateX5C(context.Background(), "server.example.com", []string{"cert1", "cert2"}, "tls-server")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Decision {
		t.Error("expected Decision=true")
	}
}
