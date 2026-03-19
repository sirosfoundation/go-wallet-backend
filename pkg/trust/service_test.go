package trust

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// testMockEvaluator implements TrustEvaluator for service tests
type testMockEvaluator struct {
	decision  bool
	reason    string
	returnErr error
}

func (m *testMockEvaluator) Evaluate(_ context.Context, _ *EvaluationRequest) (*EvaluationResponse, error) {
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	return &EvaluationResponse{
		Decision: m.decision,
		Reason:   m.reason,
	}, nil
}

func (m *testMockEvaluator) Name() string {
	return "test-mock-evaluator"
}

func (m *testMockEvaluator) SupportedResourceTypes() []ResourceType {
	return []ResourceType{ResourceTypeX5C, ResourceTypeJWK}
}

func (m *testMockEvaluator) Healthy() bool {
	return true
}

func TestContextWithTenant(t *testing.T) {
	ctx := context.Background()
	tenantID := "test-tenant-123"

	ctx = ContextWithTenant(ctx, tenantID)

	got := TenantFromContext(ctx)
	if got != tenantID {
		t.Errorf("TenantFromContext() = %q, want %q", got, tenantID)
	}
}

func TestTenantFromContext_Empty(t *testing.T) {
	ctx := context.Background()

	got := TenantFromContext(ctx)
	if got != "" {
		t.Errorf("TenantFromContext(empty ctx) = %q, want empty", got)
	}
}

func TestTenantFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), TenantIDContextKey, 12345) // int, not string

	got := TenantFromContext(ctx)
	if got != "" {
		t.Errorf("TenantFromContext(wrong type) = %q, want empty", got)
	}
}

func TestTenantTransport_WithTenant(t *testing.T) {
	var capturedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Tenant-ID")
	}))
	defer server.Close()

	transport := &TenantTransport{Base: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	ctx := ContextWithTenant(context.Background(), "tenant-abc")
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	_, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if capturedHeader != "tenant-abc" {
		t.Errorf("X-Tenant-ID header = %q, want %q", capturedHeader, "tenant-abc")
	}
}

func TestTenantTransport_WithoutTenant(t *testing.T) {
	var capturedHeader string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedHeader = r.Header.Get("X-Tenant-ID")
	}))
	defer server.Close()

	transport := &TenantTransport{Base: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	_, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if capturedHeader != "" {
		t.Errorf("X-Tenant-ID header = %q, want empty (not set)", capturedHeader)
	}
}

func TestTenantTransport_NilBase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &TenantTransport{Base: nil}
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want 200", resp.StatusCode)
	}
}

func TestNewService(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			Timeout: 30,
		},
	}
	logger := zap.NewNop()

	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: true}, nil
	}

	svc := NewService(cfg, logger, factory)

	if svc == nil {
		t.Fatal("NewService() returned nil")
	}
	if svc.cfg != cfg {
		t.Error("Service config not set")
	}
	if svc.evaluators == nil {
		t.Error("Service evaluators map not initialized")
	}
}

func TestService_GetEvaluator_EmptyEndpoint(t *testing.T) {
	cfg := &config.Config{}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{}, nil
	}

	svc := NewService(cfg, logger, factory)

	eval, err := svc.GetEvaluator("")
	if err != nil {
		t.Fatalf("GetEvaluator() error = %v", err)
	}
	if eval != nil {
		t.Error("GetEvaluator(\"\") should return nil evaluator")
	}
}

func TestService_GetEvaluator_CachesEvaluator(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			Timeout: 10,
		},
	}
	logger := zap.NewNop()

	createCount := 0
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		createCount++
		return &testMockEvaluator{decision: true}, nil
	}

	svc := NewService(cfg, logger, factory)

	// First call - creates evaluator
	eval1, err := svc.GetEvaluator("https://pdp.example.com")
	if err != nil {
		t.Fatalf("GetEvaluator() error = %v", err)
	}
	if eval1 == nil {
		t.Fatal("GetEvaluator() returned nil")
	}
	if createCount != 1 {
		t.Errorf("Factory called %d times, want 1", createCount)
	}

	// Second call - returns cached evaluator
	eval2, err := svc.GetEvaluator("https://pdp.example.com")
	if err != nil {
		t.Fatalf("GetEvaluator() error = %v", err)
	}
	if createCount != 1 {
		t.Errorf("Factory called %d times on second call, want 1 (cached)", createCount)
	}
	if eval1 != eval2 {
		t.Error("Second call returned different evaluator (not cached)")
	}
}

func TestService_GetEvaluator_FactoryError(t *testing.T) {
	cfg := &config.Config{}
	logger := zap.NewNop()

	expectedErr := errors.New("factory failed")
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return nil, expectedErr
	}

	svc := NewService(cfg, logger, factory)

	_, err := svc.GetEvaluator("https://pdp.example.com")
	if err != expectedErr {
		t.Errorf("GetEvaluator() error = %v, want %v", err, expectedErr)
	}
}

func TestService_GetEvaluator_DefaultTimeout(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			Timeout: 0, // Will use default
		},
	}
	logger := zap.NewNop()

	var receivedTimeout time.Duration
	factory := func(_ string, timeout time.Duration) (TrustEvaluator, error) {
		receivedTimeout = timeout
		return &testMockEvaluator{}, nil
	}

	svc := NewService(cfg, logger, factory)
	_, _ = svc.GetEvaluator("https://pdp.example.com")

	if receivedTimeout != 30*time.Second {
		t.Errorf("Factory received timeout = %v, want 30s", receivedTimeout)
	}
}

func TestService_EvaluateIssuer_NoEndpoint(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL: "", // No PDP configured
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{}, nil
	}

	svc := NewService(cfg, logger, factory)

	result, err := svc.EvaluateIssuer(context.Background(), "did:example:issuer", "", nil)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateIssuer() Trusted = false when no PDP configured")
	}
	if result.Framework != "none" {
		t.Errorf("EvaluateIssuer() Framework = %q, want none", result.Framework)
	}
}

func TestService_EvaluateIssuer_Success(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: true, reason: "Trusted via test anchor"}, nil
	}

	svc := NewService(cfg, logger, factory)

	result, err := svc.EvaluateIssuer(context.Background(), "did:example:issuer", "", nil)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateIssuer() Trusted = false, want true")
	}
	if result.Framework != "authzen" {
		t.Errorf("EvaluateIssuer() Framework = %q, want authzen", result.Framework)
	}
}

func TestService_EvaluateIssuer_WithX5C(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: true}, nil
	}

	svc := NewService(cfg, logger, factory)

	km := &KeyMaterial{
		Type:           "x5c",
		X5C:            []string{"MIIBxxx..."},
		CredentialType: "urn:eu.europa.ec.eudi:pid:1",
	}

	result, err := svc.EvaluateIssuer(context.Background(), "did:example:issuer", "", km)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateIssuer() Trusted = false")
	}
}

func TestService_EvaluateIssuer_WithJWK(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: true}, nil
	}

	svc := NewService(cfg, logger, factory)

	km := &KeyMaterial{
		Type: "jwk",
		JWK:  map[string]interface{}{"kty": "EC", "crv": "P-256"},
	}

	result, err := svc.EvaluateIssuer(context.Background(), "did:example:issuer", "", km)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateIssuer() Trusted = false")
	}
}

func TestService_EvaluateIssuer_EvaluatorError(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{returnErr: errors.New("evaluation failed")}, nil
	}

	svc := NewService(cfg, logger, factory)

	result, err := svc.EvaluateIssuer(context.Background(), "did:example:issuer", "", nil)
	if err != nil {
		t.Fatalf("EvaluateIssuer() returned error: %v", err)
	}
	// Evaluation errors are captured in TrustInfo, not returned as errors
	if result.Trusted {
		t.Error("EvaluateIssuer() Trusted = true on evaluator error")
	}
	if result.Reason == "" {
		t.Error("EvaluateIssuer() Reason should contain error message")
	}
}

func TestService_EvaluateVerifier_NoEndpoint(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL: "",
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{}, nil
	}

	svc := NewService(cfg, logger, factory)

	result, err := svc.EvaluateVerifier(context.Background(), "did:example:verifier", "", nil)
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateVerifier() Trusted = false when no PDP configured")
	}
}

func TestService_EvaluateVerifier_Success(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: false, reason: "Not in trusted registry"}, nil
	}

	svc := NewService(cfg, logger, factory)

	result, err := svc.EvaluateVerifier(context.Background(), "did:example:verifier", "", nil)
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if result.Trusted {
		t.Error("EvaluateVerifier() Trusted = true, want false")
	}
	if result.Reason != "Not in trusted registry" {
		t.Errorf("EvaluateVerifier() Reason = %q, want %q", result.Reason, "Not in trusted registry")
	}
}

func TestService_EvaluateIssuer_SessionOverride(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://default-pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()

	var receivedEndpoint string
	factory := func(endpoint string, _ time.Duration) (TrustEvaluator, error) {
		receivedEndpoint = endpoint
		return &testMockEvaluator{decision: true}, nil
	}

	svc := NewService(cfg, logger, factory)

	_, err := svc.EvaluateIssuer(context.Background(), "did:example:issuer", "https://session-pdp.example.com", nil)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}

	if receivedEndpoint != "https://session-pdp.example.com" {
		t.Errorf("Used endpoint = %q, want session override", receivedEndpoint)
	}
}

func TestService_IsIssuerTrustEnabled(t *testing.T) {
	tests := []struct {
		name   string
		cfg    config.TrustConfig
		expect bool
	}{
		{"enabled via PDPURL", config.TrustConfig{PDPURL: "https://pdp.example.com"}, true},
		{"enabled via Issuer.PDPURL", config.TrustConfig{Issuer: config.FlowTrustConfig{PDPURL: "https://issuer-pdp.example.com"}}, true},
		{"disabled when empty", config.TrustConfig{}, false},
		{"disabled via none", config.TrustConfig{Issuer: config.FlowTrustConfig{PDPURL: "none"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Trust: tt.cfg}
			svc := NewService(cfg, zap.NewNop(), nil)

			got := svc.IsIssuerTrustEnabled()
			if got != tt.expect {
				t.Errorf("IsIssuerTrustEnabled() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestService_IsVerifierTrustEnabled(t *testing.T) {
	tests := []struct {
		name   string
		cfg    config.TrustConfig
		expect bool
	}{
		{"enabled via PDPURL", config.TrustConfig{PDPURL: "https://pdp.example.com"}, true},
		{"enabled via Verifier.PDPURL", config.TrustConfig{Verifier: config.FlowTrustConfig{PDPURL: "https://verifier-pdp.example.com"}}, true},
		{"disabled when empty", config.TrustConfig{}, false},
		{"disabled via none", config.TrustConfig{Verifier: config.FlowTrustConfig{PDPURL: "none"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Trust: tt.cfg}
			svc := NewService(cfg, zap.NewNop(), nil)

			got := svc.IsVerifierTrustEnabled()
			if got != tt.expect {
				t.Errorf("IsVerifierTrustEnabled() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestService_Evaluate_KeyMaterialInference(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: true}, nil
	}

	svc := NewService(cfg, logger, factory)

	// Test with empty Type but X5C present - should infer x5c
	km := &KeyMaterial{
		Type: "", // Empty, should infer
		X5C:  []string{"MIIBxxx..."},
	}

	result, err := svc.EvaluateIssuer(context.Background(), "did:example:issuer", "", km)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateIssuer() with inferred X5C failed")
	}
}

func TestService_Evaluate_KeyMaterialInferenceJWK(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: true}, nil
	}

	svc := NewService(cfg, logger, factory)

	// Test with empty Type but JWK present - should infer jwk
	km := &KeyMaterial{
		Type: "", // Empty, should infer
		JWK:  map[string]interface{}{"kty": "EC"},
	}

	result, err := svc.EvaluateIssuer(context.Background(), "did:example:issuer", "", km)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateIssuer() with inferred JWK failed")
	}
}
