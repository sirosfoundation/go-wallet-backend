package trust

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// testMockEvaluator implements TrustEvaluator for service tests
type testMockEvaluator struct {
	decision  bool
	reason    string
	returnErr error
	// For Resolver interface
	resolveMetadata interface{}

	// gotReq captures the last request passed to Evaluate, so tests can
	// assert on outbound Role/Action wiring without a real AuthZEN PDP.
	gotReq *EvaluationRequest
}

func (m *testMockEvaluator) Evaluate(_ context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
	m.gotReq = req
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	return &EvaluationResponse{
		Decision: m.decision,
		Reason:   m.reason,
	}, nil
}

// Resolve implements the Resolver interface for DID resolution tests.
func (m *testMockEvaluator) Resolve(_ context.Context, _ string) (*EvaluationResponse, error) {
	if m.returnErr != nil {
		return nil, m.returnErr
	}
	return &EvaluationResponse{
		Decision:      m.decision,
		Reason:        m.reason,
		TrustMetadata: m.resolveMetadata,
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
	// Fail-closed: no PDP configured should result in Trusted = false
	if result.Trusted {
		t.Error("EvaluateIssuer() Trusted = true when no PDP configured, expected fail-closed")
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
	// Fail-closed: no PDP configured should result in Trusted = false
	if result.Trusted {
		t.Error("EvaluateVerifier() Trusted = true when no PDP configured, expected fail-closed")
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

// TestService_EvaluateVerifierWithContext_ForwardsContext pins that
// EvaluateVerifierWithContext's evalContext reaches the outbound
// EvaluationRequest.Context unchanged - the whole point of the method (see
// its doc comment): a direct-to-PDP verifier evaluation must carry the same
// trust_chain/attestation context a frontend-mediated one always has.
func TestService_EvaluateVerifierWithContext_ForwardsContext(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	mock := &testMockEvaluator{decision: true}
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return mock, nil
	}

	svc := NewService(cfg, logger, factory)

	evalContext := map[string]interface{}{
		"trust_chain":         []string{"leaf", "anchor"},
		"attestation_issuer":  "https://issuer.example.com",
		"attestation_subject": "https://verifier.example.com",
	}

	result, err := svc.EvaluateVerifierWithContext(context.Background(), "https://verifier.example.com", "", &KeyMaterial{
		Type: "x5c",
		X5C:  []string{"deadbeef"},
	}, evalContext)
	if err != nil {
		t.Fatalf("EvaluateVerifierWithContext() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateVerifierWithContext() Trusted = false, want true")
	}

	if mock.gotReq == nil {
		t.Fatal("evaluator never received a request")
	}
	if got := mock.gotReq.Context["trust_chain"]; got == nil {
		t.Error("EvaluationRequest.Context missing trust_chain - evalContext was not forwarded")
	}
	if got, want := mock.gotReq.Context["attestation_issuer"], evalContext["attestation_issuer"]; got != want {
		t.Errorf("EvaluationRequest.Context[attestation_issuer] = %v, want %v", got, want)
	}
}

// TestService_EvaluateVerifierWithContext_NilContext confirms passing a nil
// evalContext behaves exactly like plain EvaluateVerifier (no Context set),
// so EvaluateVerifierWithContext(ctx, id, ep, km, nil) is a safe drop-in.
func TestService_EvaluateVerifierWithContext_NilContext(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	mock := &testMockEvaluator{decision: true}
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return mock, nil
	}

	svc := NewService(cfg, logger, factory)

	result, err := svc.EvaluateVerifierWithContext(context.Background(), "https://verifier.example.com", "", nil, nil)
	if err != nil {
		t.Fatalf("EvaluateVerifierWithContext() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateVerifierWithContext() Trusted = false, want true")
	}
	if mock.gotReq != nil && mock.gotReq.Context != nil {
		t.Errorf("EvaluationRequest.Context = %v, want nil when evalContext is nil", mock.gotReq.Context)
	}
}

// TestService_EvaluateFIDO2Attestation_NoEndpoint exercises the fail-closed
// path when no global PDP is configured - FIDO Alliance MDS3 trust data is
// global (unlike issuer/verifier, it has no per-flow endpoint override), so
// this always uses cfg.Trust.PDPURL.
func TestService_EvaluateFIDO2Attestation_NoEndpoint(t *testing.T) {
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

	result, err := svc.EvaluateFIDO2Attestation(context.Background(), "f8a011f3-8c0a-4d15-8006-17111f9edc7d", []string{"MIIBxxx..."})
	if err != nil {
		t.Fatalf("EvaluateFIDO2Attestation() error = %v", err)
	}
	if result.Trusted {
		t.Error("EvaluateFIDO2Attestation() Trusted = true when no PDP configured, expected fail-closed")
	}
	if result.Framework != "none" {
		t.Errorf("EvaluateFIDO2Attestation() Framework = %q, want none", result.Framework)
	}
}

// TestService_EvaluateFIDO2Attestation_Trusted covers the AuthZEN wiring:
// the AAGUID must be sent as subject.id (the "name" half of the fidomds3
// registry's name-to-key binding - see go-trust's
// pkg/registry/fidomds3/registry.go's use of uuid.Parse(req.Subject.ID))
// and the x5c chain as resource.type=x5c/key.
func TestService_EvaluateFIDO2Attestation_Trusted(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: true, reason: "AAGUID certified by FIDO MDS3"}, nil
	}

	svc := NewService(cfg, logger, factory)

	aaguid := "f8a011f3-8c0a-4d15-8006-17111f9edc7d"
	result, err := svc.EvaluateFIDO2Attestation(context.Background(), aaguid, []string{"MIIBxxx..."})
	if err != nil {
		t.Fatalf("EvaluateFIDO2Attestation() error = %v", err)
	}
	if !result.Trusted {
		t.Error("EvaluateFIDO2Attestation() Trusted = false, want true")
	}
	if result.Framework != "authzen" {
		t.Errorf("EvaluateFIDO2Attestation() Framework = %q, want authzen", result.Framework)
	}
}

// TestService_EvaluateFIDO2Attestation_ActionName is the regression test for
// the bug where this call site sent no action.name at all: with Role ==
// RoleAny (empty string), go-trust's toAuthZENRequest fell all the way
// through to req.GetAction(), which was also never set - meaning an operator
// could never attach a go-trust policy (e.g. a fidomds3 AAGUID allow/
// blocklist) specifically to FIDO2 attestation evaluation. It must now carry
// the fixed FIDO2AttestationAction action name.
func TestService_EvaluateFIDO2Attestation_ActionName(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	eval := &testMockEvaluator{decision: true}
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return eval, nil
	}

	svc := NewService(cfg, logger, factory)

	if _, err := svc.EvaluateFIDO2Attestation(context.Background(), "f8a011f3-8c0a-4d15-8006-17111f9edc7d", []string{"MIIBxxx..."}); err != nil {
		t.Fatalf("EvaluateFIDO2Attestation() error = %v", err)
	}

	if eval.gotReq == nil {
		t.Fatal("Evaluate() was not called")
	}
	if eval.gotReq.Role != RoleAny {
		t.Errorf("gotReq.Role = %q, want RoleAny", eval.gotReq.Role)
	}
	if eval.gotReq.GetAction() != FIDO2AttestationAction {
		t.Errorf("gotReq.GetAction() = %q, want %q", eval.gotReq.GetAction(), FIDO2AttestationAction)
	}
}

// TestService_EvaluateIssuer_NoExplicitAction and its verifier counterpart
// guard against regressing the other evaluate() callers while fixing
// EvaluateFIDO2Attestation above: issuer/verifier evaluation identifies its
// call site via Role alone (go-trust's toAuthZENRequest prefers Role for
// action.name), so no explicit Action should ever be set for these.
func TestService_EvaluateIssuer_NoExplicitAction(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	eval := &testMockEvaluator{decision: true}
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return eval, nil
	}

	svc := NewService(cfg, logger, factory)

	if _, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", nil); err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}

	if eval.gotReq == nil {
		t.Fatal("Evaluate() was not called")
	}
	if eval.gotReq.Role != RoleCredentialIssuer {
		t.Errorf("gotReq.Role = %q, want RoleCredentialIssuer", eval.gotReq.Role)
	}
	if eval.gotReq.Action != "" {
		t.Errorf("gotReq.Action = %q, want empty (Role alone identifies this call site)", eval.gotReq.Action)
	}
}

func TestService_EvaluateVerifier_NoExplicitAction(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	eval := &testMockEvaluator{decision: true}
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return eval, nil
	}

	svc := NewService(cfg, logger, factory)

	if _, err := svc.EvaluateVerifier(context.Background(), "https://verifier.example.com", "", nil); err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}

	if eval.gotReq == nil {
		t.Fatal("Evaluate() was not called")
	}
	if eval.gotReq.Role != RoleCredentialVerifier {
		t.Errorf("gotReq.Role = %q, want RoleCredentialVerifier", eval.gotReq.Role)
	}
	if eval.gotReq.Action != "" {
		t.Errorf("gotReq.Action = %q, want empty (Role alone identifies this call site)", eval.gotReq.Action)
	}
}

func TestService_EvaluateFIDO2Attestation_NotTrusted(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  "https://pdp.example.com",
			Timeout: 10,
		},
	}
	logger := zap.NewNop()
	factory := func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &testMockEvaluator{decision: false, reason: "no FIDO MDS3 entry for AAGUID"}, nil
	}

	svc := NewService(cfg, logger, factory)

	result, err := svc.EvaluateFIDO2Attestation(context.Background(), "f8a011f3-8c0a-4d15-8006-17111f9edc7d", []string{"MIIBxxx..."})
	if err != nil {
		t.Fatalf("EvaluateFIDO2Attestation() error = %v", err)
	}
	if result.Trusted {
		t.Error("EvaluateFIDO2Attestation() Trusted = true, want false")
	}
	if result.Reason != "no FIDO MDS3 entry for AAGUID" {
		t.Errorf("EvaluateFIDO2Attestation() Reason = %q, want %q", result.Reason, "no FIDO MDS3 entry for AAGUID")
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

func TestResolveDID(t *testing.T) {
	didDoc := map[string]interface{}{
		"id": "did:web:example.com",
		"verificationMethod": []interface{}{
			map[string]interface{}{
				"id":         "did:web:example.com#key-1",
				"type":       "JsonWebKey2020",
				"controller": "did:web:example.com",
				"publicKeyJwk": map[string]interface{}{
					"kty": "EC",
					"crv": "P-256",
					"x":   "test-x",
					"y":   "test-y",
				},
			},
		},
	}

	t.Run("successful resolution", func(t *testing.T) {
		mock := &testMockEvaluator{
			decision:        true,
			resolveMetadata: didDoc,
		}
		cfg := &config.Config{}
		cfg.Trust.PDPURL = "http://pdp.test"
		svc := NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (TrustEvaluator, error) {
			return mock, nil
		})

		keys, err := svc.ResolveDID(context.Background(), "did:web:example.com", "")
		if err != nil {
			t.Fatalf("ResolveDID() error = %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(keys))
		}
		jwk, ok := keys[0].(map[string]interface{})
		if !ok {
			t.Fatal("expected map[string]interface{}")
		}
		if jwk["kid"] != "did:web:example.com#key-1" {
			t.Errorf("expected kid from verification method id, got %v", jwk["kid"])
		}
	})

	t.Run("no evaluator configured", func(t *testing.T) {
		cfg := &config.Config{}
		// No PDP URL configured
		svc := NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (TrustEvaluator, error) {
			return nil, nil
		})

		_, err := svc.ResolveDID(context.Background(), "did:web:example.com", "")
		if err == nil {
			t.Error("expected error when no evaluator configured")
		}
	})

	t.Run("resolution denied", func(t *testing.T) {
		mock := &testMockEvaluator{
			decision: false,
			reason:   "not in trust list",
		}
		cfg := &config.Config{}
		cfg.Trust.PDPURL = "http://pdp.test"
		svc := NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (TrustEvaluator, error) {
			return mock, nil
		})

		_, err := svc.ResolveDID(context.Background(), "did:web:untrusted.com", "")
		if err == nil {
			t.Error("expected error when resolution denied")
		}
	})

	t.Run("resolution error", func(t *testing.T) {
		mock := &testMockEvaluator{
			returnErr: errors.New("network timeout"),
		}
		cfg := &config.Config{}
		cfg.Trust.PDPURL = "http://pdp.test"
		svc := NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (TrustEvaluator, error) {
			return mock, nil
		})

		_, err := svc.ResolveDID(context.Background(), "did:web:example.com", "")
		if err == nil {
			t.Error("expected error on resolution failure")
		}
	})

	t.Run("no keys in DID document", func(t *testing.T) {
		mock := &testMockEvaluator{
			decision:        true,
			resolveMetadata: map[string]interface{}{"id": "did:web:example.com"},
		}
		cfg := &config.Config{}
		cfg.Trust.PDPURL = "http://pdp.test"
		svc := NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (TrustEvaluator, error) {
			return mock, nil
		})

		keys, err := svc.ResolveDID(context.Background(), "did:web:example.com", "")
		if err != nil {
			t.Fatalf("ResolveDID() error = %v", err)
		}
		if keys != nil {
			t.Errorf("expected nil keys, got %v", keys)
		}
	})

	t.Run("evaluator does not support resolution", func(t *testing.T) {
		// Use a non-resolver evaluator
		nonResolver := &nonResolvingEvaluator{}
		cfg := &config.Config{}
		cfg.Trust.PDPURL = "http://pdp.test"
		svc := NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (TrustEvaluator, error) {
			return nonResolver, nil
		})

		_, err := svc.ResolveDID(context.Background(), "did:web:example.com", "")
		if err == nil {
			t.Error("expected error when evaluator doesn't support resolution")
		}
	})
}

// nonResolvingEvaluator implements TrustEvaluator but NOT Resolver.
type nonResolvingEvaluator struct{}

func (n *nonResolvingEvaluator) Evaluate(_ context.Context, _ *EvaluationRequest) (*EvaluationResponse, error) {
	return &EvaluationResponse{Decision: true}, nil
}
func (n *nonResolvingEvaluator) Name() string                           { return "non-resolver" }
func (n *nonResolvingEvaluator) SupportedResourceTypes() []ResourceType { return nil }
func (n *nonResolvingEvaluator) Healthy() bool                          { return true }

// actionEvaluator answers per action.name and records every call in order.
type actionEvaluator struct {
	testMockEvaluator
	answers map[string]any // action -> true/false/error
	calls   []*EvaluationRequest
	tenants []string
}

func (a *actionEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
	a.calls = append(a.calls, req)
	a.tenants = append(a.tenants, TenantFromContext(ctx))
	name := string(req.Role)
	if name == "" {
		name = req.GetAction()
	}
	switch v := a.answers[name].(type) {
	case error:
		return nil, v
	case bool:
		return &EvaluationResponse{Decision: v, Reason: "answered " + name}, nil
	}
	return &EvaluationResponse{Decision: false}, nil
}

func (a *actionEvaluator) order() []string {
	var out []string
	for _, r := range a.calls {
		if r.Role != "" {
			out = append(out, string(r.Role))
		} else {
			out = append(out, r.GetAction())
		}
	}
	return out
}

func TestService_EvaluateStatusListSigner_TwoCalls(t *testing.T) {
	boom := errors.New("pdp down")
	const sls, iss = "status-list-signer", "credential-issuer"
	tests := []struct {
		name        string
		pdp         string
		fallback    bool
		answers     map[string]any
		wantOrder   []string
		wantTrusted bool
		wantAction  string
		wantError   bool // Reason reports a failed evaluation
		wantLog     string
	}{
		{"first positive: one call", "https://pdp", true, map[string]any{sls: true, iss: true},
			[]string{sls}, true, sls, false, ""},
		{"first negative is final even if issuer positive", "https://pdp", true, map[string]any{sls: false, iss: true},
			[]string{sls}, false, "", false, "signer_untrusted_denied"},
		{"first error, issuer positive: fallback", "https://pdp", true, map[string]any{sls: boom, iss: true},
			[]string{sls, iss}, true, iss, false, "credential-issuer fallback"},
		{"first error, issuer negative is a negative", "https://pdp", true, map[string]any{sls: boom, iss: false},
			[]string{sls, iss}, false, "", false, ""},
		{"both error", "https://pdp", true, map[string]any{sls: boom, iss: boom},
			[]string{sls, iss}, false, "", true, ""},
		{"fallback off, first error: error, one call", "https://pdp", false, map[string]any{sls: boom, iss: true},
			[]string{sls}, false, "", true, ""},
		{"fallback off, first positive", "https://pdp", false, map[string]any{sls: true},
			[]string{sls}, true, sls, false, ""},
		{"fallback off, first negative", "https://pdp", false, map[string]any{sls: false, iss: true},
			[]string{sls}, false, "", false, "signer_untrusted_denied"},
		{"no PDP: one call, no fallback", "", true, map[string]any{sls: true}, nil, false, "", false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Trust: config.TrustConfig{Timeout: 10, PDPURL: tc.pdp}}
			ev := &actionEvaluator{answers: tc.answers}
			core, logs := observer.New(zap.DebugLevel)
			svc := NewService(cfg, zap.New(core), func(string, time.Duration) (TrustEvaluator, error) { return ev, nil })
			km := &KeyMaterial{Type: "x5c", X5C: []string{"MIIBxxx"}}
			ctx := ContextWithTenant(context.Background(), "tenant-3")

			info, err := svc.EvaluateStatusListSigner(ctx, "https://status.example", "", km, tc.fallback)
			if err != nil {
				t.Fatal(err)
			}
			if info.Trusted != tc.wantTrusted || info.Action != tc.wantAction {
				t.Fatalf("trusted=%v action=%q, want %v %q (%+v)", info.Trusted, info.Action, tc.wantTrusted, tc.wantAction, info)
			}
			if got := info.EvaluationFailed; got != tc.wantError {
				t.Fatalf("error-reason=%v want %v (%q)", got, tc.wantError, info.Reason)
			}
			if got := ev.order(); strings.Join(got, ",") != strings.Join(tc.wantOrder, ",") {
				t.Fatalf("call order %v, want %v", got, tc.wantOrder)
			}
			// Same subject, key material and tenant on every call.
			for i, r := range ev.calls {
				if r.GetSubjectID() != "https://status.example" || r.GetKeyType() != ResourceTypeX5C || ev.tenants[i] != "tenant-3" {
					t.Errorf("call %d: subject=%q keyType=%q tenant=%q", i, r.GetSubjectID(), r.GetKeyType(), ev.tenants[i])
				}
			}
			if len(ev.calls) > 0 && (ev.calls[0].Role != RoleAny || ev.calls[0].GetAction() != StatusListSignerAction) {
				t.Errorf("first call must be status-list-signer, got role=%q action=%q", ev.calls[0].Role, ev.calls[0].GetAction())
			}
			switch tc.wantLog {
			case "credential-issuer fallback":
				var found bool
				for _, e := range logs.FilterMessageSnippet("credential-issuer fallback").All() {
					m := e.ContextMap()
					found = found || (m["signer_trust_action"] == "credential-issuer" && m["status_list_signer_error"] != nil)
				}
				if !found {
					t.Errorf("missing fallback warning: %v", logs.All())
				}
			case "signer_untrusted_denied":
				e := logs.FilterMessage("status list signer denied").All()
				if len(e) != 1 || e[0].ContextMap()["reason"] != "signer_untrusted_denied" || e[0].ContextMap()["signer_trust_action"] != "status-list-signer" {
					t.Errorf("missing denied log: %v", logs.All())
				}
			}
			if tc.wantAction == sls && logs.FilterField(zap.String("signer_trust_action", sls)).Len() != 1 {
				t.Errorf("missing signer_trust_action=status-list-signer log")
			}
			if tc.wantLog != "credential-issuer fallback" && logs.FilterMessageSnippet("fallback").Len() != 0 {
				t.Errorf("unexpected fallback log: %v", logs.All())
			}
		})
	}
}

func TestService_EvaluateStatusListSigner_Endpoint(t *testing.T) {
	cfg := &config.Config{Trust: config.TrustConfig{Timeout: 10}}
	cfg.Trust.Issuer.PDPURL = "https://issuer-pdp.example.com"
	eval := &testMockEvaluator{decision: true}
	var gotEndpoint string
	svc := NewService(cfg, zap.NewNop(), func(endpoint string, _ time.Duration) (TrustEvaluator, error) {
		gotEndpoint = endpoint
		return eval, nil
	})
	km := &KeyMaterial{Type: "x5c", X5C: []string{"MIIBxxx"}}
	info, err := svc.EvaluateStatusListSigner(context.Background(), "https://status.example", "", km, true)
	if err != nil || !info.Trusted || info.Action != StatusListSignerAction || StatusListSignerAction != "status-list-signer" {
		t.Fatalf("EvaluateStatusListSigner() = %+v, %v", info, err)
	}
	if gotEndpoint != "https://issuer-pdp.example.com" {
		t.Errorf("endpoint = %q, want the issuer PDP", gotEndpoint)
	}
	if _, err := svc.EvaluateStatusListSigner(context.Background(), "s", "https://override", km, true); err != nil || gotEndpoint != "https://override" {
		t.Errorf("override endpoint = %q, err %v", gotEndpoint, err)
	}
	none := NewService(&config.Config{}, zap.NewNop(), func(string, time.Duration) (TrustEvaluator, error) { return eval, nil })
	info, err = none.EvaluateStatusListSigner(context.Background(), "s", "", km, true)
	if err != nil || info.Trusted || info.Framework != "none" {
		t.Errorf("no PDP: %+v, %v", info, err)
	}
}

// A PDP denial whose reason text merely looks like an evaluation failure is
// still a denial: the typed EvaluationFailed field, not Reason text, decides.
func TestService_EvaluateStatusListSigner_ReasonTextIsNotASignal(t *testing.T) {
	cfg := &config.Config{Trust: config.TrustConfig{Timeout: 10, PDPURL: "https://pdp"}}
	ev := &testMockEvaluator{decision: false, reason: "Trust evaluation failed: spoofed"}
	svc := NewService(cfg, zap.NewNop(), func(string, time.Duration) (TrustEvaluator, error) { return ev, nil })
	info, err := svc.EvaluateStatusListSigner(context.Background(), "s", "", &KeyMaterial{Type: "x5c", X5C: []string{"AA"}}, true)
	if err != nil || info.Trusted || info.EvaluationFailed {
		t.Fatalf("a denial must stay a denial: %+v, %v", info, err)
	}
	ev2 := &testMockEvaluator{returnErr: errors.New("down")}
	svc = NewService(cfg, zap.NewNop(), func(string, time.Duration) (TrustEvaluator, error) { return ev2, nil })
	info, _ = svc.EvaluateStatusListSigner(context.Background(), "s", "", &KeyMaterial{Type: "x5c", X5C: []string{"AA"}}, false)
	if !info.EvaluationFailed {
		t.Fatal("an evaluation error must set EvaluationFailed")
	}
}

// failingEvaluator answers every call with a PDP error or an in-band failure
// whose text embeds the token-controlled marker.
type failingEvaluator struct {
	testMockEvaluator
	inBand bool
	marker string
}

func (f *failingEvaluator) Evaluate(context.Context, *EvaluationRequest) (*EvaluationResponse, error) {
	if f.inBand {
		return &EvaluationResponse{Failed: true, Reason: "pdp broke on " + f.marker}, nil
	}
	return nil, errors.New("transport broke on " + f.marker)
}

func TestService_EvaluateStatusListSigner_LogsAreRedacted(t *testing.T) {
	const marker = "ATTACKER-CONTROLLED-ISS"
	for _, tc := range []struct {
		name string
		ev   TrustEvaluator
	}{
		{"transport error", &failingEvaluator{marker: marker}},
		{"in-band failure", &failingEvaluator{marker: marker, inBand: true}},
		{"denied", &actionEvaluator{answers: map[string]any{"status-list-signer": false}}},
		{"fallback trusted", &actionEvaluator{answers: map[string]any{"status-list-signer": errors.New("down " + marker), "credential-issuer": true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Trust: config.TrustConfig{Timeout: 10, PDPURL: "https://pdp"}}
			core, logs := observer.New(zap.DebugLevel)
			svc := NewService(cfg, zap.New(core), func(string, time.Duration) (TrustEvaluator, error) { return tc.ev, nil })
			km := &KeyMaterial{Type: "x5c", X5C: []string{"MIIBxxx"}}
			if _, err := svc.EvaluateStatusListSigner(context.Background(), marker, "", km, true); err != nil {
				t.Fatal(err)
			}
			if logs.Len() == 0 {
				t.Fatal("expected log output")
			}
			for _, e := range logs.All() {
				if s := fmt.Sprint(e.Message, e.ContextMap()); strings.Contains(s, marker) {
					t.Errorf("log line carries token-controlled content: %s", s)
				}
			}
		})
	}
}

// failedResolver reports an in-band failure from Resolve (Failed=true).
type failedResolver struct{ testMockEvaluator }

func (f *failedResolver) Resolve(_ context.Context, _ string) (*EvaluationResponse, error) {
	return &EvaluationResponse{Decision: false, Reason: "pdp down", Failed: true}, nil
}

func TestResolveDID_InBandFailureIsNotDenial(t *testing.T) {
	cfg := &config.Config{}
	cfg.Trust.PDPURL = "http://pdp.test"
	svc := NewService(cfg, zap.NewNop(), func(_ string, _ time.Duration) (TrustEvaluator, error) {
		return &failedResolver{}, nil
	})
	keys, err := svc.ResolveDID(context.Background(), "did:web:example.com", "")
	if err == nil || keys != nil {
		t.Fatalf("expected error and no keys, got %v, %v", keys, err)
	}
	if !strings.Contains(err.Error(), "failed") || strings.Contains(err.Error(), "denied") {
		t.Errorf("want failure (not denial) error, got %v", err)
	}
}
