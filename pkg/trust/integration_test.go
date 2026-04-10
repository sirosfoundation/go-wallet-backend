package trust_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/testserver"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
	authzenevaluator "github.com/sirosfoundation/go-wallet-backend/pkg/trust/authzen"
)

// newTestService creates a trust.Service wired to an embedded go-trust testserver.
// Returns the service and a cleanup function.
func newTestService(t *testing.T, opts ...testserver.Option) (*trust.Service, func()) {
	t.Helper()

	srv := testserver.New(opts...)

	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  srv.URL(),
			Timeout: 10,
		},
	}

	factory := func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return authzenevaluator.NewEvaluator(&authzenevaluator.Config{
			BaseURL: endpoint,
			Timeout: timeout,
		})
	}

	svc := trust.NewService(cfg, zap.NewNop(), factory)
	return svc, srv.Close
}

// newTestServicePerFlow creates a trust.Service with separate issuer and verifier PDPs.
func newTestServicePerFlow(t *testing.T, issuerOpts []testserver.Option, verifierOpts []testserver.Option) (*trust.Service, func()) {
	t.Helper()

	issuerSrv := testserver.New(issuerOpts...)
	verifierSrv := testserver.New(verifierOpts...)

	cfg := &config.Config{
		Trust: config.TrustConfig{
			Timeout:  10,
			Issuer:   config.FlowTrustConfig{PDPURL: issuerSrv.URL()},
			Verifier: config.FlowTrustConfig{PDPURL: verifierSrv.URL()},
		},
	}

	factory := func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return authzenevaluator.NewEvaluator(&authzenevaluator.Config{
			BaseURL: endpoint,
			Timeout: timeout,
		})
	}

	svc := trust.NewService(cfg, zap.NewNop(), factory)
	return svc, func() {
		issuerSrv.Close()
		verifierSrv.Close()
	}
}

// ---------------------------------------------------------------------------
// Issuer Trust Integration Tests
// ---------------------------------------------------------------------------

func TestIntegration_EvaluateIssuer_AcceptAll(t *testing.T) {
	svc, cleanup := newTestService(t, testserver.WithAcceptAll())
	defer cleanup()

	result, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Errorf("expected Trusted=true, got false (reason: %s)", result.Reason)
	}
	if result.Framework != "authzen" {
		t.Errorf("Framework = %q, want authzen", result.Framework)
	}
}

func TestIntegration_EvaluateIssuer_RejectAll(t *testing.T) {
	svc, cleanup := newTestService(t, testserver.WithRejectAll())
	defer cleanup()

	result, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if result.Trusted {
		t.Error("expected Trusted=false with reject-all PDP")
	}
}

func TestIntegration_EvaluateIssuer_WithJWK(t *testing.T) {
	svc, cleanup := newTestService(t, testserver.WithAcceptAll())
	defer cleanup()

	result, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", &trust.KeyMaterial{
		Type: "jwk",
		JWK:  map[string]interface{}{"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Errorf("expected Trusted=true for JWK issuer, got false (reason: %s)", result.Reason)
	}
}

func TestIntegration_EvaluateIssuer_WithCredentialType(t *testing.T) {
	var capturedReq *authzen.EvaluationRequest

	svc, cleanup := newTestService(t, testserver.WithDecisionFunc(
		func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			capturedReq = req
			return &authzen.EvaluationResponse{Decision: true}, nil
		},
	))
	defer cleanup()

	result, err := svc.EvaluateIssuer(context.Background(), "https://pid-issuer.example.com", "", &trust.KeyMaterial{
		Type:           "x5c",
		X5C:            []string{"MIIBxxx"},
		CredentialType: "eu.europa.ec.eudi.pid.1",
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Errorf("expected Trusted=true, got false (reason: %s)", result.Reason)
	}

	// Verify the AuthZEN request was built correctly
	if capturedReq == nil {
		t.Fatal("DecisionFunc was not called")
	}
	if capturedReq.Subject.ID != "https://pid-issuer.example.com" {
		t.Errorf("Subject.ID = %q, want %q", capturedReq.Subject.ID, "https://pid-issuer.example.com")
	}
	if capturedReq.Action == nil || capturedReq.Action.Name != "credential-issuer" {
		name := ""
		if capturedReq.Action != nil {
			name = capturedReq.Action.Name
		}
		t.Errorf("Action.Name = %q, want credential-issuer", name)
	}
	if capturedReq.Resource.Type != "x5c" {
		t.Errorf("Resource.Type = %q, want x5c", capturedReq.Resource.Type)
	}
}

func TestIntegration_EvaluateIssuer_ResolutionOnly(t *testing.T) {
	svc, cleanup := newTestService(t, testserver.WithAcceptAll())
	defer cleanup()

	// nil key material -> resolution-only mode
	result, err := svc.EvaluateIssuer(context.Background(), "did:web:issuer.example.com", "", nil)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Errorf("expected Trusted=true for resolution-only issuer, got false (reason: %s)", result.Reason)
	}
}

func TestIntegration_EvaluateIssuer_NoEndpoint_FailClosed(t *testing.T) {
	// No PDP configured at all
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL: "", // No PDP
		},
	}
	factory := func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return authzenevaluator.NewEvaluator(&authzenevaluator.Config{
			BaseURL: endpoint,
			Timeout: timeout,
		})
	}

	svc := trust.NewService(cfg, zap.NewNop(), factory)

	result, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if result.Trusted {
		t.Error("expected fail-closed (Trusted=false) when no PDP configured")
	}
}

// ---------------------------------------------------------------------------
// Verifier Trust Integration Tests
// ---------------------------------------------------------------------------

func TestIntegration_EvaluateVerifier_AcceptAll(t *testing.T) {
	svc, cleanup := newTestService(t, testserver.WithAcceptAll())
	defer cleanup()

	result, err := svc.EvaluateVerifier(context.Background(), "https://verifier.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if !result.Trusted {
		t.Errorf("expected Trusted=true, got false (reason: %s)", result.Reason)
	}
}

func TestIntegration_EvaluateVerifier_RejectAll(t *testing.T) {
	svc, cleanup := newTestService(t, testserver.WithRejectAll())
	defer cleanup()

	result, err := svc.EvaluateVerifier(context.Background(), "https://verifier.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if result.Trusted {
		t.Error("expected Trusted=false with reject-all PDP")
	}
}

func TestIntegration_EvaluateVerifier_ActionRouting(t *testing.T) {
	var capturedReq *authzen.EvaluationRequest

	svc, cleanup := newTestService(t, testserver.WithDecisionFunc(
		func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			capturedReq = req
			// Only trust credential-verifier actions
			if req.Action != nil && req.Action.Name == "credential-verifier" {
				return &authzen.EvaluationResponse{Decision: true}, nil
			}
			return &authzen.EvaluationResponse{Decision: false}, nil
		},
	))
	defer cleanup()

	result, err := svc.EvaluateVerifier(context.Background(), "https://rp.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if !result.Trusted {
		t.Errorf("expected Trusted=true for credential-verifier action, got false (reason: %s)", result.Reason)
	}

	if capturedReq == nil {
		t.Fatal("DecisionFunc was not called")
	}
	if capturedReq.Action == nil || capturedReq.Action.Name != "credential-verifier" {
		name := ""
		if capturedReq.Action != nil {
			name = capturedReq.Action.Name
		}
		t.Errorf("Action.Name = %q, want credential-verifier", name)
	}
	if capturedReq.Resource.Type != "x5c" {
		t.Errorf("Resource.Type = %q, want x5c", capturedReq.Resource.Type)
	}
}

func TestIntegration_EvaluateVerifier_X5CChain(t *testing.T) {
	var capturedReq *authzen.EvaluationRequest

	svc, cleanup := newTestService(t, testserver.WithDecisionFunc(
		func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			capturedReq = req
			return &authzen.EvaluationResponse{
				Decision: true,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"registry":     "etsi-tsl",
						"service_type": "http://uri.etsi.org/TrstSvc/Svctype/QCertForESig",
					},
				},
			}, nil
		},
	))
	defer cleanup()

	// Simulate a multi-cert x5c chain (leaf + intermediate)
	certChain := []string{
		"MIIBleafcert...",
		"MIIBintermediate...",
	}

	result, err := svc.EvaluateVerifier(context.Background(), "https://rp.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  certChain,
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if !result.Trusted {
		t.Errorf("expected Trusted=true, got false (reason: %s)", result.Reason)
	}

	// Verify the full chain was sent
	if capturedReq == nil {
		t.Fatal("DecisionFunc was not called")
	}
	if len(capturedReq.Resource.Key) != 2 {
		t.Errorf("Resource.Key has %d entries, want 2", len(capturedReq.Resource.Key))
	}
}

func TestIntegration_EvaluateVerifier_NoEndpoint_FailClosed(t *testing.T) {
	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL: "", // No PDP
		},
	}
	factory := func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return authzenevaluator.NewEvaluator(&authzenevaluator.Config{
			BaseURL: endpoint,
			Timeout: timeout,
		})
	}

	svc := trust.NewService(cfg, zap.NewNop(), factory)

	result, err := svc.EvaluateVerifier(context.Background(), "https://rp.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if result.Trusted {
		t.Error("expected fail-closed (Trusted=false) when no PDP configured")
	}
}

// ---------------------------------------------------------------------------
// Per-Flow PDP Configuration Tests
// ---------------------------------------------------------------------------

func TestIntegration_PerFlowPDP_SeparateEndpoints(t *testing.T) {
	// Issuer PDP accepts all, Verifier PDP rejects all
	svc, cleanup := newTestServicePerFlow(t,
		[]testserver.Option{testserver.WithAcceptAll()},
		[]testserver.Option{testserver.WithRejectAll()},
	)
	defer cleanup()

	// Issuer should be trusted
	issuerResult, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !issuerResult.Trusted {
		t.Errorf("Issuer should be trusted (accept-all PDP), got false (reason: %s)", issuerResult.Reason)
	}

	// Verifier should NOT be trusted
	verifierResult, err := svc.EvaluateVerifier(context.Background(), "https://verifier.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if verifierResult.Trusted {
		t.Error("Verifier should NOT be trusted (reject-all PDP)")
	}
}

func TestIntegration_PerFlowPDP_IssuerOnlyEnabled(t *testing.T) {
	issuerSrv := testserver.New(testserver.WithAcceptAll())
	defer issuerSrv.Close()

	cfg := &config.Config{
		Trust: config.TrustConfig{
			Timeout:  10,
			Issuer:   config.FlowTrustConfig{PDPURL: issuerSrv.URL()},
			Verifier: config.FlowTrustConfig{PDPURL: ""}, // Verifier disabled
		},
	}

	factory := func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return authzenevaluator.NewEvaluator(&authzenevaluator.Config{
			BaseURL: endpoint,
			Timeout: timeout,
		})
	}

	svc := trust.NewService(cfg, zap.NewNop(), factory)

	if !svc.IsIssuerTrustEnabled() {
		t.Error("IsIssuerTrustEnabled() = false, want true")
	}
	if svc.IsVerifierTrustEnabled() {
		t.Error("IsVerifierTrustEnabled() = true, want false")
	}

	// Issuer evaluation works
	issuerResult, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !issuerResult.Trusted {
		t.Errorf("Issuer should be trusted, got false (reason: %s)", issuerResult.Reason)
	}

	// Verifier evaluation fails closed
	verifierResult, err := svc.EvaluateVerifier(context.Background(), "https://verifier.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if verifierResult.Trusted {
		t.Error("Verifier should fail-closed when PDP not configured")
	}
}

// ---------------------------------------------------------------------------
// AuthZEN Wire Protocol Tests
// ---------------------------------------------------------------------------

func TestIntegration_WireProtocol_IssuerRequest(t *testing.T) {
	var capturedReq *authzen.EvaluationRequest

	svc, cleanup := newTestService(t, testserver.WithDecisionFunc(
		func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			capturedReq = req
			return &authzen.EvaluationResponse{Decision: true}, nil
		},
	))
	defer cleanup()

	_, err := svc.EvaluateIssuer(context.Background(), "https://pid-issuer.eudiw.dev", "", &trust.KeyMaterial{
		Type:           "x5c",
		X5C:            []string{"MIIB..leaf", "MIIB..intermediate"},
		CredentialType: "eu.europa.ec.eudi.pid.1",
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}

	if capturedReq == nil {
		t.Fatal("PDP did not receive request")
	}

	// Verify Subject
	if capturedReq.Subject.Type != "key" {
		t.Errorf("Subject.Type = %q, want key", capturedReq.Subject.Type)
	}
	if capturedReq.Subject.ID != "https://pid-issuer.eudiw.dev" {
		t.Errorf("Subject.ID = %q, want https://pid-issuer.eudiw.dev", capturedReq.Subject.ID)
	}

	// Verify Resource
	if capturedReq.Resource.Type != "x5c" {
		t.Errorf("Resource.Type = %q, want x5c", capturedReq.Resource.Type)
	}

	// Verify Action
	if capturedReq.Action == nil {
		t.Fatal("Action is nil")
	}
	if capturedReq.Action.Name != "credential-issuer" {
		t.Errorf("Action.Name = %q, want credential-issuer", capturedReq.Action.Name)
	}
}

func TestIntegration_WireProtocol_VerifierRequest(t *testing.T) {
	var capturedReq *authzen.EvaluationRequest

	svc, cleanup := newTestService(t, testserver.WithDecisionFunc(
		func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			capturedReq = req
			return &authzen.EvaluationResponse{Decision: true}, nil
		},
	))
	defer cleanup()

	_, err := svc.EvaluateVerifier(context.Background(), "https://rp.eudiw.dev", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIB..leaf"},
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}

	if capturedReq == nil {
		t.Fatal("PDP did not receive request")
	}

	// Verify Subject
	if capturedReq.Subject.Type != "key" {
		t.Errorf("Subject.Type = %q, want key", capturedReq.Subject.Type)
	}
	if capturedReq.Subject.ID != "https://rp.eudiw.dev" {
		t.Errorf("Subject.ID = %q, want https://rp.eudiw.dev", capturedReq.Subject.ID)
	}

	// Verify Resource
	if capturedReq.Resource.Type != "x5c" {
		t.Errorf("Resource.Type = %q, want x5c", capturedReq.Resource.Type)
	}

	// Verify Action routes to credential-verifier
	if capturedReq.Action == nil {
		t.Fatal("Action is nil")
	}
	if capturedReq.Action.Name != "credential-verifier" {
		t.Errorf("Action.Name = %q, want credential-verifier", capturedReq.Action.Name)
	}
}

func TestIntegration_WireProtocol_ResponseReasonPropagation(t *testing.T) {
	svc, cleanup := newTestService(t, testserver.WithDecisionFunc(
		func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			return &authzen.EvaluationResponse{
				Decision: true,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"registry":     "etsi-tsl",
						"service_type": "http://uri.etsi.org/TrstSvc/Svctype/QCertForESig",
						"message":      "certificate validated against Swedish TSL",
					},
				},
			}, nil
		},
	))
	defer cleanup()

	result, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !result.Trusted {
		t.Error("expected Trusted=true")
	}
	if result.Reason != "certificate validated against Swedish TSL" {
		t.Errorf("Reason = %q, want reason from PDP response", result.Reason)
	}
}

func TestIntegration_WireProtocol_ErrorReasonPropagation(t *testing.T) {
	svc, cleanup := newTestService(t, testserver.WithDecisionFunc(
		func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			return &authzen.EvaluationResponse{
				Decision: false,
				Context: &authzen.EvaluationResponseContext{
					Reason: map[string]interface{}{
						"error": "certificate chain does not terminate at a trusted root",
					},
				},
			}, nil
		},
	))
	defer cleanup()

	result, err := svc.EvaluateVerifier(context.Background(), "https://untrusted-rp.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if result.Trusted {
		t.Error("expected Trusted=false")
	}
	// The reason comes from the PDP; the registry manager may wrap it
	if result.Reason == "" {
		t.Error("expected non-empty Reason from PDP response")
	}
}

// ---------------------------------------------------------------------------
// Session Override Tests
// ---------------------------------------------------------------------------

func TestIntegration_SessionOverride_IssuerEndpoint(t *testing.T) {
	// Default PDP rejects, session PDP accepts
	defaultSrv := testserver.New(testserver.WithRejectAll())
	defer defaultSrv.Close()

	sessionSrv := testserver.New(testserver.WithAcceptAll())
	defer sessionSrv.Close()

	cfg := &config.Config{
		Trust: config.TrustConfig{
			PDPURL:  defaultSrv.URL(),
			Timeout: 10,
		},
	}

	factory := func(endpoint string, timeout time.Duration) (trust.TrustEvaluator, error) {
		return authzenevaluator.NewEvaluator(&authzenevaluator.Config{
			BaseURL: endpoint,
			Timeout: timeout,
		})
	}

	svc := trust.NewService(cfg, zap.NewNop(), factory)

	// Without override - rejected
	result, err := svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", "", &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if result.Trusted {
		t.Error("expected Trusted=false without session override")
	}

	// With session override - accepted
	result, err = svc.EvaluateIssuer(context.Background(), "https://issuer.example.com", sessionSrv.URL(), &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	})
	if err != nil {
		t.Fatalf("EvaluateIssuer() with override error = %v", err)
	}
	if !result.Trusted {
		t.Errorf("expected Trusted=true with session override, got false (reason: %s)", result.Reason)
	}
}

// ---------------------------------------------------------------------------
// Policy-Based Decision Tests
// ---------------------------------------------------------------------------

func TestIntegration_PolicyDecision_IssuerVsVerifier(t *testing.T) {
	// PDP makes decisions based on action.name
	svc, cleanup := newTestService(t, testserver.WithDecisionFunc(
		func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
			if req.Action == nil {
				return &authzen.EvaluationResponse{Decision: false}, nil
			}
			switch req.Action.Name {
			case "credential-issuer":
				return &authzen.EvaluationResponse{
					Decision: true,
					Context: &authzen.EvaluationResponseContext{
						Reason: map[string]interface{}{
							"message": "issuer trusted by ETSI TSL",
						},
					},
				}, nil
			case "credential-verifier":
				return &authzen.EvaluationResponse{
					Decision: false,
					Context: &authzen.EvaluationResponseContext{
						Reason: map[string]interface{}{
							"error": "verifier not in trusted registry",
						},
					},
				}, nil
			default:
				return &authzen.EvaluationResponse{Decision: false}, nil
			}
		},
	))
	defer cleanup()

	// Same PDP, same subject, same key material - different decisions by role
	km := &trust.KeyMaterial{
		Type: "x5c",
		X5C:  []string{"MIIBxxx"},
	}

	issuerResult, err := svc.EvaluateIssuer(context.Background(), "https://entity.example.com", "", km)
	if err != nil {
		t.Fatalf("EvaluateIssuer() error = %v", err)
	}
	if !issuerResult.Trusted {
		t.Errorf("Issuer should be trusted, got false (reason: %s)", issuerResult.Reason)
	}

	verifierResult, err := svc.EvaluateVerifier(context.Background(), "https://entity.example.com", "", km)
	if err != nil {
		t.Fatalf("EvaluateVerifier() error = %v", err)
	}
	if verifierResult.Trusted {
		t.Error("Verifier should NOT be trusted")
	}
	if verifierResult.Reason == "" {
		t.Error("Verifier reason should not be empty")
	}
}
