package authz

import (
	"context"
	"os"
	"testing"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"go.uber.org/zap"
)

func TestSPOCPAuthorizer_DefaultRules(t *testing.T) {
	logger := zap.NewNop()

	auth, err := NewSPOCPAuthorizer(nil, logger)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	tests := []struct {
		name       string
		tenantID   string
		request    *gotrust.EvaluationRequest
		shouldPass bool
	}{
		{
			name:     "credential-issuer with JWK",
			tenantID: "default",
			request: &gotrust.EvaluationRequest{
				Subject: gotrust.Subject{
					Type: "key",
					ID:   "https://issuer.example.com",
				},
				Resource: gotrust.Resource{
					Type: "jwk",
					ID:   "https://issuer.example.com",
				},
				Action: &gotrust.Action{
					Name: "credential-issuer",
				},
			},
			shouldPass: true,
		},
		{
			name:     "credential-verifier with x5c",
			tenantID: "default",
			request: &gotrust.EvaluationRequest{
				Subject: gotrust.Subject{
					Type: "key",
					ID:   "x509_san_dns:verifier.example.com",
				},
				Resource: gotrust.Resource{
					Type: "x5c",
					ID:   "x509_san_dns:verifier.example.com",
				},
				Action: &gotrust.Action{
					Name: "credential-verifier",
				},
			},
			shouldPass: true,
		},
		{
			name:     "resolution for DID",
			tenantID: "default",
			request: &gotrust.EvaluationRequest{
				Subject: gotrust.Subject{
					Type: "key",
					ID:   "did:web:example.com",
				},
				Resource: gotrust.Resource{
					Type: "resolution",
					ID:   "did:web:example.com",
				},
			},
			shouldPass: true,
		},
		{
			name:     "resolution for OIDF entity",
			tenantID: "default",
			request: &gotrust.EvaluationRequest{
				Subject: gotrust.Subject{
					Type: "key",
					ID:   "https://federation.example.com",
				},
				Resource: gotrust.Resource{
					Type: "resolution",
					ID:   "https://federation.example.com",
				},
			},
			shouldPass: true,
		},
		{
			name:     "unsupported action",
			tenantID: "default",
			request: &gotrust.EvaluationRequest{
				Subject: gotrust.Subject{
					Type: "key",
					ID:   "https://example.com",
				},
				Resource: gotrust.Resource{
					Type: "jwk",
					ID:   "https://example.com",
				},
				Action: &gotrust.Action{
					Name: "admin-action",
				},
			},
			shouldPass: false,
		},
		{
			name:     "unsupported resource type",
			tenantID: "default",
			request: &gotrust.EvaluationRequest{
				Subject: gotrust.Subject{
					Type: "key",
					ID:   "https://example.com",
				},
				Resource: gotrust.Resource{
					Type: "unknown",
					ID:   "https://example.com",
				},
				Action: &gotrust.Action{
					Name: "credential-issuer",
				},
			},
			shouldPass: false,
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &AuthorizationRequest{
				TenantID: tt.tenantID,
				UserID:   "user-123",
				Request:  tt.request,
			}

			err := auth.Authorize(ctx, req)
			if tt.shouldPass && err != nil {
				t.Errorf("expected authorization to pass, but got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected authorization to fail, but it passed")
			}
		})
	}
}

func TestSPOCPAuthorizer_CustomRules(t *testing.T) {
	logger := zap.NewNop()

	// Custom rules that only allow credential-issuer with jwk
	customRules := []sexp.Element{
		sexp.NewList("authzen",
			sexp.NewList("tenant"),
			sexp.NewList("action", sexp.NewAtom("credential-issuer")),
			sexp.NewList("resource",
				sexp.NewList("type", sexp.NewAtom("jwk")),
				sexp.NewList("id"),
			),
			sexp.NewList("subject",
				sexp.NewList("type", sexp.NewAtom("key")),
				sexp.NewList("id"),
			),
		),
	}

	auth, err := NewSPOCPAuthorizer(&SPOCPConfig{DefaultRules: customRules}, logger)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	ctx := context.Background()

	// This should pass
	issuerReq := &AuthorizationRequest{
		TenantID: "default",
		Request: &gotrust.EvaluationRequest{
			Subject:  gotrust.Subject{Type: "key", ID: "issuer"},
			Resource: gotrust.Resource{Type: "jwk", ID: "issuer"},
			Action:   &gotrust.Action{Name: "credential-issuer"},
		},
	}
	if err := auth.Authorize(ctx, issuerReq); err != nil {
		t.Errorf("expected credential-issuer to pass: %v", err)
	}

	// This should fail (custom rules don't allow credential-verifier)
	verifierReq := &AuthorizationRequest{
		TenantID: "default",
		Request: &gotrust.EvaluationRequest{
			Subject:  gotrust.Subject{Type: "key", ID: "verifier"},
			Resource: gotrust.Resource{Type: "jwk", ID: "verifier"},
			Action:   &gotrust.Action{Name: "credential-verifier"},
		},
	}
	if err := auth.Authorize(ctx, verifierReq); err == nil {
		t.Errorf("expected credential-verifier to fail with custom rules")
	}
}

func TestNoOpAuthorizer(t *testing.T) {
	ctx := context.Background()
	auth := NoOpAuthorizer{}

	// NoOp should always pass
	req := &AuthorizationRequest{
		TenantID: "default",
		Request: &gotrust.EvaluationRequest{
			Subject:  gotrust.Subject{Type: "key", ID: "any"},
			Resource: gotrust.Resource{Type: "any", ID: "any"},
			Action:   &gotrust.Action{Name: "any-action"},
		},
	}

	if err := auth.Authorize(ctx, req); err != nil {
		t.Errorf("NoOp authorizer should always pass: %v", err)
	}
}

func TestSPOCPAuthorizer_NilRequest(t *testing.T) {
	logger := zap.NewNop()

	auth, err := NewSPOCPAuthorizer(nil, logger)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	ctx := context.Background()
	req := &AuthorizationRequest{
		TenantID: "default",
		Request:  nil,
	}

	err = auth.Authorize(ctx, req)
	if err != ErrInvalidQuery {
		t.Errorf("expected ErrInvalidQuery for nil request, got: %v", err)
	}
}

func TestSPOCPAuthorizer_LoadRulesFile(t *testing.T) {
	logger := zap.NewNop()

	// Create a temporary rules file with multi-line s-expressions
	tmpDir := t.TempDir()
	rulesFile := tmpDir + "/rules.txt"

	// Rules file with:
	// - Comment using # (hash)
	// - Comment using ; (semicolon)
	// - Multi-line S-expression
	// - Single-line S-expression
	rulesContent := `# Allow credential-issuer with JWK (comment with hash)
; This is a multi-line rule (comment with semicolon)
(7:authzen
  (6:tenant)
  (6:action17:credential-issuer)
  (8:resource
    (4:type3:jwk)
    (2:id))
  (7:subject
    (4:type3:key)
    (2:id)))
# Allow resolution
(7:authzen(6:tenant)(6:action)(8:resource(4:type10:resolution)(2:id))(7:subject(4:type3:key)(2:id)))
`

	if err := os.WriteFile(rulesFile, []byte(rulesContent), 0644); err != nil {
		t.Fatalf("failed to write rules file: %v", err)
	}

	auth, err := NewSPOCPAuthorizer(&SPOCPConfig{RulesFile: rulesFile}, logger)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	ctx := context.Background()

	// This should pass (credential-issuer with JWK from multi-line rule)
	issuerReq := &AuthorizationRequest{
		TenantID: "default",
		Request: &gotrust.EvaluationRequest{
			Subject:  gotrust.Subject{Type: "key", ID: "issuer"},
			Resource: gotrust.Resource{Type: "jwk", ID: "issuer"},
			Action:   &gotrust.Action{Name: "credential-issuer"},
		},
	}
	if err := auth.Authorize(ctx, issuerReq); err != nil {
		t.Errorf("expected credential-issuer to pass: %v", err)
	}

	// This should pass (resolution from single-line rule)
	resolveReq := &AuthorizationRequest{
		TenantID: "default",
		Request: &gotrust.EvaluationRequest{
			Subject:  gotrust.Subject{Type: "key", ID: "did:web:example.com"},
			Resource: gotrust.Resource{Type: "resolution", ID: "did:web:example.com"},
		},
	}
	if err := auth.Authorize(ctx, resolveReq); err != nil {
		t.Errorf("expected resolution to pass: %v", err)
	}

	// This should fail (credential-verifier not in rules)
	verifierReq := &AuthorizationRequest{
		TenantID: "default",
		Request: &gotrust.EvaluationRequest{
			Subject:  gotrust.Subject{Type: "key", ID: "verifier"},
			Resource: gotrust.Resource{Type: "jwk", ID: "verifier"},
			Action:   &gotrust.Action{Name: "credential-verifier"},
		},
	}
	if err := auth.Authorize(ctx, verifierReq); err == nil {
		t.Errorf("expected credential-verifier to fail (not in custom rules)")
	}
}
