package authz

import (
	"context"
	"testing"

	gotrust "github.com/sirosfoundation/go-trust/pkg/authzen"
	"go.uber.org/zap"
)

// TestDefaultRules_KidResourceType covers the query wallet-common sends when a
// verifier's request JWT header carries a `kid` rather than an inline `jwk` --
// the normal shape for a DID-based client_id.
//
// "kid" was absent from the allowed key types, so this query was refused by
// the proxy's own firewall before it ever reached the PDP:
//
//	"msg": "query authorization denied", "action": "credential-verifier",
//	"error": "query not authorized"
func TestDefaultRules_KidResourceType(t *testing.T) {
	auth, err := NewSPOCPAuthorizer(nil, zap.NewNop())
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	const did = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0"

	authorize := func(t *testing.T, resourceType, action string) error {
		t.Helper()
		return auth.Authorize(context.Background(), &AuthorizationRequest{
			TenantID: "default",
			Request: &gotrust.EvaluationRequest{
				Subject:  gotrust.Subject{Type: "key", ID: did},
				Resource: gotrust.Resource{Type: resourceType, ID: did, Key: []interface{}{did + "#0"}},
				Action:   &gotrust.Action{Name: action},
			},
		})
	}

	t.Run("credential-verifier with a kid is allowed", func(t *testing.T) {
		if err := authorize(t, "kid", "credential-verifier"); err != nil {
			t.Errorf("expected the wallet's verifier query to be authorized, got %v", err)
		}
	})

	t.Run("credential-issuer with a kid is allowed", func(t *testing.T) {
		// An issuer identified by a DID signs the same way.
		if err := authorize(t, "kid", "credential-issuer"); err != nil {
			t.Errorf("expected the issuer query to be authorized, got %v", err)
		}
	})

	t.Run("an unknown resource type is still refused", func(t *testing.T) {
		// The firewall still has to be a firewall.
		if err := authorize(t, "pem", "credential-verifier"); err == nil {
			t.Error("expected an unknown resource type to be refused")
		}
	})

	t.Run("an unknown action with a kid is still refused", func(t *testing.T) {
		if err := authorize(t, "kid", "drop-everything"); err == nil {
			t.Error("expected an unknown action to be refused")
		}
	})
}
