package audience

import (
	"testing"

	"github.com/sirosfoundation/go-tokenauth/claims"
)

func TestAllowed(t *testing.T) {
	legacy := &claims.Result{Mode: claims.ModeLegacy, Audience: []string{"rp.example.com"}}
	session := &claims.Result{Mode: claims.ModeSession, Audience: []string{"wallet-engine"}}
	ok := &claims.Result{Mode: claims.ModeSession, Audience: []string{"wallet-registry"}}

	if !Allowed(legacy, true, "wallet-registry") {
		t.Error("legacy must be admitted when admitLegacy is true")
	}
	if Allowed(legacy, false, "wallet-registry") {
		t.Error("legacy must NOT be admitted when admitLegacy is false")
	}
	if Allowed(session, true, "wallet-registry") {
		t.Error("session token with other audience must be refused even if admitLegacy")
	}
	if !Allowed(ok, false, "wallet-registry", "wallet-backend") {
		t.Error("matching audience must be allowed")
	}
}
