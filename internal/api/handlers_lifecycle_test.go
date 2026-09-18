package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

// TestLifecycleRefusalBody pins the 403 body of a SID-AUTH-06 login refusal.
// The code cases are the ones this test has always covered; the `scope`
// assertions are the addition: WALLET_REVOKED means both "this instance" and
// "the whole wallet", and a client must be able to tell them apart without
// reading the message.
func TestLifecycleRefusalBody(t *testing.T) {
	tests := []struct {
		name, code, scope, wantMsg string
		err                        error
	}{
		{"suspended", "WALLET_SUSPENDED", service.LifecycleScopeInstance, "suspended", service.ErrWalletInstanceSuspended},
		{"single instance revoked", "WALLET_REVOKED", service.LifecycleScopeInstance, "other devices enrolled to this wallet keep their own status", service.ErrWalletInstanceRevoked},
		{"wallet deactivated", "WALLET_REVOKED", service.LifecycleScopeWallet, "a new enrollment is required", service.ErrWalletDeactivated},
		{"wrapped deactivated", "WALLET_REVOKED", service.LifecycleScopeWallet, "a new enrollment is required", fmt.Errorf("finish login: %w", service.ErrWalletDeactivated)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := lifecycleRefusalBody(tt.err)
			assert.Equal(t, tt.code, body["error"])
			assert.Equal(t, tt.scope, body["scope"])
			assert.Contains(t, body["message"], tt.wantMsg)
		})
	}
}

// TestLifecycleRefusalScopeSeparatesRevocationFromDeactivation states the
// point of the field: the two refusals that share WALLET_REVOKED differ in
// scope, so no client has to parse prose to decide whether its wallet still
// exists.
func TestLifecycleRefusalScopeSeparatesRevocationFromDeactivation(t *testing.T) {
	instance := service.LifecycleRefusalDetails(service.ErrWalletInstanceRevoked)
	wallet := service.LifecycleRefusalDetails(service.ErrWalletDeactivated)

	assert.Equal(t, instance.Code, wallet.Code, "the codes are deliberately the same, for existing clients")
	assert.NotEqual(t, instance.Scope, wallet.Scope, "the scope is what tells them apart")
	assert.Equal(t, service.LifecycleScopeInstance, instance.Scope)
	assert.Equal(t, service.LifecycleScopeWallet, wallet.Scope)
}
