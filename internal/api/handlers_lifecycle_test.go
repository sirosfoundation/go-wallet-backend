package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

// TestLifecycleRefusalBody pins the 403 body of a SID-AUTH-06 login refusal,
// including the `scope` that tells WALLET_REVOKED for one instance from the whole wallet.
func TestLifecycleRefusalBody(t *testing.T) {
	tests := []struct {
		name, code, scope, wantMsg string
		err                        error
	}{
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

// TestLifecycleRefusalScopeSeparatesRevocationFromDeactivation: the two
// WALLET_REVOKED refusals differ in scope, so clients need not parse prose.
func TestLifecycleRefusalScopeSeparatesRevocationFromDeactivation(t *testing.T) {
	instance := service.LifecycleRefusalDetails(service.ErrWalletInstanceRevoked)
	wallet := service.LifecycleRefusalDetails(service.ErrWalletDeactivated)

	assert.Equal(t, instance.Code, wallet.Code, "the codes are deliberately the same, for existing clients")
	assert.NotEqual(t, instance.Scope, wallet.Scope, "the scope is what tells them apart")
	assert.Equal(t, service.LifecycleScopeInstance, instance.Scope)
	assert.Equal(t, service.LifecycleScopeWallet, wallet.Scope)
}
