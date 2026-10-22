package service

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Clients switch on code and scope, never the message: a deactivated wallet
// must be told apart from one revoked instance.
func TestLifecycleRefusalDetails(t *testing.T) {
	wallet := LifecycleRefusalDetails(fmt.Errorf("login: %w", ErrWalletDeactivated))
	assert.Equal(t, "WALLET_REVOKED", wallet.Code)
	assert.Equal(t, LifecycleScopeWallet, wallet.Scope)
	assert.NotEmpty(t, wallet.Message)

	instance := LifecycleRefusalDetails(fmt.Errorf("login: %w", ErrWalletInstanceRevoked))
	assert.Equal(t, "WALLET_REVOKED", instance.Code, "the code stays the one existing clients switch on")
	assert.Equal(t, LifecycleScopeInstance, instance.Scope)
	assert.NotEqual(t, wallet.Message, instance.Message)
}
