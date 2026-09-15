package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sirosfoundation/go-wallet-backend/internal/service"
)

func TestLifecycleRefusal(t *testing.T) {
	tests := []struct {
		name, code, wantMsg string
		err                 error
	}{
		{"suspended", "WALLET_SUSPENDED", "suspended", service.ErrWalletInstanceSuspended},
		{"single instance revoked", "WALLET_REVOKED", "other devices enrolled to this wallet are not affected", service.ErrWalletInstanceRevoked},
		{"wallet deactivated", "WALLET_REVOKED", "a new enrollment is required", service.ErrWalletDeactivated},
		{"wrapped deactivated", "WALLET_REVOKED", "a new enrollment is required", fmt.Errorf("finish login: %w", service.ErrWalletDeactivated)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, msg := lifecycleRefusal(tt.err)
			assert.Equal(t, tt.code, code)
			assert.Contains(t, msg, tt.wantMsg)
		})
	}
}
