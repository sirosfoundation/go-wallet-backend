package service

import (
	"context"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

// CheckWalletLifecycleForTest exposes the SID-AUTH-06 login gate to the
// external test package, which can drive the admin handlers without an
// import cycle.
func CheckWalletLifecycleForTest(ctx context.Context, store storage.Store, tenantID domain.TenantID, userID domain.UserID, credentialID string) error {
	return (&WebAuthnService{store: store}).checkWalletLifecycle(ctx, tenantID, userID, credentialID)
}
