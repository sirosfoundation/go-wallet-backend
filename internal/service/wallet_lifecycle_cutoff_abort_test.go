package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
)

// seedRevokedWithStaleCutoff leaves the state of a half-finished revocation:
// the instance is revoked, the user's cut-off predates that revocation, and the
// wallet data is still there.
func seedRevokedWithStaleCutoff(t *testing.T, fs *failStore) (domain.UserID, *domain.WalletInstance) {
	t.Helper()
	ctx := context.Background()
	uid := seedWalletUser(t, fs.Store)
	id := "inst-" + uid.String()
	require.NoError(t, fs.Store.Users().InvalidateAuthBefore(ctx, uid, time.Now().Add(-time.Hour)))
	require.NoError(t, fs.Store.WalletInstances().UpdateStatus(ctx, id, domain.DefaultTenantID, domain.InstanceStatusRevoked, "stolen"))
	inst, err := fs.Store.WalletInstances().GetByID(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, inst.DeactivatedAt)
	return uid, inst
}

func vaultKept(t *testing.T, fs *failStore, uid domain.UserID) bool {
	t.Helper()
	u, err := fs.Store.Users().GetByID(context.Background(), uid)
	require.NoError(t, err)
	return u.PrivateData != nil
}

// A cut-off that cannot be read must stop the cascade before erasure: the
// erased wallet could otherwise be written back by an already-issued token.
func TestWalletLifecycle_CascadeAbortsBeforeErasureWhenCutoffCannotBeRead(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore("users.GetAuthCutoff")
	svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
	uid, inst := seedRevokedWithStaleCutoff(t, fs)

	err := svc.CascadeForRevoked(ctx, domain.DefaultTenantID, inst, userActor(uid))
	require.ErrorIs(t, err, ErrErasureIncomplete)
	assert.True(t, vaultKept(t, fs, uid), "nothing is erased while the cut-off is unknown")

	delete(fs.fail, "users.GetAuthCutoff")
	require.NoError(t, svc.CascadeForRevoked(ctx, domain.DefaultTenantID, inst, userActor(uid)), "retryable")
	assert.False(t, vaultKept(t, fs, uid))
}

// A cut-off older than the revocation that cannot be repaired must stop the
// cascade before erasure; once the store works, the retry repairs and erases.
func TestWalletLifecycle_CascadeRepairsStaleCutoffBeforeErasure(t *testing.T) {
	ctx := context.Background()
	fs := newFailStore("users.InvalidateAuthBefore")
	svc := NewWalletLifecycleService(fs, zap.NewNop(), nil)
	uid, inst := seedRevokedWithStaleCutoff(t, fs)

	err := svc.CascadeForRevoked(ctx, domain.DefaultTenantID, inst, userActor(uid))
	require.ErrorIs(t, err, ErrErasureIncomplete)
	assert.True(t, vaultKept(t, fs, uid), "nothing is erased while the cut-off predates the revocation")

	delete(fs.fail, "users.InvalidateAuthBefore")
	require.NoError(t, svc.CascadeForRevoked(ctx, domain.DefaultTenantID, inst, userActor(uid)))
	cutoff, err := fs.Store.Users().GetAuthCutoff(ctx, uid)
	require.NoError(t, err)
	assert.False(t, cutoff.Before(*inst.DeactivatedAt), "cut-off repaired to at least the revocation time")
	assert.False(t, vaultKept(t, fs, uid))
}
