package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// The cascade's "is anything live? then erase" step must not interleave with
// a first attestation's instance write: the cascade waits for the holder of
// the user's lifecycle lock.
func TestCascade_WaitsForTheUserLifecycleLock(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	uid := seedWalletUser(t, store)
	id := "inst-" + uid.String()
	inst, err := store.WalletInstances().GetByID(ctx, id)
	require.NoError(t, err)
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, id, domain.DefaultTenantID, domain.InstanceStatusRevoked, "x"))
	inst.Status = domain.InstanceStatusRevoked

	unlock := svc.LockUser(uid)
	done := make(chan error, 1)
	go func() { done <- svc.CascadeForRevoked(ctx, domain.DefaultTenantID, inst, providerActor) }()

	select {
	case <-done:
		t.Fatal("cascade ran while the user's lifecycle lock was held")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("cascade did not proceed after the lock was released")
	}
}

// A holder of the lock runs the cascade through the Locked variant without
// deadlocking (WIAService's raced-first-attestation path).
func TestCascadeForRevokedLocked_DoesNotRelock(t *testing.T) {
	ctx := context.Background()
	store := memory.NewStore()
	svc := NewWalletLifecycleService(store, zap.NewNop(), nil)
	uid := seedWalletUser(t, store)
	inst, err := store.WalletInstances().GetByID(ctx, "inst-"+uid.String())
	require.NoError(t, err)
	require.NoError(t, store.WalletInstances().UpdateStatus(ctx, inst.ID, domain.DefaultTenantID, domain.InstanceStatusRevoked, "x"))
	inst.Status = domain.InstanceStatusRevoked

	unlock := svc.LockUser(uid)
	defer unlock()
	done := make(chan error, 1)
	go func() { done <- svc.CascadeForRevokedLocked(ctx, domain.DefaultTenantID, inst, providerActor) }()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: the Locked variant took the lock again")
	}
}

func TestUserLocks_AreReleasedWhenIdle(t *testing.T) {
	var l userLocks
	a, b := domain.NewUserID(), domain.NewUserID()
	ua, ub := l.lock(a), l.lock(b) // different users do not block each other
	ua()
	ub()
	assert.Empty(t, l.m, "idle entries are dropped")
}
