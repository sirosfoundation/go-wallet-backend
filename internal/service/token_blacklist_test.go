package service

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func newTestBlacklist(t *testing.T) *TokenBlacklist {
	t.Helper()
	return NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop())
}

func TestTokenBlacklist_AddAndIsBlacklisted(t *testing.T) {
	ctx := context.Background()
	b := newTestBlacklist(t)

	if b.IsBlacklisted(ctx, "jti-1") {
		t.Error("expected jti-1 not to be blacklisted before Add")
	}

	if err := b.Add(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if !b.IsBlacklisted(ctx, "jti-1") {
		t.Error("expected jti-1 to be blacklisted after Add")
	}
	if b.Count() != 1 {
		t.Errorf("Count() = %d, want 1", b.Count())
	}

	// Empty jti is a no-op in both directions.
	if err := b.Add(ctx, "", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Add empty jti: %v", err)
	}
	if b.IsBlacklisted(ctx, "") {
		t.Error("empty jti should never be blacklisted")
	}
}

func TestTokenBlacklist_IsBlacklisted_ExpiredEntryNotBlacklisted(t *testing.T) {
	ctx := context.Background()
	b := newTestBlacklist(t)

	// An entry whose own expiry has already passed (the token itself would
	// already fail its own "exp" check) reports as not blacklisted, without
	// needing the cleanup loop to have run yet.
	if err := b.Add(ctx, "jti-expired", time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if b.IsBlacklisted(ctx, "jti-expired") {
		t.Error("expected an entry past its own expiry not to be blacklisted")
	}
}

func TestTokenBlacklist_Remove(t *testing.T) {
	ctx := context.Background()
	b := newTestBlacklist(t)

	if err := b.Add(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := b.Remove(ctx, "jti-1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if b.IsBlacklisted(ctx, "jti-1") {
		t.Error("expected jti-1 not to be blacklisted after Remove")
	}
}

func TestTokenBlacklist_Disabled_NoOps(t *testing.T) {
	ctx := context.Background()
	b := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop())

	if err := b.Add(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if b.IsBlacklisted(ctx, "jti-1") {
		t.Error("expected IsBlacklisted to always return false when disabled")
	}
	if err := b.RevokeUser(ctx, "user-1"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}
	if b.IsUserRevoked(ctx, "user-1", time.Now()) {
		t.Error("expected IsUserRevoked to always return false when disabled")
	}
}

// TestTokenBlacklist_Cleanup_RemovesExpiredJTIsAndStaleRevocations exercises
// cleanup() directly (it otherwise only ever runs on a real ticker via
// Start/cleanupLoop, which no test invokes) - both the pre-existing
// per-jti expiry sweep and the new per-user revocation retention sweep
// (userRevocationRetention) added alongside RevokeUser/IsUserRevoked.
func TestTokenBlacklist_Cleanup_RemovesExpiredJTIsAndStaleRevocations(t *testing.T) {
	ctx := context.Background()
	b := newTestBlacklist(t)

	if err := b.Add(ctx, "jti-expired", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := b.Add(ctx, "jti-live", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := b.RevokeUser(ctx, "user-stale"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}
	if err := b.RevokeUser(ctx, "user-recent"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}
	// Backdate one revocation past the retention window directly (same
	// package - unexported field access), the other stays recent.
	b.mu.Lock()
	b.userRevocations["user-stale"] = time.Now().Add(-(userRevocationRetention + time.Hour))
	b.mu.Unlock()

	b.cleanup()

	if b.Count() != 1 {
		t.Errorf("Count() after cleanup = %d, want 1 (only jti-live should remain)", b.Count())
	}
	if b.IsBlacklisted(ctx, "jti-expired") {
		t.Error("expected jti-expired to be removed by cleanup")
	}
	if !b.IsBlacklisted(ctx, "jti-live") {
		t.Error("expected jti-live to survive cleanup")
	}

	b.mu.RLock()
	_, staleStillPresent := b.userRevocations["user-stale"]
	_, recentStillPresent := b.userRevocations["user-recent"]
	b.mu.RUnlock()

	if staleStillPresent {
		t.Error("expected user-stale's revocation entry to be removed by cleanup (past retention)")
	}
	if !recentStillPresent {
		t.Error("expected user-recent's revocation entry to survive cleanup (within retention)")
	}
}

func TestTokenBlacklist_StartStop_Disabled(t *testing.T) {
	// Start() on a disabled blacklist logs and returns without launching the
	// cleanup goroutine; Stop() must still be safe to call afterward.
	b := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop())
	b.Start()
	b.Stop()
}
