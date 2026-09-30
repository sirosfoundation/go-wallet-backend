package service

import (
	"context"
	"sync"
	"sync/atomic"
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

// TestTokenBlacklist_ConsumeOnce covers the atomic, always-on primitive
// added for WebAuthnService.RefreshAccessToken's single-use enforcement
// (Copilot review on go-wallet-backend#400): unlike Add/IsBlacklisted,
// ConsumeOnce must work even when the blacklist feature is disabled, and
// must be safe under concurrent use of the same jti.
func TestTokenBlacklist_ConsumeOnce(t *testing.T) {
	ctx := context.Background()

	t.Run("first call returns true, every subsequent call returns false", func(t *testing.T) {
		b := newTestBlacklist(t)
		expiry := time.Now().Add(time.Hour)

		first, err := b.ConsumeOnce(ctx, "jti-consume-1", expiry)
		if err != nil || !first {
			t.Fatalf("first ConsumeOnce: firstUse=%v err=%v, want true/nil", first, err)
		}

		second, err := b.ConsumeOnce(ctx, "jti-consume-1", expiry)
		if err != nil || second {
			t.Fatalf("second ConsumeOnce: firstUse=%v err=%v, want false/nil", second, err)
		}
	})

	t.Run("works even when the blacklist feature is disabled", func(t *testing.T) {
		b := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop())
		expiry := time.Now().Add(time.Hour)

		first, err := b.ConsumeOnce(ctx, "jti-consume-2", expiry)
		if err != nil || !first {
			t.Fatalf("first ConsumeOnce (disabled feature): firstUse=%v err=%v, want true/nil", first, err)
		}
		second, err := b.ConsumeOnce(ctx, "jti-consume-2", expiry)
		if err != nil || second {
			t.Fatalf("second ConsumeOnce (disabled feature): firstUse=%v err=%v, want false/nil", second, err)
		}
	})

	t.Run("empty jti is always treated as first use (untracked)", func(t *testing.T) {
		b := newTestBlacklist(t)
		expiry := time.Now().Add(time.Hour)

		for i := 0; i < 3; i++ {
			first, err := b.ConsumeOnce(ctx, "", expiry)
			if err != nil || !first {
				t.Fatalf("ConsumeOnce(\"\") call %d: firstUse=%v err=%v, want true/nil", i, first, err)
			}
		}
	})

	t.Run("a jti past its own recorded expiry can be consumed again", func(t *testing.T) {
		b := newTestBlacklist(t)

		first, err := b.ConsumeOnce(ctx, "jti-consume-3", time.Now().Add(-time.Hour))
		if err != nil || !first {
			t.Fatalf("first ConsumeOnce (already-expired entry): firstUse=%v err=%v, want true/nil", first, err)
		}
		// The stored entry is already expired, so a later consume attempt
		// for the same jti is treated as first use again - matching
		// IsBlacklisted's own "expired entries don't count" semantics.
		second, err := b.ConsumeOnce(ctx, "jti-consume-3", time.Now().Add(time.Hour))
		if err != nil || !second {
			t.Fatalf("second ConsumeOnce (past-expiry entry): firstUse=%v err=%v, want true/nil", second, err)
		}
	})

	t.Run("concurrent ConsumeOnce on the same jti: exactly one caller wins", func(t *testing.T) {
		b := newTestBlacklist(t)
		expiry := time.Now().Add(time.Hour)

		const n = 50
		var wg sync.WaitGroup
		var wins int64
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				if first, _ := b.ConsumeOnce(ctx, "jti-race", expiry); first {
					atomic.AddInt64(&wins, 1)
				}
			}()
		}
		wg.Wait()

		if wins != 1 {
			t.Fatalf("expected exactly 1 winner out of %d concurrent ConsumeOnce calls on the same jti, got %d", n, wins)
		}
	})
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
	if b.IsUserRevoked(ctx, "user-1") {
		t.Error("expected IsUserRevoked to always return false when disabled")
	}
}

// TestTokenBlacklist_RevokeFamily_AndIsFamilyRevoked is a regression test
// for #402: revoking a refresh-token family/session id (sid) must make
// IsFamilyRevoked report it as revoked, and a different sid must be
// unaffected.
func TestTokenBlacklist_RevokeFamily_AndIsFamilyRevoked(t *testing.T) {
	ctx := context.Background()
	b := newTestBlacklist(t)

	if b.IsFamilyRevoked(ctx, "sid-1") {
		t.Error("expected sid-1 not to be revoked before RevokeFamily")
	}

	if err := b.RevokeFamily(ctx, "sid-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	if !b.IsFamilyRevoked(ctx, "sid-1") {
		t.Error("expected sid-1 to be revoked after RevokeFamily")
	}
	if b.IsFamilyRevoked(ctx, "sid-2") {
		t.Error("expected an unrelated sid-2 to remain unaffected")
	}

	// Empty sid is always a no-op in both directions, exactly like an empty
	// jti/userID elsewhere in this type.
	if err := b.RevokeFamily(ctx, "", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeFamily(\"\"): %v", err)
	}
	if b.IsFamilyRevoked(ctx, "") {
		t.Error("expected an empty sid to never be reported as revoked")
	}
}

// TestTokenBlacklist_RevokeFamily_ExpiresLikeAJTIEntry proves a family
// revocation's own retention window is honored: once its expiry has
// passed, IsFamilyRevoked must stop reporting it as revoked - unlike
// RevokeUser/IsUserRevoked, which are permanent (see RevokeFamily's doc
// comment for why a session revocation doesn't need to be).
func TestTokenBlacklist_RevokeFamily_ExpiresLikeAJTIEntry(t *testing.T) {
	ctx := context.Background()
	b := newTestBlacklist(t)

	if err := b.RevokeFamily(ctx, "sid-already-expired", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	if b.IsFamilyRevoked(ctx, "sid-already-expired") {
		t.Error("expected a family revocation past its own expiry to no longer be reported as revoked")
	}
}

// TestTokenBlacklist_RevokeFamily_NotGatedByEnabled is a regression test for
// #402, mirroring ConsumeOnce's own "not gated by config.Enabled" test and
// doc comment: revoking a session's refresh-token family on logout is a
// correctness property of session termination itself, not the general
// operator-opt-in revocation feature Add/IsBlacklisted/RevokeUser implement
// - making it conditional on that same toggle would leave the checked-in
// default configuration (TokenBlacklist disabled) unable to revoke a
// session's refresh tokens on logout at all.
func TestTokenBlacklist_RevokeFamily_NotGatedByEnabled(t *testing.T) {
	ctx := context.Background()
	b := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop())

	if err := b.RevokeFamily(ctx, "sid-disabled-feature", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeFamily (disabled feature): %v", err)
	}
	if !b.IsFamilyRevoked(ctx, "sid-disabled-feature") {
		t.Error("expected family revocation to work even when the general blacklist feature is disabled")
	}
}

// TestTokenBlacklist_Cleanup_SweepsExpiredFamilyRevocations proves cleanup()
// also sweeps expired family-revocation entries (unlike userRevocations,
// which are permanent - see cleanup's and RevokeFamily's doc comments for
// why the two behave differently).
func TestTokenBlacklist_Cleanup_SweepsExpiredFamilyRevocations(t *testing.T) {
	ctx := context.Background()
	b := newTestBlacklist(t)

	if err := b.RevokeFamily(ctx, "sid-expired", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if err := b.RevokeFamily(ctx, "sid-live", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	b.cleanup()

	b.mu.RLock()
	_, expiredStillPresent := b.families["sid-expired"]
	_, liveStillPresent := b.families["sid-live"]
	b.mu.RUnlock()

	if expiredStillPresent {
		t.Error("expected the expired family revocation to be removed by cleanup")
	}
	if !liveStillPresent {
		t.Error("expected the still-live family revocation to survive cleanup")
	}
}

// TestTokenBlacklist_Cleanup_RemovesExpiredJTIsButNotUserRevocations
// exercises cleanup() directly (it otherwise only ever runs on a real
// ticker via Start/cleanupLoop, which no test invokes): the per-jti expiry
// sweep still runs, but user-level revocations (see IsUserRevoked's doc
// comment) are never swept - a Copilot review finding (#391) flagged the
// original time-bounded retention as unsound: it could expire a
// revocation marker while a long-lived token for that user was still
// otherwise valid.
func TestTokenBlacklist_Cleanup_RemovesExpiredJTIsButNotUserRevocations(t *testing.T) {
	ctx := context.Background()
	b := newTestBlacklist(t)

	if err := b.Add(ctx, "jti-expired", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := b.Add(ctx, "jti-live", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := b.RevokeUser(ctx, "user-revoked-long-ago"); err != nil {
		t.Fatalf("RevokeUser: %v", err)
	}

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
	if !b.IsUserRevoked(ctx, "user-revoked-long-ago") {
		t.Error("expected a user revocation to survive cleanup regardless of age")
	}
}

// TestTokenBlacklist_ConsumeOnce_EntriesAreCleanedUpEvenWhenDisabled is a
// regression test for a Copilot review finding on go-wallet-backend#400:
// ConsumeOnce writes entries unconditionally (see its doc comment), but
// Start() used to skip launching the cleanup goroutine entirely whenever
// config.Enabled was false - so every successful refresh would permanently
// grow the map for the life of the process in the (default) disabled
// configuration. Start() now always launches the cleanup loop; this proves
// an expired ConsumeOnce-written entry is actually swept even with
// Enabled: false.
//
// Exercises the real Start()/cleanupLoop lifecycle (a short
// CleanupIntervalSeconds, polled for) rather than calling the unexported
// cleanup() directly: a direct call would pass identically against the old,
// buggy Start() too, since cleanup() itself was never what was broken - it
// was Start() skipping the goroutine entirely when disabled. Only actually
// starting the worker and observing the entry disappear on its own proves
// the fixed lifecycle, not just that cleanup's own logic is correct
// (Copilot review on #400, second round).
func TestTokenBlacklist_ConsumeOnce_EntriesAreCleanedUpEvenWhenDisabled(t *testing.T) {
	ctx := context.Background()
	b := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false, CleanupIntervalSeconds: 1}, zap.NewNop())

	if _, err := b.ConsumeOnce(ctx, "jti-disabled-expired", time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("ConsumeOnce: %v", err)
	}
	if b.Count() != 1 {
		t.Fatalf("Count() after ConsumeOnce = %d, want 1", b.Count())
	}

	b.Start()
	defer b.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for b.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}

	if b.Count() != 0 {
		t.Errorf("Count() after Start()'s cleanup worker ran = %d, want 0 (expired ConsumeOnce entry should be swept even when disabled)", b.Count())
	}
}

func TestTokenBlacklist_StartStop_Enabled(t *testing.T) {
	b := newTestBlacklist(t) // Enabled: true
	b.Start()
	b.Stop()
}

func TestTokenBlacklist_StartStop_Disabled(t *testing.T) {
	// Start() on a disabled blacklist still launches the cleanup goroutine
	// (see Start's doc comment - ConsumeOnce needs it regardless of
	// config.Enabled) and logs accordingly; Stop() must be safe to call
	// afterward either way.
	b := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop())
	b.Start()
	b.Stop()
}

// TestRevokeFamily_NeverShortensExistingMarker is the regression test for a
// #414 review finding: re-revoking a family with a smaller retention (e.g.
// after the configured retention dropped) must not shorten the marker,
// while a later expiry must extend it.
func TestRevokeFamily_NeverShortensExistingMarker(t *testing.T) {
	b := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop())
	ctx := context.Background()
	long := time.Now().Add(400 * 24 * time.Hour)
	short := time.Now().Add(365 * 24 * time.Hour)
	longer := time.Now().Add(500 * 24 * time.Hour)

	if err := b.RevokeFamily(ctx, "sid-x", long); err != nil {
		t.Fatal(err)
	}
	if err := b.RevokeFamily(ctx, "sid-x", short); err != nil {
		t.Fatal(err)
	}
	b.mu.RLock()
	got := b.families["sid-x"]
	b.mu.RUnlock()
	if !got.Equal(long) {
		t.Errorf("re-revoke with a shorter expiry changed the marker: got %v, want %v", got, long)
	}

	if err := b.RevokeFamily(ctx, "sid-x", longer); err != nil {
		t.Fatal(err)
	}
	b.mu.RLock()
	got = b.families["sid-x"]
	b.mu.RUnlock()
	if !got.Equal(longer) {
		t.Errorf("re-revoke with a longer expiry must extend: got %v, want %v", got, longer)
	}
}
