package service

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// runRevocationStoreContract exercises the behaviour every RevocationStore
// must share; newStore returns a fresh, empty store.
func runRevocationStoreContract(t *testing.T, newStore func(t *testing.T) RevocationStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("added jti is revoked until its expiry", func(t *testing.T) {
		s := newStore(t)
		if s.Has(ctx, "jti-1") {
			t.Fatal("unknown jti must not be revoked")
		}
		if err := s.Add(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if !s.Has(ctx, "jti-1") {
			t.Error("added jti must be revoked")
		}
		if s.Has(ctx, "jti-2") {
			t.Error("other jti must not be revoked")
		}
	})

	t.Run("expired jti is not revoked", func(t *testing.T) {
		s := newStore(t)
		if err := s.Add(ctx, "jti-old", time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if s.Has(ctx, "jti-old") {
			t.Error("a jti past its expiry must not be reported revoked")
		}
	})

	t.Run("revoked user stays revoked, others unaffected", func(t *testing.T) {
		s := newStore(t)
		if s.IsUserRevoked(ctx, "u1") {
			t.Fatal("unknown user must not be revoked")
		}
		if err := s.RevokeUser(ctx, "u1"); err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeUser(ctx, "u1"); err != nil {
			t.Fatalf("revoking twice must be idempotent: %v", err)
		}
		if !s.IsUserRevoked(ctx, "u1") {
			t.Error("revoked user must be reported revoked")
		}
		if s.IsUserRevoked(ctx, "u2") {
			t.Error("other user must not be revoked")
		}
	})
}

func TestMemoryRevocationStore_Contract(t *testing.T) {
	runRevocationStoreContract(t, func(t *testing.T) RevocationStore {
		return NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop()).store
	})
}

// recordingStore records calls so the TokenBlacklist facade can be checked
// for what it forwards.
type recordingStore struct {
	added   []string
	revoked []string
	has     map[string]bool
	users   map[string]bool
}

func (r *recordingStore) Add(_ context.Context, jti string, _ time.Time) error {
	r.added = append(r.added, jti)
	return nil
}
func (r *recordingStore) Has(_ context.Context, jti string) bool { return r.has[jti] }
func (r *recordingStore) RevokeUser(_ context.Context, id string) error {
	r.revoked = append(r.revoked, id)
	return nil
}
func (r *recordingStore) IsUserRevoked(_ context.Context, id string) bool { return r.users[id] }

func TestTokenBlacklist_DelegatesToStore(t *testing.T) {
	ctx := context.Background()
	rs := &recordingStore{has: map[string]bool{"j": true}, users: map[string]bool{"u": true}}
	b := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop(), rs)

	_ = b.Add(ctx, "j", time.Now().Add(time.Hour))
	_ = b.Add(ctx, "", time.Now().Add(time.Hour))
	_ = b.RevokeUser(ctx, "u")
	_ = b.RevokeUser(ctx, "")
	if len(rs.added) != 1 || rs.added[0] != "j" {
		t.Errorf("Add forwarded %v, want [j] (empty jti must not reach the store)", rs.added)
	}
	if len(rs.revoked) != 1 || rs.revoked[0] != "u" {
		t.Errorf("RevokeUser forwarded %v, want [u]", rs.revoked)
	}
	if !b.IsBlacklisted(ctx, "j") || b.IsBlacklisted(ctx, "") || !b.IsUserRevoked(ctx, "u") || b.IsUserRevoked(ctx, "") {
		t.Error("checks must reflect the store, and empty identifiers must never be revoked")
	}

	off := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop(), rs)
	rs.added, rs.revoked = nil, nil
	_ = off.Add(ctx, "j2", time.Now().Add(time.Hour))
	_ = off.RevokeUser(ctx, "u2")
	if len(rs.added)+len(rs.revoked) != 0 || off.IsBlacklisted(ctx, "j") || off.IsUserRevoked(ctx, "u") {
		t.Error("a disabled blacklist must neither write to nor read from the store")
	}
}
