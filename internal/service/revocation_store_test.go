package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func mustHas(t *testing.T, s RevocationStore, jti string) bool {
	t.Helper()
	ok, err := s.Has(context.Background(), jti)
	if err != nil {
		t.Fatalf("Has(%q): %v", jti, err)
	}
	return ok
}

func mustUserRevoked(t *testing.T, s RevocationStore, id string) bool {
	t.Helper()
	ok, err := s.IsUserRevoked(context.Background(), id)
	if err != nil {
		t.Fatalf("IsUserRevoked(%q): %v", id, err)
	}
	return ok
}

// runRevocationStoreContract exercises the behaviour every RevocationStore
// must share; newStore returns a fresh, empty store.
func runRevocationStoreContract(t *testing.T, newStore func(t *testing.T) RevocationStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("added jti is revoked until its expiry", func(t *testing.T) {
		s := newStore(t)
		if mustHas(t, s, "jti-1") {
			t.Fatal("unknown jti must not be revoked")
		}
		if err := s.Add(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if !mustHas(t, s, "jti-1") {
			t.Error("added jti must be revoked")
		}
		if mustHas(t, s, "jti-2") {
			t.Error("other jti must not be revoked")
		}
	})

	t.Run("expired jti is not revoked", func(t *testing.T) {
		s := newStore(t)
		if err := s.Add(ctx, "jti-old", time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if mustHas(t, s, "jti-old") {
			t.Error("a jti past its expiry must not be reported revoked")
		}
	})

	t.Run("revoked user stays revoked, others unaffected", func(t *testing.T) {
		s := newStore(t)
		if mustUserRevoked(t, s, "u1") {
			t.Fatal("unknown user must not be revoked")
		}
		if err := s.RevokeUser(ctx, "u1"); err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeUser(ctx, "u1"); err != nil {
			t.Fatalf("revoking twice must be idempotent: %v", err)
		}
		if !mustUserRevoked(t, s, "u1") {
			t.Error("revoked user must be reported revoked")
		}
		if mustUserRevoked(t, s, "u2") {
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
	err     error // returned by Has/IsUserRevoked
}

func (r *recordingStore) Add(_ context.Context, jti string, _ time.Time) error {
	r.added = append(r.added, jti)
	return nil
}
func (r *recordingStore) Has(_ context.Context, jti string) (bool, error) {
	return r.has[jti], r.err
}
func (r *recordingStore) RevokeUser(_ context.Context, id string) error {
	r.revoked = append(r.revoked, id)
	return nil
}
func (r *recordingStore) IsUserRevoked(_ context.Context, id string) (bool, error) {
	return r.users[id], r.err
}

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

func TestTokenBlacklist_StoreErrorRefuses(t *testing.T) {
	ctx := context.Background()
	rs := &recordingStore{err: errors.New("store down")}
	b := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop(), rs)
	if !b.IsBlacklisted(ctx, "j") {
		t.Error("a store error must not read as 'not revoked'")
	}
	if !b.IsUserRevoked(ctx, "u") {
		t.Error("a store error must not read as 'user not revoked'")
	}
}

// removableStore is a recordingStore that also supports Remove.
type removableStore struct {
	recordingStore
	removed []string
}

func (r *removableStore) Remove(_ context.Context, jti string) error {
	r.removed = append(r.removed, jti)
	return nil
}

func TestTokenBlacklist_Remove_WithStore(t *testing.T) {
	ctx := context.Background()
	cfg := config.TokenBlacklistConfig{Enabled: true}

	rs := &removableStore{}
	b := NewTokenBlacklistWithStore(cfg, zap.NewNop(), rs)
	if err := b.Remove(ctx, "j"); err != nil || len(rs.removed) != 1 || rs.removed[0] != "j" {
		t.Errorf("Remove must reach the store: err=%v removed=%v", err, rs.removed)
	}

	plain := NewTokenBlacklistWithStore(cfg, zap.NewNop(), &recordingStore{})
	if err := plain.Remove(ctx, "j"); !errors.Is(err, ErrRevocationRemoveUnsupported) {
		t.Errorf("Remove on a store that cannot delete = %v, want ErrRevocationRemoveUnsupported", err)
	}

	off := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop(), rs)
	rs.removed = nil
	if err := off.Remove(ctx, "j"); err != nil || len(rs.removed) != 0 {
		t.Errorf("a disabled blacklist must not call the store: err=%v removed=%v", err, rs.removed)
	}
}

func TestMemoryRevocationStore_Remove(t *testing.T) {
	ctx := context.Background()
	b := NewTokenBlacklist(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop())
	_ = b.Add(ctx, "j", time.Now().Add(time.Hour))
	if b.Count() != 1 {
		t.Fatalf("Count = %d, want 1", b.Count())
	}
	if err := b.Remove(ctx, "j"); err != nil {
		t.Fatal(err)
	}
	if b.IsBlacklisted(ctx, "j") || b.Count() != 0 {
		t.Error("Remove must delete the entry from the in-memory store")
	}
}

// With a custom store the local map holds only ConsumeOnce entries: Count,
// the cleanup sweep and ConsumeOnce neither see nor touch the store's jtis.
func TestTokenBlacklist_LocalStateIsSeparateFromStore(t *testing.T) {
	ctx := context.Background()
	rs := &recordingStore{has: map[string]bool{}}
	b := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop(), rs)

	_ = b.Add(ctx, "revoked", time.Now().Add(time.Hour))
	if b.Count() != 0 {
		t.Errorf("Count = %d, want 0: store entries are not counted locally", b.Count())
	}
	if first, _ := b.ConsumeOnce(ctx, "refresh", time.Now().Add(-time.Second)); !first {
		t.Fatal("first ConsumeOnce must win")
	}
	if len(rs.added) != 1 {
		t.Errorf("ConsumeOnce must not write to the store, store saw %v", rs.added)
	}
	if b.Count() != 1 {
		t.Fatalf("Count = %d, want 1 ConsumeOnce entry", b.Count())
	}
	b.cleanup()
	if b.Count() != 0 {
		t.Errorf("cleanup must sweep expired ConsumeOnce entries, Count = %d", b.Count())
	}
}
