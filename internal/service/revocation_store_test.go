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
	if !blacklisted(t, b, ctx, "j") || blacklisted(t, b, ctx, "") || !userRevoked(t, b, ctx, "u") || userRevoked(t, b, ctx, "") {
		t.Error("checks must reflect the store, and empty identifiers must never be revoked")
	}

	off := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop(), rs)
	rs.added, rs.revoked = nil, nil
	_ = off.Add(ctx, "j2", time.Now().Add(time.Hour))
	_ = off.RevokeUser(ctx, "u2")
	if len(rs.added)+len(rs.revoked) != 0 || blacklisted(t, off, ctx, "j") || userRevoked(t, off, ctx, "u") {
		t.Error("a disabled blacklist must neither write to nor read from the store")
	}
}

func TestTokenBlacklist_StoreErrorIsReported(t *testing.T) {
	ctx := context.Background()
	rs := &recordingStore{err: errors.New("store down")}
	b := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: true}, zap.NewNop(), rs)
	if revoked, err := b.IsBlacklisted(ctx, "j"); err == nil || revoked {
		t.Errorf("IsBlacklisted = (%v, %v), want (false, error): the caller must be told the answer is unknown", revoked, err)
	}
	if revoked, err := b.IsUserRevoked(ctx, "u"); err == nil || revoked {
		t.Errorf("IsUserRevoked = (%v, %v), want (false, error)", revoked, err)
	}

	// A disabled blacklist never consults the store, so it cannot fail.
	off := NewTokenBlacklistWithStore(config.TokenBlacklistConfig{Enabled: false}, zap.NewNop(), rs)
	if _, err := off.IsBlacklisted(ctx, "j"); err != nil {
		t.Errorf("disabled blacklist must not error: %v", err)
	}
}

// revocationReader is the check half of a revocation checker.
type revocationReader interface {
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	IsUserRevoked(ctx context.Context, userID string) (bool, error)
}

func blacklisted(t *testing.T, r revocationReader, ctx context.Context, jti string) bool {
	t.Helper()
	ok, err := r.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	return ok
}

func userRevoked(t *testing.T, r revocationReader, ctx context.Context, userID string) bool {
	t.Helper()
	ok, err := r.IsUserRevoked(ctx, userID)
	if err != nil {
		t.Fatalf("IsUserRevoked: %v", err)
	}
	return ok
}
