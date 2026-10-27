package memory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

func testAppAttestRecord(id string) *domain.AppAttestKeyRecord {
	return &domain.AppAttestKeyRecord{
		KeyID: id, PublicKey: []byte{4, 1, 2, 3}, Environment: domain.AppAttestProduction,
		AppID: "T.b", ChainVerified: true, TenantID: "acme", Status: domain.AppAttestKeyActive,
	}
}

func TestAppAttestKeyStore_CreateGetAndNoReset(t *testing.T) {
	ctx := context.Background()
	s := NewStore().AppAttestKeys()
	if err := s.Create(ctx, testAppAttestRecord("k1")); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceCounter(ctx, "k1", 5); err != nil {
		t.Fatal(err)
	}
	// A second Create for the same key must not reset the counter.
	if err := s.Create(ctx, testAppAttestRecord("k1")); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
	got, err := s.Get(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Counter != 5 || got.CreatedAt.IsZero() {
		t.Fatalf("counter=%d created=%v", got.Counter, got.CreatedAt)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestAppAttestKeyStore_GetReturnsCopy(t *testing.T) {
	ctx := context.Background()
	s := NewStore().AppAttestKeys()
	_ = s.Create(ctx, testAppAttestRecord("k1"))
	got, _ := s.Get(ctx, "k1")
	got.PublicKey[0] = 9
	got.Status = domain.AppAttestKeyRevoked
	again, _ := s.Get(ctx, "k1")
	if again.PublicKey[0] != 4 || !again.IsActive() {
		t.Fatal("stored record changed through a returned pointer")
	}
}

func TestAppAttestKeyStore_AdvanceCounterStrict(t *testing.T) {
	ctx := context.Background()
	s := NewStore().AppAttestKeys()
	_ = s.Create(ctx, testAppAttestRecord("k1"))
	for _, c := range []uint32{1, 2, 10} {
		if err := s.AdvanceCounter(ctx, "k1", c); err != nil {
			t.Fatalf("advance %d: %v", c, err)
		}
	}
	for _, c := range []uint32{10, 9, 0} {
		if err := s.AdvanceCounter(ctx, "k1", c); !errors.Is(err, storage.ErrCounterNotAdvanced) {
			t.Fatalf("advance %d: want ErrCounterNotAdvanced, got %v", c, err)
		}
	}
	if err := s.AdvanceCounter(ctx, "missing", 1); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestAppAttestKeyStore_RevokedCannotAdvance(t *testing.T) {
	ctx := context.Background()
	s := NewStore().AppAttestKeys()
	_ = s.Create(ctx, testAppAttestRecord("k1"))
	if err := s.Revoke(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := s.AdvanceCounter(ctx, "k1", 1); !errors.Is(err, storage.ErrCounterNotAdvanced) {
		t.Fatalf("want ErrCounterNotAdvanced, got %v", err)
	}
	got, _ := s.Get(ctx, "k1")
	if got.IsActive() {
		t.Fatal("revoked key reads as active")
	}
	if err := s.Revoke(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestAppAttestKeyStore_ConcurrentAdvanceExactlyOneWins(t *testing.T) {
	ctx := context.Background()
	s := NewStore().AppAttestKeys()
	_ = s.Create(ctx, testAppAttestRecord("k1"))
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.AdvanceCounter(ctx, "k1", 7) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d advances to the same counter succeeded, want exactly 1", wins.Load())
	}
}
