package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
)

func TestKeyAttestationStore_MarkAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	kas := store.KeyAttestations()

	verifiedAt := time.Now().UTC()
	rec := &domain.KeyAttestationRecord{
		KeyThumbprint:    "thumb-1",
		WalletInstanceID: "inst-1",
		TenantID:         "acme",
		AAGUID:           "aaguid-1",
		VerifiedAt:       verifiedAt,
	}
	if err := kas.MarkKeyAttested(ctx, rec); err != nil {
		t.Fatalf("MarkKeyAttested: %v", err)
	}

	got, err := kas.GetByKeyThumbprint(ctx, "thumb-1")
	if err != nil {
		t.Fatalf("GetByKeyThumbprint: %v", err)
	}
	if got.WalletInstanceID != "inst-1" {
		t.Errorf("WalletInstanceID = %q, want inst-1", got.WalletInstanceID)
	}
	if got.AAGUID != "aaguid-1" {
		t.Errorf("AAGUID = %q, want aaguid-1", got.AAGUID)
	}
	if !got.VerifiedAt.Equal(verifiedAt) {
		t.Errorf("VerifiedAt = %v, want %v", got.VerifiedAt, verifiedAt)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestKeyAttestationStore_GetByKeyThumbprint_NotFound(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	kas := store.KeyAttestations()

	_, err := kas.GetByKeyThumbprint(ctx, "does-not-exist")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want storage.ErrNotFound", err)
	}
}

// TestKeyAttestationStore_DistinctKeysDoNotShareEvidence is the direct
// regression test for the bug this store replaces: two different keys
// (even for the same wallet instance) must never resolve to the same
// evidence record.
func TestKeyAttestationStore_DistinctKeysDoNotShareEvidence(t *testing.T) {
	ctx := context.Background()
	store := NewStore()
	kas := store.KeyAttestations()

	if err := kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{
		KeyThumbprint:    "thumb-hardware",
		WalletInstanceID: "inst-1",
		VerifiedAt:       time.Now().UTC(),
	}); err != nil {
		t.Fatalf("MarkKeyAttested: %v", err)
	}

	// A different key, same wallet instance, never separately attested.
	_, err := kas.GetByKeyThumbprint(ctx, "thumb-softkey")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("err = %v, want storage.ErrNotFound (a different key must not inherit another key's evidence)", err)
	}
}
