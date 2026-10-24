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

func TestKeyAttestationStore_UVRoundTripNoDowngrade(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()

	if err := kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "t", AAGUID: "a", UV: true, VerifiedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, _ := kas.GetByKeyThumbprint(ctx, "t")
	if !got.UV {
		t.Fatal("UV=true was not stored")
	}
	// A later attestation of the same key without UV does NOT replace it:
	// evidence is never overwritten by weaker evidence.
	if err := kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "t", AAGUID: "a", UV: false, VerifiedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, _ = kas.GetByKeyThumbprint(ctx, "t")
	if !got.UV {
		t.Fatal("UV=false replaced UV=true")
	}
	// A record stored without the field reads as UV none.
	if err := kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "old", AAGUID: "a", VerifiedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got, _ = kas.GetByKeyThumbprint(ctx, "old")
	if got.UV {
		t.Fatal("a record without uv must read as false")
	}
}

func TestKeyAttestationStore_NeverOverwrittenByWeakerEvidence(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()
	mark := func(r domain.KeyAttestationRecord) {
		t.Helper()
		r.KeyThumbprint = "k"
		r.VerifiedAt = time.Now()
		if err := kas.MarkKeyAttested(ctx, &r); err != nil {
			t.Fatal(err)
		}
	}
	home := func() domain.KeyHome {
		t.Helper()
		g, err := kas.GetByKeyThumbprint(ctx, "k")
		if err != nil {
			t.Fatal(err)
		}
		return g.Home
	}
	mark(domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, AppDigest: "d1"})
	// Weaker home, absent home (old-style FIDO2 default is rank 3 only for fido2), different kind at equal rank.
	mark(domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAppAttestAssertion, Home: domain.KeyHomeSecureEnclaveAsserted})
	mark(domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAndroidKey})
	if home() != domain.KeyHomeTEE {
		t.Fatalf("weaker/absent evidence overwrote the record: %q", home())
	}
	g, _ := kas.GetByKeyThumbprint(ctx, "k")
	if g.AppDigest != "d1" {
		t.Fatalf("fields were overwritten: %+v", g)
	}
	// Stronger evidence replaces it, and CreatedAt survives.
	created := g.CreatedAt
	mark(domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox})
	g, _ = kas.GetByKeyThumbprint(ctx, "k")
	if g.Home != domain.KeyHomeStrongBox || !g.CreatedAt.Equal(created) {
		t.Fatalf("stronger evidence not stored / CreatedAt lost: %+v", g)
	}
}

func TestKeyAttestationStore_LegacyRecordReadsAsFIDO2Hardware(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()
	if err := kas.MarkKeyAttested(ctx, &domain.KeyAttestationRecord{KeyThumbprint: "old", AAGUID: "a", VerifiedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	g, _ := kas.GetByKeyThumbprint(ctx, "old")
	if g.Kind != domain.KeyEvidenceFIDO2 || g.Home != domain.KeyHomeFIDO2Hardware {
		t.Fatalf("kind/home = %q/%q", g.Kind, g.Home)
	}
}
