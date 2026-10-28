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

// Stored evidence is isolated from the caller's pointers on write and on read.
func TestKeyAttestationStore_DeviceLockedPointerIsIsolated(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()
	locked := true
	in := &domain.KeyAttestationRecord{KeyThumbprint: "k", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, DeviceLocked: &locked, VerifiedAt: time.Now()}
	if err := kas.MarkKeyAttested(ctx, in); err != nil {
		t.Fatal(err)
	}
	locked = false // caller mutates its own value after the write
	got, _ := kas.GetByKeyThumbprint(ctx, "k")
	if got.DeviceLocked == nil || !*got.DeviceLocked {
		t.Fatal("caller mutation after MarkKeyAttested changed stored evidence")
	}
	*got.DeviceLocked = false // caller mutates a read result
	again, _ := kas.GetByKeyThumbprint(ctx, "k")
	if !*again.DeviceLocked {
		t.Fatal("mutating a read result changed stored evidence")
	}
}

func TestKeyAttestationStore_CertSerialsAndRevocationMark(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()
	rec := &domain.KeyAttestationRecord{
		KeyThumbprint: "k1", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE,
		ChainFingerprint: "fp1", CertSerials: []string{"a1", "b2"}, VerifiedAt: time.Now().UTC(),
	}
	if err := kas.MarkKeyAttested(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, _ := kas.GetByKeyThumbprint(ctx, "k1")
	if len(got.CertSerials) != 2 || got.CertSerials[1] != "b2" || got.Revoked() {
		t.Fatalf("got %+v", got)
	}
	// The stored copy is not reachable through the returned one.
	got.CertSerials[0] = "zz"
	again, _ := kas.GetByKeyThumbprint(ctx, "k1")
	if again.CertSerials[0] != "a1" {
		t.Fatal("stored serials changed through a returned record")
	}

	at := time.Now().UTC()
	// Wrong fingerprint, unknown key: no mark, no error.
	for _, c := range []struct{ tp, fp string }{{"k1", "other"}, {"missing", "fp1"}} {
		if ok, err := kas.MarkKeyRevoked(ctx, c.tp, c.fp, "r", at); ok || err != nil {
			t.Fatalf("%v: ok=%v err=%v", c, ok, err)
		}
	}
	if ok, err := kas.MarkKeyRevoked(ctx, "k1", "fp1", "status_list_revoked", at); !ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if ok, _ := kas.MarkKeyRevoked(ctx, "k1", "fp1", "again", at); ok {
		t.Fatal("marked twice")
	}
	got, err := kas.GetByKeyThumbprint(ctx, "k1")
	if err != nil || !got.Revoked() || got.RevokedReason != "status_list_revoked" || got.Home != domain.KeyHomeTEE {
		t.Fatalf("record not kept revoked: %+v err=%v", got, err)
	}
	// Never deleted, and a fresh weaker record replaces it.
	fresh := &domain.KeyAttestationRecord{KeyThumbprint: "k1", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, ChainFingerprint: "fp2", CertSerials: []string{"c3"}}
	if err := kas.MarkKeyAttested(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	got, _ = kas.GetByKeyThumbprint(ctx, "k1")
	if got.Revoked() || got.ChainFingerprint != "fp2" {
		t.Fatalf("fresh record did not replace the revoked one: %+v", got)
	}
}

func TestKeyAttestationStore_ReplaceKeyEvidence(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()
	strong := &domain.KeyAttestationRecord{KeyThumbprint: "k1", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox, ChainFingerprint: "old", VerifiedAt: time.Now().UTC()}
	if err := kas.MarkKeyAttested(ctx, strong); err != nil {
		t.Fatal(err)
	}
	weak := &domain.KeyAttestationRecord{KeyThumbprint: "k1", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, ChainFingerprint: "new"}
	// A different stored chain, or no record: nothing is written.
	if ok, err := kas.ReplaceKeyEvidence(ctx, weak, "not-the-stored-chain"); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	other := &domain.KeyAttestationRecord{KeyThumbprint: "none", ChainFingerprint: "x"}
	if ok, err := kas.ReplaceKeyEvidence(ctx, other, "x"); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got, _ := kas.GetByKeyThumbprint(ctx, "k1"); got.ChainFingerprint != "old" {
		t.Fatalf("written without a match: %+v", got)
	}
	created, _ := kas.GetByKeyThumbprint(ctx, "k1")
	// The stale chain matches: replaced whatever the rank (no-downgrade is not applied).
	if ok, err := kas.ReplaceKeyEvidence(ctx, weak, "old"); !ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	got, _ := kas.GetByKeyThumbprint(ctx, "k1")
	if got.ChainFingerprint != "new" || got.Home != domain.KeyHomeTEE || !got.CreatedAt.Equal(created.CreatedAt) || got.Revoked() {
		t.Fatalf("got %+v", got)
	}
}
