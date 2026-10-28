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

func TestKeyAttestationStore_DeleteIfUnchanged(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()

	first := &domain.KeyAttestationRecord{KeyThumbprint: "t", VerifiedAt: time.Now().UTC()}
	if err := kas.MarkKeyAttested(ctx, first); err != nil {
		t.Fatal(err)
	}
	staleToken := first.WriteToken
	if staleToken == "" {
		t.Fatal("MarkKeyAttested must set a write token")
	}
	second := &domain.KeyAttestationRecord{KeyThumbprint: "t", VerifiedAt: time.Now().UTC()}
	if err := kas.MarkKeyAttested(ctx, second); err != nil {
		t.Fatal(err)
	}

	if err := kas.DeleteIfUnchanged(ctx, "t", staleToken); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a superseded write token must not delete, got %v", err)
	}
	if err := kas.DeleteIfUnchanged(ctx, "t", ""); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("an empty token must not delete, got %v", err)
	}
	if err := kas.DeleteIfUnchanged(ctx, "t", second.WriteToken); err != nil {
		t.Fatalf("current token: %v", err)
	}
	if _, err := kas.GetByKeyThumbprint(ctx, "t"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("record must be gone, got %v", err)
	}
}

func TestKeyAttestationStore_RestoreIfUnchanged(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()

	first := &domain.KeyAttestationRecord{KeyThumbprint: "t", AAGUID: "old", VerifiedAt: time.Now().UTC()}
	if err := kas.MarkKeyAttested(ctx, first); err != nil {
		t.Fatal(err)
	}
	if first.Previous != nil {
		t.Fatal("a first insert has no previous evidence")
	}
	second := &domain.KeyAttestationRecord{KeyThumbprint: "t", AAGUID: "new", VerifiedAt: time.Now().UTC()}
	if err := kas.MarkKeyAttested(ctx, second); err != nil {
		t.Fatal(err)
	}
	if second.Previous == nil || second.Previous.AAGUID != "old" {
		t.Fatalf("Previous = %+v, want the replaced record", second.Previous)
	}
	written := *second

	stale := *first
	if err := kas.RestoreIfUnchanged(ctx, &stale, second.Previous); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a superseded write must not restore, got %v", err)
	}
	if err := kas.RestoreIfUnchanged(ctx, &written, second.Previous); err != nil {
		t.Fatal(err)
	}
	got, err := kas.GetByKeyThumbprint(ctx, "t")
	if err != nil || got.AAGUID != "old" || !got.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("restored = %+v, %v", got, err)
	}
	if err := kas.RestoreIfUnchanged(ctx, &written, second.Previous); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a restore is itself a new write; replay must not match, got %v", err)
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

// A write that does not land (weaker evidence never replaces stronger) carries
// no write token and no previous record, so rolling it back is a no-op and
// cannot delete the stronger record.
func TestKeyAttestationStore_NoOpWriteHasNoRollbackHandle(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()
	strong := &domain.KeyAttestationRecord{KeyThumbprint: "tp-noop", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox, ChainFingerprint: "fp1", VerifiedAt: time.Now().UTC()}
	must(t, kas.MarkKeyAttested(ctx, strong))
	weak := &domain.KeyAttestationRecord{KeyThumbprint: "tp-noop", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, ChainFingerprint: "fp2", VerifiedAt: time.Now().UTC()}
	must(t, kas.MarkKeyAttested(ctx, weak))
	eq(t, "", weak.WriteToken)
	eq(t, true, weak.Previous == nil)
	isNotFound(t, kas.DeleteIfUnchanged(ctx, "tp-noop", weak.WriteToken))
	got, err := kas.GetByKeyThumbprint(ctx, "tp-noop")
	must(t, err)
	eq(t, domain.KeyHomeStrongBox, got.Home)
}

// Marking a record revoked and replacing stale evidence are writes of their
// own: a rollback of the write that stored the record must not undo them.
func TestKeyAttestationStore_RevokeAndReplaceRotateTheWriteToken(t *testing.T) {
	ctx := context.Background()
	kas := NewStore().KeyAttestations()
	first := &domain.KeyAttestationRecord{KeyThumbprint: "tp-rot", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, ChainFingerprint: "fp1", VerifiedAt: time.Now().UTC()}
	must(t, kas.MarkKeyAttested(ctx, first))
	written := *first

	marked, err := kas.MarkKeyRevoked(ctx, "tp-rot", "fp1", "revoked", time.Now())
	must(t, err)
	eq(t, true, marked)
	isNotFound(t, kas.DeleteIfUnchanged(ctx, "tp-rot", written.WriteToken))
	isNotFound(t, kas.RestoreIfUnchanged(ctx, &written, &domain.KeyAttestationRecord{KeyThumbprint: "tp-rot", Home: domain.KeyHomeTEE}))
	got, err := kas.GetByKeyThumbprint(ctx, "tp-rot")
	must(t, err)
	eq(t, true, got.Revoked())

	repl := &domain.KeyAttestationRecord{KeyThumbprint: "tp-rot", Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox, ChainFingerprint: "fp3", VerifiedAt: time.Now().UTC()}
	ok, err := kas.ReplaceKeyEvidence(ctx, repl, "fp1")
	must(t, err)
	eq(t, true, ok)
	if repl.WriteToken == "" || repl.WriteToken == written.WriteToken || repl.Previous == nil || repl.Previous.ChainFingerprint != "fp1" {
		t.Fatalf("replacement handle = token %q previous %+v", repl.WriteToken, repl.Previous)
	}
	isNotFound(t, kas.DeleteIfUnchanged(ctx, "tp-rot", written.WriteToken))
	// The replacement's own handle restores the record it replaced.
	rolled := *repl
	must(t, kas.RestoreIfUnchanged(ctx, &rolled, rolled.Previous))
	got, err = kas.GetByKeyThumbprint(ctx, "tp-rot")
	must(t, err)
	eq(t, "fp1", got.ChainFingerprint)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func eq(t *testing.T, want, got any) {
	t.Helper()
	if want != got {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func isNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
