package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// Rule: a WIA is only issued when the instance key has verified FIDO2 evidence.
const wiaNeedsFido2Rules = "# id: fido2-only\n(assure-wia-issue (evidence (verified (fido2 (mds3 trusted)(aaguid 00000000-0000-0000-0000-0000000000aa)))))\n"

// wiaWithPopKey issues a WIA for a fresh PoP key; before runs with the key's
// thumbprint so the test can store evidence for (or against) it first.
func wiaWithPopKey(t *testing.T, svc *WIAService, before func(jkt string)) (string, error) {
	t.Helper()
	ctx := context.Background()
	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	if before != nil {
		before(expectedThumbprint(t, &key.PublicKey))
	}
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		return "", err
	}
	return expectedThumbprint(t, &key.PublicKey), nil
}

func putRecord(t *testing.T, keys storage.KeyAttestationStore, r domain.KeyAttestationRecord) {
	t.Helper()
	r.VerifiedAt = time.Now().UTC()
	if err := keys.MarkKeyAttested(context.Background(), &r); err != nil {
		t.Fatal(err)
	}
}

func instanceType(t *testing.T, instances storage.WalletInstanceStore, jkt string) domain.WSCDType {
	t.Helper()
	inst, err := instances.GetByID(context.Background(), jkt)
	if err != nil {
		t.Fatal(err)
	}
	return inst.WSCDType
}

func TestWIAInstanceKey_VerifiedFIDO2RecordFeedsEvidenceAndWSCDType(t *testing.T) {
	svc, instances := wiaAssuranceSvc(t, wiaNeedsFido2Rules)
	keys := memory.NewStore().KeyAttestations()
	svc.SetKeyAttestations(keys)

	jkt, err := wiaWithPopKey(t, svc, func(jkt string) {
		putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: jkt, Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware, AAGUID: "00000000-0000-0000-0000-0000000000aa"})
	})
	if err != nil {
		t.Fatalf("verified record must satisfy the fido2 rule: %v", err)
	}
	if got := instanceType(t, instances, jkt); got != domain.WSCDTypeFIDO2Hardware {
		t.Fatalf("wscd_type = %q, want fido2_hardware", got)
	}
}

func TestWIAInstanceKey_OldRecordWithoutKindOrHomeReadsAsFIDO2Hardware(t *testing.T) {
	svc, instances := wiaAssuranceSvc(t, wiaNeedsFido2Rules)
	keys := memory.NewStore().KeyAttestations()
	svc.SetKeyAttestations(keys)
	jkt, err := wiaWithPopKey(t, svc, func(jkt string) {
		putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: jkt, AAGUID: "00000000-0000-0000-0000-0000000000aa"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := instanceType(t, instances, jkt); got != domain.WSCDTypeFIDO2Hardware {
		t.Fatalf("wscd_type = %q", got)
	}
}

// ARKG caveat: the attested credential public key is not the PoP key, so the
// thumbprints differ, nothing matches and the instance stays unknown.
func TestWIAInstanceKey_ThumbprintMismatchStaysUnknown(t *testing.T) {
	keys := memory.NewStore().KeyAttestations()
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: "some-other-key-thumbprint", Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware, AAGUID: "00000000-0000-0000-0000-0000000000aa"})

	// Policy disabled: the WIA is issued, wscd_type is unknown.
	off, offInstances := newTestWIAServiceWithInstances(t)
	off.SetKeyAttestations(keys)
	jkt, err := wiaWithPopKey(t, off, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := instanceType(t, offInstances, jkt); got != domain.WSCDTypeUnknown {
		t.Fatalf("wscd_type = %q, want unknown", got)
	}

	// Policy enabled and requiring fido2 evidence: no evidence, refused.
	on, _ := wiaAssuranceSvc(t, wiaNeedsFido2Rules)
	on.SetKeyAttestations(keys)
	if _, err := wiaWithPopKey(t, on, nil); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("err = %v, want ErrWIARefusedByPolicy", err)
	}
}

func TestWIAInstanceKey_NoStoreInstalledIsUnknown(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	jkt, err := wiaWithPopKey(t, svc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := instanceType(t, instances, jkt); got != domain.WSCDTypeUnknown {
		t.Fatalf("wscd_type = %q", got)
	}
}

type failingKeyStore struct{ storage.KeyAttestationStore }

func (failingKeyStore) GetByKeyThumbprint(context.Context, string) (*domain.KeyAttestationRecord, error) {
	return nil, errors.New("boom")
}

func TestWIAInstanceKey_StoreErrorIsNoEvidence(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	svc.SetKeyAttestations(failingKeyStore{})
	jkt, err := wiaWithPopKey(t, svc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := instanceType(t, instances, jkt); got != domain.WSCDTypeUnknown {
		t.Fatalf("wscd_type = %q", got)
	}
}

// A verified record of another kind is not FIDO2 evidence (the fido2 slot
// stays none) but its verified home still maps to a wscd_type.
func TestWIAInstanceKey_NonFIDO2RecordIsNotFIDO2Evidence(t *testing.T) {
	svc, _ := wiaAssuranceSvc(t, wiaNeedsFido2Rules)
	keys := memory.NewStore().KeyAttestations()
	svc.SetKeyAttestations(keys)
	_, err := wiaWithPopKey(t, svc, func(jkt string) {
		putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: jkt, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, AAGUID: "00000000-0000-0000-0000-0000000000aa"})
	})
	if !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("an android_key record must not satisfy a fido2 rule, err = %v", err)
	}

	// Directly: the fido2 slot is empty and the type follows the home.
	rec := &domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE}
	if fido2VerifiedFromRecord(rec) != nil {
		t.Fatal("non-fido2 record rendered as fido2 evidence")
	}
	if got := instanceWSCDType(rec); got != domain.WSCDTypeNativeAndroid {
		t.Fatalf("type = %q", got)
	}
	if got := instanceWSCDType(nil); got != domain.WSCDTypeUnknown {
		t.Fatalf("nil record type = %q", got)
	}
	// A verified record with no home (not guessable) is unknown.
	if got := instanceWSCDType(&domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAndroidKey}); got != domain.WSCDTypeUnknown {
		t.Fatalf("homeless record type = %q", got)
	}
}

// Key attestation for credential keys must not read instance-key evidence of
// another kind as FIDO2 evidence.
func TestKeyAttestation_IgnoresNonFIDO2Records(t *testing.T) {
	svc, _, keys := assuranceSvc(t, nil, uvRules)
	tp := "t1"
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: tp, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox, AAGUID: "aa1", UV: true})
	if got := svc.fido2EvidenceFor(context.Background(), []string{tp}, nil); got != nil {
		t.Fatalf("android_key record rendered as fido2 evidence: %+v", got)
	}
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: "t2", Kind: domain.KeyEvidenceFIDO2, AAGUID: "aa1", UV: true})
	got := svc.fido2EvidenceFor(context.Background(), []string{"t2"}, nil)
	if got == nil || got.AAGUID != "aa1" || got.UV != assurance.UVPresent {
		t.Fatalf("fido2 record not rendered: %+v", got)
	}
}

// The preview's WIA half sees the same instance-key evidence a real WIA would.
func TestPreview_WIAHalfUsesInstanceKeyEvidence(t *testing.T) {
	rules := wiaNeedsFido2Rules + "# id: s1\n(assure-wia (profile s1-full-client)(evidence (verified (fido2 (mds3 trusted)))))\n"
	svc, instances, keys := previewSvc(t, rules, true)
	const jkt = "instance-key-jkt-1234"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: jkt, Status: domain.InstanceStatusActive, LastAttestedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{WalletInstanceID: jkt})
	if err != nil {
		t.Fatal(err)
	}
	if got.WIAIssue {
		t.Fatal("no evidence: WIA must not be issued")
	}
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: jkt, Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware, AAGUID: "00000000-0000-0000-0000-0000000000aa"})
	got, err = svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{WalletInstanceID: jkt})
	if err != nil {
		t.Fatal(err)
	}
	if !got.WIAIssue {
		t.Fatalf("evidence stored: WIA must be issued, got %+v", got)
	}
}

// --- instance_key evidence slot ----------------------------------------------

const wiaNeedsInstanceKeyRules = "# id: ik-fido2-hw\n(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key (kind fido2)(home fido2_hw)(level)(boot)(binding attested)))))\n"

func TestWIAInstanceKey_SlotIsFilledFromTheVerifiedRecord(t *testing.T) {
	svc, _ := wiaAssuranceSvc(t, wiaNeedsInstanceKeyRules)
	keys := memory.NewStore().KeyAttestations()
	svc.SetKeyAttestations(keys)
	// No record: slot none, rule requiring it does not permit.
	if _, err := wiaWithPopKey(t, svc, nil); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("no evidence: err = %v", err)
	}
	// Old-style row (no kind/home) normalizes to fido2/fido2_hw and fills it.
	if _, err := wiaWithPopKey(t, svc, func(jkt string) {
		putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: jkt, AAGUID: "a"})
	}); err != nil {
		t.Fatalf("verified record must fill the slot: %v", err)
	}
}

func TestWIAInstanceKey_SlotRenderingAndExtensibility(t *testing.T) {
	if instanceKeyVerifiedFromRecord(nil) != nil {
		t.Fatal("nil record rendered a slot")
	}
	ik := instanceKeyVerifiedFromRecord(&domain.KeyAttestationRecord{Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware})
	if ik == nil || ik.Kind != "fido2" || ik.Home != "fido2_hw" || ik.Binding != assurance.BindingAttested || ik.Level != "" || ik.Boot != "" {
		t.Fatalf("fido2 slot = %+v", ik)
	}
	// A kind without a registered builder is never rendered as verified.
	if got := instanceKeyVerifiedFromRecord(&domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE}); got != nil {
		t.Fatalf("builder-less kind rendered: %+v", got)
	}
	// A new kind plugs in by registering a builder keyed by Kind.
	instanceKeyBuilders[domain.KeyEvidenceAndroidKey] = testAndroidBuilder{}
	t.Cleanup(func() { delete(instanceKeyBuilders, domain.KeyEvidenceAndroidKey) })
	got := instanceKeyVerifiedFromRecord(&domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, SecurityLevel: "trusted_environment", VerifiedBootState: "verified"})
	if got == nil || got.Home != "tee" || got.Level != "trusted_environment" || got.Boot != "verified" {
		t.Fatalf("registered builder not used: %+v", got)
	}
}

type testAndroidBuilder struct{}

func (testAndroidBuilder) Kind() domain.KeyEvidenceKind { return domain.KeyEvidenceAndroidKey }
func (testAndroidBuilder) Build(r *domain.KeyAttestationRecord) *assurance.InstanceKeyVerified {
	return &assurance.InstanceKeyVerified{Kind: string(r.Kind), Home: string(r.Home), Level: r.SecurityLevel, Boot: r.VerifiedBootState, Binding: assurance.BindingAttested}
}

// Key attestation never sees the slot, and the claimed group of a key
// attestation request cannot fill it (K and S stay orthogonal).
func TestKeyAttestation_EvidenceNeverCarriesInstanceKey(t *testing.T) {
	svc, instances, keys := assuranceSvc(t, nil, uvRules)
	_ = instances
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: "t9", Kind: domain.KeyEvidenceFIDO2, AAGUID: "aa1", UV: true})
	jwks := []map[string]interface{}{{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}
	f := svc.assuranceFacts(context.Background(), "", jwks, &SecurityProperties{Plugin: "strongbox", KeyStorage: []string{"strongbox"}})
	if f.InstanceKey != nil {
		t.Fatalf("key attestation facts carry instance-key evidence: %+v", f.InstanceKey)
	}
	if ev := svc.assessor.Evidence(f); ev.InstanceKey != nil {
		t.Fatalf("evidence carries instance-key evidence: %+v", ev.InstanceKey)
	}
}

func TestPreview_WIAHalfSeesInstanceKeySlot(t *testing.T) {
	svc, instances, keys := previewSvc(t, wiaNeedsInstanceKeyRules, true)
	const jkt = "instance-key-jkt-5678"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: jkt, Status: domain.InstanceStatusActive, LastAttestedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{WalletInstanceID: jkt})
	if got.WIAIssue {
		t.Fatal("no evidence: must not issue")
	}
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: jkt, AAGUID: "a"})
	got, _ = svc.PreviewAssurance(context.Background(), &AssurancePreviewRequest{WalletInstanceID: jkt})
	if !got.WIAIssue {
		t.Fatalf("evidence stored: must issue: %+v", got)
	}
}
