package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

// fakeKeyVerifier is a registry test double.
type fakeKeyVerifier struct {
	typ   KeyAttestationType
	res   *InstanceKeyEvidenceResult
	err   error
	calls int
	got   *InstanceKeyEvidenceInput
}

func (f *fakeKeyVerifier) Type() KeyAttestationType { return f.typ }

// Kind and Recheck make the fake a re-checker that finds every record good
// (tests of the re-check use the real verifier).
func (f *fakeKeyVerifier) Kind() domain.KeyEvidenceKind {
	if f.typ == KeyAttestationAppAttestAssertion {
		return domain.KeyEvidenceAppAttestAssertion
	}
	return domain.KeyEvidenceAndroidKey
}

func (f *fakeKeyVerifier) Recheck(context.Context, *domain.KeyAttestationRecord, time.Time) (RecheckResult, error) {
	return RecheckResult{Verdict: RecheckGood}, nil
}

// goodChecker is a checker that finds every android_key record good.
func goodChecker() *instanceKeyChecker {
	c := newInstanceKeyChecker(zap.NewNop())
	c.register(&fakeKeyVerifier{typ: KeyAttestationAndroidKey})
	return c
}
func (f *fakeKeyVerifier) Verify(_ context.Context, in *InstanceKeyEvidenceInput) (*InstanceKeyEvidenceResult, error) {
	f.calls++
	f.got = in
	return f.res, f.err
}

func tryKeyAttestation(t *testing.T, svc *WIAService, ka *KeyAttestation) (jkt string, err error) {
	t.Helper()
	ctx := context.Background()
	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	jkt = expectedThumbprint(t, &key.PublicKey)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge, KeyAttestation: ka})
	return jkt, err
}

func androidRecord() *domain.KeyAttestationRecord {
	return &domain.KeyAttestationRecord{
		Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox,
		SecurityLevel: "strongbox",
		// A verifier cannot choose the key or scope of what is stored.
		KeyThumbprint: "attacker-chosen", WalletInstanceID: "attacker-chosen", TenantID: "attacker-tenant",
	}
}

func TestInstanceKeyAttestationChallenge_Encoding(t *testing.T) {
	// SHA-256("siros-instance-key-v1" || C), C = the challenge string's bytes
	// as issued (not base64-decoded), no separator.
	want := sha256.Sum256([]byte("siros-instance-key-v1" + "AAAA"))
	if got := InstanceKeyAttestationChallenge("AAAA"); hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("challenge = %x, want %x", got, want)
	}
	// Pinned vector so the encoding cannot drift unnoticed (clients compute it).
	if got := hex.EncodeToString(InstanceKeyAttestationChallenge("AAAA")); got != "2b720816b6d9f97343b4ac4e5821bdedcf26915d1795396c869b1706f142d428" {
		t.Fatalf("pinned vector drifted: %s", got)
	}
	if len(InstanceKeyAttestationChallenge("x")) != 32 {
		t.Fatal("challenge is not 32 bytes")
	}
}

func TestKeyAttestation_UnmarshalKeepsObjectAndRejectsNonObject(t *testing.T) {
	var ka KeyAttestation
	if err := json.Unmarshal([]byte(`{"type":"android_key","x5c":["AA=="]}`), &ka); err != nil {
		t.Fatal(err)
	}
	if ka.Type != KeyAttestationAndroidKey || string(ka.Raw) != `{"type":"android_key","x5c":["AA=="]}` {
		t.Fatalf("got %+v", ka)
	}
	for _, bad := range []string{`"android_key"`, `[1]`, `12`} {
		if err := json.Unmarshal([]byte(bad), &KeyAttestation{}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestWIAKeyAttestation_UnknownTypeIs400BeforeChallengeIsConsumed(t *testing.T) {
	svc, _ := newTestWIAServiceWithInstances(t)
	ctx := context.Background()
	challenge, _, err := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, _ := createTestPop(t, challenge)
	for _, typ := range []KeyAttestationType{"nope", "", "ANDROID_KEY"} {
		_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge, KeyAttestation: &KeyAttestation{Type: typ}})
		if !errors.Is(err, ErrWIAKeyAttestationTypeUnsupported) {
			t.Fatalf("type %q: err = %v", typ, err)
		}
	}
	// The challenge survived the rejections.
	if _, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge}); err != nil {
		t.Fatalf("challenge was burned by an unsupported type: %v", err)
	}
}

func TestWIAKeyAttestation_AbsentFieldCallsNoVerifierAndStaysUnknown(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	f := &fakeKeyVerifier{typ: KeyAttestationAndroidKey, res: &InstanceKeyEvidenceResult{Record: androidRecord()}}
	svc.RegisterInstanceKeyVerifier(f)
	jkt, err := tryKeyAttestation(t, svc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 0 || instanceType(t, instances, jkt) != domain.WSCDTypeUnknown {
		t.Fatalf("calls=%d type=%s", f.calls, instanceType(t, instances, jkt))
	}
}

func TestWIAKeyAttestation_VerifiedRecordIsStoredUnderTheBackendsKey(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	store := memory.NewStore().KeyAttestations()
	svc.SetKeyAttestations(store)
	f := &fakeKeyVerifier{typ: KeyAttestationAndroidKey, res: &InstanceKeyEvidenceResult{Record: androidRecord()}}
	svc.RegisterInstanceKeyVerifier(f)

	jkt, err := tryKeyAttestation(t, svc, &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: json.RawMessage(`{"type":"android_key"}`)})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := store.GetByKeyThumbprint(context.Background(), jkt)
	if err != nil {
		t.Fatalf("record not stored under the PoP key's thumbprint: %v", err)
	}
	if rec.WalletInstanceID != jkt || rec.TenantID != domain.DefaultTenantID || rec.Home != domain.KeyHomeStrongBox || rec.VerifiedAt.IsZero() {
		t.Fatalf("record = %+v", rec)
	}
	if got := instanceType(t, instances, jkt); got != domain.WSCDTypeNativeAndroid {
		t.Fatalf("wscd_type = %s", got)
	}
	// The verifier got the backend-established facts.
	if f.got.Thumbprint != jkt || f.got.PoPKey == nil || f.got.WIAChallenge == "" || f.got.TenantID != domain.DefaultTenantID || string(f.got.Payload) != `{"type":"android_key"}` {
		t.Fatalf("input = %+v", f.got)
	}
}

func TestWIAKeyAttestation_NoHomeResultIssuesWithUnknown(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	store := memory.NewStore().KeyAttestations()
	svc.SetKeyAttestations(store)
	svc.RegisterInstanceKeyVerifier(&fakeKeyVerifier{typ: KeyAttestationAndroidKey, res: &InstanceKeyEvidenceResult{Reason: "software"}})
	jkt, err := tryKeyAttestation(t, svc, &KeyAttestation{Type: KeyAttestationAndroidKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a no-home result stored a record: %v", err)
	}
	if instanceType(t, instances, jkt) != domain.WSCDTypeUnknown {
		t.Fatal("wscd_type is not unknown")
	}
}

func TestWIAKeyAttestation_FailuresRefuseTheWIAAndRecordNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"invalid":      {ErrWIAKeyAttestationInvalid, ErrWIAKeyAttestationInvalid},
		"unavailable":  {ErrWIAKeyAttestationUnavailable, ErrWIAKeyAttestationUnavailable},
		"unclassified": {errors.New("boom"), ErrWIAKeyAttestationInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			svc, instances := newTestWIAServiceWithInstances(t)
			store := memory.NewStore().KeyAttestations()
			svc.SetKeyAttestations(store)
			// Even a verifier that wrongly returns a record with an error stores nothing.
			svc.RegisterInstanceKeyVerifier(&fakeKeyVerifier{typ: KeyAttestationAndroidKey, res: &InstanceKeyEvidenceResult{Record: androidRecord()}, err: tc.err})
			jkt, err := tryKeyAttestation(t, svc, &KeyAttestation{Type: KeyAttestationAndroidKey})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if _, e := store.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(e, storage.ErrNotFound) {
				t.Fatalf("record stored: %v", e)
			}
			if _, e := instances.GetByID(context.Background(), jkt); !errors.Is(e, storage.ErrNotFound) {
				t.Fatalf("a refused WIA created an instance: %v", e)
			}
		})
	}
}

func TestWIAKeyAttestation_RegistryIsKeyedByType(t *testing.T) {
	svc, _ := newTestWIAServiceWithInstances(t)
	a := &fakeKeyVerifier{typ: KeyAttestationAndroidKey, res: &InstanceKeyEvidenceResult{}}
	b := &fakeKeyVerifier{typ: KeyAttestationAppAttestAssertion, res: &InstanceKeyEvidenceResult{}}
	svc.RegisterInstanceKeyVerifier(a)
	svc.RegisterInstanceKeyVerifier(b)
	if _, err := tryKeyAttestation(t, svc, &KeyAttestation{Type: KeyAttestationAppAttestAssertion}); err != nil {
		t.Fatal(err)
	}
	if a.calls != 0 || b.calls != 1 {
		t.Fatalf("dispatch a=%d b=%d", a.calls, b.calls)
	}
	if got := svc.InstanceKeyVerifierTypes(); len(got) != 2 || got[0] != "android_key" || got[1] != "app_attest_assertion" {
		t.Fatalf("types = %v", got)
	}
}

type failingMarkStore struct{ storage.KeyAttestationStore }

func (failingMarkStore) MarkKeyAttested(context.Context, *domain.KeyAttestationRecord) error {
	return errors.New("db down")
}

// A storage failure after successful verification is a retryable outage
// (ErrWIAKeyAttestationUnavailable, HTTP 503), not an internal failure, and
// the WIA is refused without creating an instance.
func TestWIAKeyAttestation_PersistenceFailureIsUnavailable(t *testing.T) {
	svc, instances := newTestWIAServiceWithInstances(t)
	svc.SetKeyAttestations(failingMarkStore{memory.NewStore().KeyAttestations()})
	svc.RegisterInstanceKeyVerifier(&fakeKeyVerifier{typ: KeyAttestationAndroidKey, res: &InstanceKeyEvidenceResult{Record: androidRecord()}})
	jkt, err := tryKeyAttestation(t, svc, &KeyAttestation{Type: KeyAttestationAndroidKey})
	if !errors.Is(err, ErrWIAKeyAttestationUnavailable) {
		t.Fatalf("err = %v, want ErrWIAKeyAttestationUnavailable", err)
	}
	if _, e := instances.GetByID(context.Background(), jkt); !errors.Is(e, storage.ErrNotFound) {
		t.Fatalf("a refused WIA created an instance: %v", e)
	}
}
