package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
)

const (
	testAssertChallenge = "wia-challenge-C"
	testAssertJKT       = "pop-key-thumbprint"
)

type assertionHarness struct {
	v    *AppAttestAssertionVerifier
	keys storage.AppAttestKeyStore
	dev  *testAppAttestDevice
}

// newAssertionHarness stores a verified production App Attest key (tenant
// "acme", user "u1") and returns a verifier for it.
func newAssertionHarness(t *testing.T) *assertionHarness {
	t.Helper()
	keys := memory.NewStore().AppAttestKeys()
	dev := newTestAppAttestDevice(t)
	pub, _ := dev.key.PublicKey.ECDH()
	if err := keys.Create(context.Background(), &domain.AppAttestKeyRecord{
		KeyID: dev.keyIDB64(), PublicKey: pub.Bytes(), Environment: domain.AppAttestProduction,
		AppID: testAppAttestAppID, ChainVerified: true, TenantID: "acme", UserID: userPtr("u1"),
		Status: domain.AppAttestKeyActive,
	}); err != nil {
		t.Fatal(err)
	}
	v, err := NewAppAttestAssertionVerifier(keys, testAppAttestAppID, "production", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	return &assertionHarness{v: v, keys: keys, dev: dev}
}

func (h *assertionHarness) input(t *testing.T, keyID, assertion string) *InstanceKeyEvidenceInput {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"type": "app_attest_assertion", "key_id": keyID, "assertion": assertion})
	return &InstanceKeyEvidenceInput{
		Payload: payload, Thumbprint: testAssertJKT, TenantID: "acme", UserID: "u1",
		WIAChallenge: testAssertChallenge, Now: time.Now().UTC(),
	}
}

// good builds a valid assertion for the harness' challenge and key at counter.
func (h *assertionHarness) good(t *testing.T, counter uint32) string {
	t.Helper()
	return h.dev.assertion(t, AppAttestClientDataHash(testAssertChallenge, testAssertJKT), assertionOpts{appID: testAppAttestAppID, counter: counter})
}

func (h *assertionHarness) storedCounter(t *testing.T) uint32 {
	t.Helper()
	rec, err := h.keys.Get(context.Background(), h.dev.keyIDB64())
	if err != nil {
		t.Fatal(err)
	}
	return rec.Counter
}

func requireInvalid(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("assertion accepted, want rejection")
	}
	if !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("error %v is not ErrWIAKeyAttestationInvalid", err)
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err, want)
	}
}

func TestAppAttestClientDataHash_Encoding(t *testing.T) {
	// Pinned: SHA-256("siros-instance-key-v1" || C || jkt), the ASCII bytes of
	// both strings, no separator. Clients compute the same value.
	got := base64.StdEncoding.EncodeToString(AppAttestClientDataHash("AAAA", "BBBB"))
	if got != "d6pGqJuID10pCZXQKeXOLWd9Acw7PiBK8IRvG7e4+ws=" {
		t.Fatalf("encoding drifted: %s", got)
	}
	if len(AppAttestClientDataHash("a", "b")) != 32 {
		t.Fatal("not 32 bytes")
	}
}

func TestAppAttestAssertion_ValidAssertionYieldsAssertedHomeAndAdvancesCounter(t *testing.T) {
	h := newAssertionHarness(t)
	res, err := h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), h.good(t, 1)))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Record == nil || res.Record.Kind != domain.KeyEvidenceAppAttestAssertion || res.Record.Home != domain.KeyHomeSecureEnclaveAsserted {
		t.Fatalf("result = %+v", res)
	}
	if res.Record.SecurityLevel != "" || res.Record.VerifiedBootState != "" {
		t.Errorf("an assertion reported a level/boot state: %+v", res.Record)
	}
	if got := h.storedCounter(t); got != 1 {
		t.Fatalf("stored counter = %d, want 1", got)
	}
	// The next assertion must be strictly greater.
	if _, err := h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), h.good(t, 2))); err != nil {
		t.Fatalf("counter 2: %v", err)
	}
	if _, err := h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), h.good(t, 7))); err != nil {
		t.Fatalf("counter 7 (gaps are fine): %v", err)
	}
}

func TestAppAttestAssertion_CounterReplayAndRegression(t *testing.T) {
	h := newAssertionHarness(t)
	ctx := context.Background()
	if _, err := h.v.Verify(ctx, h.input(t, h.dev.keyIDB64(), h.good(t, 5))); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]uint32{"replay": 5, "regression": 4, "zero": 0} {
		_, err := h.v.Verify(ctx, h.input(t, h.dev.keyIDB64(), h.good(t, c)))
		requireInvalid(t, err, "counter")
		if got := h.storedCounter(t); got != 5 {
			t.Fatalf("%s moved the counter to %d", name, got)
		}
	}
}

func TestAppAttestAssertion_BadSignatureDoesNotBurnTheCounter(t *testing.T) {
	h := newAssertionHarness(t)
	bad := h.dev.assertion(t, AppAttestClientDataHash(testAssertChallenge, testAssertJKT), assertionOpts{appID: testAppAttestAppID, counter: 9, badSig: true})
	_, err := h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), bad))
	requireInvalid(t, err, "signature")
	if got := h.storedCounter(t); got != 0 {
		t.Fatalf("an unauthenticated assertion advanced the counter to %d", got)
	}
	// The legitimate assertion with that counter still works afterwards.
	if _, err := h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), h.good(t, 9))); err != nil {
		t.Fatal(err)
	}
}

func TestAppAttestAssertion_ClientDataHashBindsChallengeAndKey(t *testing.T) {
	h := newAssertionHarness(t)
	ctx := context.Background()
	cases := map[string][]byte{
		"other challenge":     AppAttestClientDataHash("another-challenge", testAssertJKT),
		"other pop key":       AppAttestClientDataHash(testAssertChallenge, "some-other-jkt"),
		"no key":              AppAttestClientDataHash(testAssertChallenge, ""),
		"challenge only":      InstanceKeyAttestationChallenge(testAssertChallenge),
		"no domain label":     sha256Of(testAssertChallenge + testAssertJKT),
		"swapped order":       sha256Of(instanceKeyChallengeLabel + testAssertJKT + testAssertChallenge),
		"separator":           sha256Of(instanceKeyChallengeLabel + testAssertChallenge + "|" + testAssertJKT),
		"raw challenge bytes": sha256Of(testAssertChallenge),
	}
	for name, cdh := range cases {
		t.Run(name, func(t *testing.T) {
			a := h.dev.assertion(t, cdh, assertionOpts{appID: testAppAttestAppID, counter: 1})
			_, err := h.v.Verify(ctx, h.input(t, h.dev.keyIDB64(), a))
			requireInvalid(t, err, "signature")
		})
	}
	if got := h.storedCounter(t); got != 0 {
		t.Fatalf("counter = %d after only rejected assertions", got)
	}
}

func TestAppAttestAssertion_RPIDHashMustMatchAppID(t *testing.T) {
	h := newAssertionHarness(t)
	a := h.dev.assertion(t, AppAttestClientDataHash(testAssertChallenge, testAssertJKT), assertionOpts{appID: "TEAM.com.other", counter: 1})
	_, err := h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), a))
	requireInvalid(t, err, "rpIdHash")
}

func TestAppAttestAssertion_SignatureFromAnotherKeyRefused(t *testing.T) {
	h := newAssertionHarness(t)
	other := newTestAppAttestDevice(t)
	a := other.assertion(t, AppAttestClientDataHash(testAssertChallenge, testAssertJKT), assertionOpts{appID: testAppAttestAppID, counter: 1})
	_, err := h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), a))
	requireInvalid(t, err, "signature")
}

func TestAppAttestAssertion_KeyContext(t *testing.T) {
	h := newAssertionHarness(t)
	ctx := context.Background()
	id := h.dev.keyIDB64()

	t.Run("unknown key", func(t *testing.T) {
		other := newTestAppAttestDevice(t)
		_, err := h.v.Verify(ctx, h.input(t, other.keyIDB64(), h.good(t, 1)))
		requireInvalid(t, err, "unknown")
	})
	for name, mut := range map[string]func(*InstanceKeyEvidenceInput){
		"other tenant":    func(in *InstanceKeyEvidenceInput) { in.TenantID = "evil" },
		"other user":      func(in *InstanceKeyEvidenceInput) { in.UserID = "u2" },
		"no user context": func(in *InstanceKeyEvidenceInput) { in.UserID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			in := h.input(t, id, h.good(t, 1))
			mut(in)
			_, err := h.v.Verify(ctx, in)
			requireInvalid(t, err, "another context")
		})
	}
	if got := h.storedCounter(t); got != 0 {
		t.Fatalf("a foreign caller advanced the counter to %d", got)
	}
	t.Run("revoked", func(t *testing.T) {
		if err := h.keys.Revoke(ctx, id); err != nil {
			t.Fatal(err)
		}
		_, err := h.v.Verify(ctx, h.input(t, id, h.good(t, 1)))
		requireInvalid(t, err, "not active")
	})
}

func TestAppAttestAssertion_EnvironmentAndEligibility(t *testing.T) {
	ctx := context.Background()
	mk := func(env domain.AppAttestEnvironment, chain bool, verifierEnv string) (*AppAttestAssertionVerifier, *testAppAttestDevice, storage.AppAttestKeyStore) {
		keys := memory.NewStore().AppAttestKeys()
		dev := newTestAppAttestDevice(t)
		pub, _ := dev.key.PublicKey.ECDH()
		_ = keys.Create(ctx, &domain.AppAttestKeyRecord{
			KeyID: dev.keyIDB64(), PublicKey: pub.Bytes(), Environment: env, AppID: testAppAttestAppID,
			ChainVerified: chain, TenantID: "acme", UserID: userPtr("u1"), Status: domain.AppAttestKeyActive,
		})
		v, err := NewAppAttestAssertionVerifier(keys, testAppAttestAppID, verifierEnv, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		return v, dev, keys
	}
	assertFor := func(d *testAppAttestDevice) string {
		return d.assertion(t, AppAttestClientDataHash(testAssertChallenge, testAssertJKT), assertionOpts{appID: testAppAttestAppID, counter: 1})
	}
	input := func(d *testAppAttestDevice) *InstanceKeyEvidenceInput {
		payload, _ := json.Marshal(map[string]string{"type": "app_attest_assertion", "key_id": d.keyIDB64(), "assertion": assertFor(d)})
		return &InstanceKeyEvidenceInput{Payload: payload, Thumbprint: testAssertJKT, TenantID: "acme", UserID: "u1", WIAChallenge: testAssertChallenge, Now: time.Now()}
	}

	t.Run("development key never yields a home", func(t *testing.T) {
		v, d, keys := mk(domain.AppAttestDevelopment, true, "development")
		res, err := v.Verify(ctx, input(d))
		if err != nil {
			t.Fatal(err)
		}
		if res.Record != nil {
			t.Fatalf("development key produced evidence: %+v", res.Record)
		}
		rec, _ := keys.Get(ctx, d.keyIDB64())
		if rec.Counter != 1 {
			t.Errorf("a sound assertion must still advance the counter (got %d)", rec.Counter)
		}
	})
	t.Run("chain-unverified production key never yields a home", func(t *testing.T) {
		v, d, _ := mk(domain.AppAttestProduction, false, "production")
		res, err := v.Verify(ctx, input(d))
		if err != nil || res.Record != nil {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})
	t.Run("key attested in another environment is refused", func(t *testing.T) {
		v, d, _ := mk(domain.AppAttestProduction, true, "development")
		_, err := v.Verify(ctx, input(d))
		requireInvalid(t, err, "environment")
		v, d, _ = mk(domain.AppAttestDevelopment, true, "production")
		_, err = v.Verify(ctx, input(d))
		requireInvalid(t, err, "environment")
	})
}

func TestAppAttestAssertion_MalformedInput(t *testing.T) {
	h := newAssertionHarness(t)
	ctx := context.Background()
	id := h.dev.keyIDB64()
	cdh := AppAttestClientDataHash(testAssertChallenge, testAssertJKT)
	shortAuth := h.dev.assertion(t, cdh, assertionOpts{appID: testAppAttestAppID, counter: 1})
	_ = shortAuth
	cases := map[string]*InstanceKeyEvidenceInput{
		"payload not json":       {Payload: []byte("{"), TenantID: "acme", UserID: "u1"},
		"payload is a string":    {Payload: []byte(`"x"`), TenantID: "acme", UserID: "u1"},
		"payload too large":      {Payload: []byte(`{"assertion":"` + strings.Repeat("A", 2*maxAppAttestAssertionBytes+1) + `"}`), TenantID: "acme", UserID: "u1"},
		"missing key_id":         h.input(t, "", h.good(t, 1)),
		"key_id not base64":      h.input(t, "@@@", h.good(t, 1)),
		"key_id wrong length":    h.input(t, base64.StdEncoding.EncodeToString([]byte("short")), h.good(t, 1)),
		"missing assertion":      h.input(t, id, ""),
		"assertion not base64":   h.input(t, id, "@@@"),
		"assertion not cbor":     h.input(t, id, base64.StdEncoding.EncodeToString([]byte("not cbor"))),
		"assertion cbor string":  h.input(t, id, base64.StdEncoding.EncodeToString([]byte{0x63, 'a', 'b', 'c'})),
		"assertion oversize":     h.input(t, id, base64.StdEncoding.EncodeToString(make([]byte, maxAppAttestAssertionBytes+1))),
		"assertion empty object": h.input(t, id, base64.StdEncoding.EncodeToString([]byte{0xa0})),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := h.v.Verify(ctx, in)
			requireInvalid(t, err, "")
		})
	}
	if got := h.storedCounter(t); got != 0 {
		t.Fatalf("malformed input moved the counter to %d", got)
	}
}

// Oversize is refused by length alone: the same otherwise valid objects with
// modest padding are accepted.
func TestAppAttestAssertion_OversizeRefusedByLengthAlone(t *testing.T) {
	ctx := context.Background()
	build := func(h *assertionHarness, counter uint32, assertionPad, payloadPad int) *InstanceKeyEvidenceInput {
		a := h.dev.assertion(t, AppAttestClientDataHash(testAssertChallenge, testAssertJKT), assertionOpts{appID: testAppAttestAppID, counter: counter})
		raw, _ := base64.StdEncoding.DecodeString(a)
		var m map[string]any
		_ = cbor.Unmarshal(raw, &m)
		m["pad"] = make([]byte, assertionPad)
		padded, _ := cbor.Marshal(m)
		payload, _ := json.Marshal(map[string]string{
			"type": "app_attest_assertion", "key_id": h.dev.keyIDB64(),
			"assertion": base64.StdEncoding.EncodeToString(padded), "pad": strings.Repeat("A", payloadPad),
		})
		return &InstanceKeyEvidenceInput{Payload: payload, Thumbprint: testAssertJKT, TenantID: "acme", UserID: "u1", WIAChallenge: testAssertChallenge, Now: time.Now()}
	}
	h := newAssertionHarness(t)
	if _, err := h.v.Verify(ctx, build(h, 1, 100, 100)); err != nil {
		t.Fatalf("modest padding rejected: %v", err)
	}
	_, err := h.v.Verify(ctx, build(h, 2, maxAppAttestAssertionBytes, 100))
	requireInvalid(t, err, "unreasonable size")
	_, err = h.v.Verify(ctx, build(h, 3, 100, 2*maxAppAttestAssertionBytes))
	requireInvalid(t, err, "too large")
}

func TestAppAttestAssertion_UnusableStoredKeyRefused(t *testing.T) {
	h := newAssertionHarness(t)
	for name, pk := range map[string][]byte{"short": {4, 1, 2}, "compressed": append([]byte{2}, make([]byte, 32)...), "off curve": append([]byte{4}, make([]byte, 64)...)} {
		keys := memory.NewStore().AppAttestKeys()
		_ = keys.Create(context.Background(), &domain.AppAttestKeyRecord{
			KeyID: h.dev.keyIDB64(), PublicKey: pk, Environment: domain.AppAttestProduction, ChainVerified: true,
			TenantID: "acme", UserID: userPtr("u1"), Status: domain.AppAttestKeyActive,
		})
		v, _ := NewAppAttestAssertionVerifier(keys, testAppAttestAppID, "production", zap.NewNop())
		_, err := v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), h.good(t, 1)))
		if !errors.Is(err, ErrWIAKeyAttestationInvalid) || !strings.Contains(err.Error(), "unusable") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestAppAttestAssertion_ShortAuthenticatorData(t *testing.T) {
	h := newAssertionHarness(t)
	short, err := cborMarshalAssertion([]byte("sig"), make([]byte, appAttestAssertionAuthLen-1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), short))
	requireInvalid(t, err, "incomplete")
}

// Many requests presenting the same valid assertion (same counter): the
// counter's compare-and-set lets exactly one through.
func TestAppAttestAssertion_ConcurrentReplayExactlyOneWins(t *testing.T) {
	h := newAssertionHarness(t)
	in := h.input(t, h.dev.keyIDB64(), h.good(t, 3))
	var wins, invalid atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 48; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := h.v.Verify(context.Background(), in)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrWIAKeyAttestationInvalid):
				invalid.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || invalid.Load() != 47 {
		t.Fatalf("wins=%d invalid=%d, want 1 and 47", wins.Load(), invalid.Load())
	}
	if got := h.storedCounter(t); got != 3 {
		t.Fatalf("counter = %d", got)
	}
}

// failingAppAttestStore makes the store unavailable.
type failingAppAttestStore struct {
	storage.AppAttestKeyStore
	failGet, failAdvance bool
}

func (f failingAppAttestStore) Get(ctx context.Context, id string) (*domain.AppAttestKeyRecord, error) {
	if f.failGet {
		return nil, errors.New("db down")
	}
	return f.AppAttestKeyStore.Get(ctx, id)
}

func (f failingAppAttestStore) AdvanceCounter(ctx context.Context, id string, n uint32) error {
	if f.failAdvance {
		return errors.New("db down")
	}
	return f.AppAttestKeyStore.AdvanceCounter(ctx, id, n)
}

func TestAppAttestAssertion_StoreOutageFailsClosedAsUnavailable(t *testing.T) {
	for name, st := range map[string]func(storage.AppAttestKeyStore) storage.AppAttestKeyStore{
		"get": func(s storage.AppAttestKeyStore) storage.AppAttestKeyStore {
			return failingAppAttestStore{s, true, false}
		},
		"advance": func(s storage.AppAttestKeyStore) storage.AppAttestKeyStore {
			return failingAppAttestStore{s, false, true}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newAssertionHarness(t)
			h.v.keys = st(h.keys)
			_, err := h.v.Verify(context.Background(), h.input(t, h.dev.keyIDB64(), h.good(t, 1)))
			if !errors.Is(err, ErrWIAKeyAttestationUnavailable) {
				t.Fatalf("err = %v, want unavailable", err)
			}
		})
	}
}

func TestNewAppAttestAssertionVerifier_RequiresStoreAppIDAndKnownEnvironment(t *testing.T) {
	keys := memory.NewStore().AppAttestKeys()
	if _, err := NewAppAttestAssertionVerifier(nil, "a", "production", zap.NewNop()); err == nil {
		t.Error("nil store accepted")
	}
	if _, err := NewAppAttestAssertionVerifier(keys, "", "production", zap.NewNop()); err == nil {
		t.Error("empty app id accepted")
	}
	if _, err := NewAppAttestAssertionVerifier(keys, "a", "staging", zap.NewNop()); err == nil {
		t.Error("unknown environment accepted")
	}
}

func TestAppAttestAssertionBuilder_AlwaysAssertionNeverAttested(t *testing.T) {
	b := appAttestAssertionBuilder{}
	got := b.Build(&domain.KeyAttestationRecord{
		Kind: domain.KeyEvidenceAppAttestAssertion, Home: domain.KeyHomeSecureEnclaveAsserted,
		SecurityLevel: "strongbox", VerifiedBootState: "verified", // must not be rendered
	})
	if got == nil || got.Binding != assurance.BindingAssertion || got.Home != "secure_enclave_asserted" || got.Kind != "app_attest_assertion" || got.Level != "" || got.Boot != "" {
		t.Fatalf("slot = %+v", got)
	}
	// A record claiming a stronger home is not rendered at all.
	for _, home := range []domain.KeyHome{domain.KeyHomeStrongBox, domain.KeyHomeTEE, domain.KeyHomeFIDO2Hardware, domain.KeyHomeHSM, ""} {
		if s := b.Build(&domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAppAttestAssertion, Home: home}); s != nil {
			t.Errorf("home %q rendered as %+v", home, s)
		}
	}
	// And the registry maps the kind to this builder.
	slot := instanceKeyVerifiedFromRecord(&domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAppAttestAssertion, Home: domain.KeyHomeSecureEnclaveAsserted})
	if slot == nil || slot.Binding != assurance.BindingAssertion {
		t.Fatalf("registry slot = %+v", slot)
	}
}

// ---- end to end through GenerateWIA ----

// Issue only when the instance key carries app_attest_assertion evidence.
const wiaNeedsAssertionRules = "# id: needs-assertion\n(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key (kind app_attest_assertion)(home secure_enclave_asserted)(level)(boot)(binding assertion)))))\n"

// Issue regardless of the instance key evidence.
const wiaAnyRules = "# id: any\n(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key))))\n"

type e2e struct {
	svc       *WIAService
	instances storage.WalletInstanceStore
	records   storage.KeyAttestationStore
	appKeys   storage.AppAttestKeyStore
	dev       *testAppAttestDevice
}

func newAssertionE2E(t *testing.T, rules string) *e2e {
	t.Helper()
	svc, instances := wiaAssuranceSvc(t, rules)
	st := memory.NewStore()
	records, appKeys := st.KeyAttestations(), st.AppAttestKeys()
	svc.SetKeyAttestations(records)
	svc.SetAppAttestKeys(appKeys)
	dev := newTestAppAttestDevice(t)
	pub, _ := dev.key.PublicKey.ECDH()
	if err := appKeys.Create(context.Background(), &domain.AppAttestKeyRecord{
		KeyID: dev.keyIDB64(), PublicKey: pub.Bytes(), Environment: domain.AppAttestProduction, AppID: testAppAttestAppID,
		ChainVerified: true, TenantID: domain.DefaultTenantID, Status: domain.AppAttestKeyActive,
	}); err != nil {
		t.Fatal(err)
	}
	v, err := NewAppAttestAssertionVerifier(appKeys, testAppAttestAppID, "production", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	svc.RegisterInstanceKeyVerifier(v)
	return &e2e{svc, instances, records, appKeys, dev}
}

// wia requests a WIA for a fresh PoP key; assertionFor builds the
// key_attestation from the issued challenge and the PoP key's thumbprint.
func (e *e2e) wia(t *testing.T, user *domain.UserID, assertionFor func(challenge, jkt string) *KeyAttestation) (string, string, error) {
	t.Helper()
	ctx := context.Background()
	challenge, _, err := e.svc.CreateChallenge(ctx, domain.DefaultTenantID)
	if err != nil {
		t.Fatal(err)
	}
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)
	var ka *KeyAttestation
	if assertionFor != nil {
		ka = assertionFor(challenge, jkt)
	}
	tok, err := e.svc.GenerateWIA(ctx, domain.DefaultTenantID, user, &WIARequest{Pop: pop, Challenge: challenge, KeyAttestation: ka})
	return tok, jkt, err
}

func (e *e2e) assertion(t *testing.T, counter uint32) func(c, jkt string) *KeyAttestation {
	return func(c, jkt string) *KeyAttestation {
		a := e.dev.assertion(t, AppAttestClientDataHash(c, jkt), assertionOpts{appID: testAppAttestAppID, counter: counter})
		raw, _ := json.Marshal(map[string]string{"type": "app_attest_assertion", "key_id": e.dev.keyIDB64(), "assertion": a})
		return &KeyAttestation{Type: KeyAttestationAppAttestAssertion, Raw: raw}
	}
}

func TestAppAttestAssertion_EndToEndRecordsAssertedEvidenceAndFeedsTheSlot(t *testing.T) {
	e := newAssertionE2E(t, wiaNeedsAssertionRules)
	_, jkt, err := e.wia(t, nil, e.assertion(t, 1))
	if err != nil {
		t.Fatalf("WIA refused: %v", err)
	}
	rec, err := e.records.GetByKeyThumbprint(context.Background(), jkt)
	if err != nil {
		t.Fatalf("no per-key record for the instance key: %v", err)
	}
	if rec.Kind != domain.KeyEvidenceAppAttestAssertion || rec.Home != domain.KeyHomeSecureEnclaveAsserted || rec.KeyThumbprint != jkt {
		t.Fatalf("record = %+v", rec)
	}
	// B1 maps secure_enclave_asserted to native_ios.
	if got := instanceType(t, e.instances, jkt); got != domain.WSCDTypeNativeIOS {
		t.Fatalf("wscd_type = %s", got)
	}

	// The same rule refuses an instance key with no evidence at all.
	if _, _, err := e.wia(t, nil, nil); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("no evidence: err = %v, want refusal by policy", err)
	}
}

func TestAppAttestAssertion_EndToEndRejectsInvalidSubmissionAndRecordsNothing(t *testing.T) {
	e := newAssertionE2E(t, wiaAnyRules)
	good := e.assertion(t, 1)
	cases := map[string]func(c, jkt string) *KeyAttestation{
		// Signed for the right challenge but another PoP key.
		"assertion for another instance key": func(c, jkt string) *KeyAttestation { return good(c, "someone-elses-jkt") },
		// A valid assertion captured for another challenge, replayed here.
		"assertion for another challenge": func(_, jkt string) *KeyAttestation { return good("old-challenge", jkt) },
	}
	for name, f := range cases {
		_, jkt, err := e.wia(t, nil, f)
		if !errors.Is(err, ErrWIAKeyAttestationInvalid) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if _, gerr := e.records.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(gerr, storage.ErrNotFound) {
			t.Fatalf("%s: a record was stored (%v)", name, gerr)
		}
		if _, gerr := e.instances.GetByID(context.Background(), jkt); !errors.Is(gerr, storage.ErrNotFound) {
			t.Fatalf("%s: a refused WIA created an instance", name)
		}
	}
	// The rejected assertions did not consume the counter: counter 1 still works.
	if _, _, err := e.wia(t, nil, e.assertion(t, 1)); err != nil {
		t.Fatalf("legitimate assertion after rejected ones: %v", err)
	}
	// Replaying the now-used counter, with a correctly bound assertion, fails.
	if _, _, err := e.wia(t, nil, e.assertion(t, 1)); !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("counter replay: err = %v", err)
	}
}

func TestAppAttestAssertion_EndToEndKeyBelongsToTheAttestingUser(t *testing.T) {
	e := newAssertionE2E(t, wiaAnyRules)
	if _, _, err := e.wia(t, userPtr("someone"), e.assertion(t, 1)); !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("a user-less App Attest key was usable by a user: %v", err)
	}
}

func TestAppAttestAssertion_EndToEndNeverOverwritesStrongerEvidence(t *testing.T) {
	e := newAssertionE2E(t, wiaAnyRules)
	_, jkt, err := e.wia(t, nil, func(c, jkt string) *KeyAttestation {
		// Stronger evidence for this very instance key already exists.
		putRecord(t, e.records, domain.KeyAttestationRecord{KeyThumbprint: jkt, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox})
		return e.assertion(t, 1)(c, jkt)
	})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := e.records.GetByKeyThumbprint(context.Background(), jkt)
	if rec.Kind != domain.KeyEvidenceAndroidKey || rec.Home != domain.KeyHomeStrongBox {
		t.Fatalf("an assertion replaced stronger evidence: %+v", rec)
	}
}

func TestAppAttestAssertion_EndToEndAbsentEvidenceIsUnknown(t *testing.T) {
	e := newAssertionE2E(t, wiaAnyRules)
	_, jkt, err := e.wia(t, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := instanceType(t, e.instances, jkt); got != domain.WSCDTypeUnknown {
		t.Fatalf("wscd_type = %s", got)
	}
}

// An assertion never yields hardware_attested evidence nor any K level: the
// rendered slot says binding assertion and the home asserted.
func TestAppAttestAssertion_RenderedSlotIsNeverAttested(t *testing.T) {
	e := newAssertionE2E(t, wiaAnyRules)
	_, jkt, err := e.wia(t, nil, e.assertion(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := e.records.GetByKeyThumbprint(context.Background(), jkt)
	slot := instanceKeyVerifiedFromRecord(rec)
	if slot == nil || slot.Binding == assurance.BindingAttested || slot.Home == string(domain.KeyHomeTEE) || slot.Home == string(domain.KeyHomeStrongBox) {
		t.Fatalf("slot = %+v", slot)
	}
}

// The once-per-install limitation: the App Attest key is attested in one WIA
// request (native_attestation), stored bound to the caller, and later WIAs
// for new instance keys use assertions instead of attesting again.
func TestAppAttest_AttestOnceThenAssertForLaterWIAs(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	svc, instances := wiaAssuranceSvc(t, wiaAnyRules)
	st := memory.NewStore()
	records := st.KeyAttestations()
	svc.SetKeyAttestations(records)
	svc.nativeAttSvc = h.svc
	svc.SetAppAttestKeys(h.keys) // also reaches the native service
	v, err := NewAppAttestAssertionVerifier(h.keys, testAppAttestAppID, "production", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	svc.RegisterInstanceKeyVerifier(v)
	ctx := context.Background()
	user := userPtr("u1")
	dev := newTestAppAttestDevice(t)

	// First WIA: the App Attest key is attested with the WIA challenge.
	challenge, _, _ := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	pop, key := createTestPop(t, challenge)
	firstJKT := expectedThumbprint(t, &key.PublicKey)
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, user, &WIARequest{
		Pop: pop, Challenge: challenge,
		NativeAttestation: &NativeAttestationRequest{
			Type: NativeAttestationAppleAppAttest, KeyID: dev.keyIDB64(), Challenge: challenge,
			Token: dev.attestation(t, h.ca, challenge, attOpts{appID: testAppAttestAppID}),
		},
	})
	if err != nil {
		t.Fatalf("first WIA: %v", err)
	}
	stored, err := h.keys.Get(ctx, dev.keyIDB64())
	if err != nil {
		t.Fatalf("attested key not stored by the WIA path: %v", err)
	}
	if stored.TenantID != domain.DefaultTenantID || stored.UserID == nil || stored.UserID.ID != "u1" || stored.WalletInstanceID != firstJKT {
		t.Fatalf("stored binding = %+v", stored)
	}
	// The attestation alone says nothing about the instance key.
	if got := instanceType(t, instances, firstJKT); got != domain.WSCDTypeUnknown {
		t.Fatalf("attestation alone set wscd_type %s", got)
	}

	// Later WIA, a new instance key, no attestation object: an assertion.
	challenge2, _, _ := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	pop2, key2 := createTestPop(t, challenge2)
	jkt2 := expectedThumbprint(t, &key2.PublicKey)
	a := dev.assertion(t, AppAttestClientDataHash(challenge2, jkt2), assertionOpts{appID: testAppAttestAppID, counter: 1})
	raw, _ := json.Marshal(map[string]string{"type": "app_attest_assertion", "key_id": dev.keyIDB64(), "assertion": a})
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, user, &WIARequest{
		Pop: pop2, Challenge: challenge2, KeyAttestation: &KeyAttestation{Type: KeyAttestationAppAttestAssertion, Raw: raw},
	}); err != nil {
		t.Fatalf("later WIA with an assertion: %v", err)
	}
	if got := instanceType(t, instances, jkt2); got != domain.WSCDTypeNativeIOS {
		t.Fatalf("wscd_type = %s", got)
	}

	// Another user cannot use the stored key.
	challenge3, _, _ := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	pop3, key3 := createTestPop(t, challenge3)
	a3 := dev.assertion(t, AppAttestClientDataHash(challenge3, expectedThumbprint(t, &key3.PublicKey)), assertionOpts{appID: testAppAttestAppID, counter: 2})
	raw3, _ := json.Marshal(map[string]string{"type": "app_attest_assertion", "key_id": dev.keyIDB64(), "assertion": a3})
	_, err = svc.GenerateWIA(ctx, domain.DefaultTenantID, userPtr("mallory"), &WIARequest{
		Pop: pop3, Challenge: challenge3, KeyAttestation: &KeyAttestation{Type: KeyAttestationAppAttestAssertion, Raw: raw3},
	})
	if !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("foreign user: err = %v", err)
	}
}

// ---- review follow-ups ----

// Independent interoperability vector: generated with OpenSSL (Python
// cryptography), not with this code. Apple defines nonce = SHA-256(authData ||
// clientDataHash) and the signature is ECDSA-with-SHA-256 over the nonce, i.e.
// over its hash again, which is what an ECDSA-SHA256 implementation produces
// when asked to sign the nonce bytes. NOT captured from a device; a real
// device capture should be added when one is available.
func TestAppAttestAssertion_IndependentlyGeneratedVector(t *testing.T) {
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pub := mustHex("0492cb9907c1a2269d6b4cc793d91c7cce0c141fd4fbf627163f796fe06a86ad4a9fece7cbe4aed0c7665e7e33e929067b891d836ae00dbff3dc8afaadb969aa25")
	authData := mustHex("d16f4131385fa57127c04450e362e990f08119f946d44314cab368cca47c167b0000000001")
	sig := mustHex("304402203481d95f4732d60db1fbe1c854d6a8a00e94d10f7c5207ce71f84fbfbfc3023902200edc82917987ea517df9590a704e854af6b4ff7a3507fc005e449a9414310d05")
	const keyID = "Ju3TG9M5sluwGChWwEOS2rukZMhrKuDSmdEeiS2gAOg="
	if got := hex.EncodeToString(AppAttestClientDataHash("vector-challenge-C", "vector-jkt")); got != "4f46c47c3457350bbb6f30090c3a4c48d7342b891d75e9ac84e67e36a5eaf6b8" {
		t.Fatalf("clientDataHash does not match the independent computation: %s", got)
	}
	keys := memory.NewStore().AppAttestKeys()
	_ = keys.Create(context.Background(), &domain.AppAttestKeyRecord{
		KeyID: keyID, PublicKey: pub, Environment: domain.AppAttestProduction, ChainVerified: true,
		TenantID: "acme", Status: domain.AppAttestKeyActive,
	})
	v, err := NewAppAttestAssertionVerifier(keys, "TEAM123.com.example.test", "production", zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	cborBytes, _ := cbor.Marshal(map[string]any{"signature": sig, "authenticatorData": authData})
	payload, _ := json.Marshal(map[string]string{"type": "app_attest_assertion", "key_id": keyID, "assertion": base64.StdEncoding.EncodeToString(cborBytes)})
	res, err := v.Verify(context.Background(), &InstanceKeyEvidenceInput{
		Payload: payload, Thumbprint: "vector-jkt", TenantID: "acme", WIAChallenge: "vector-challenge-C", Now: time.Now(),
	})
	if err != nil || res.Record == nil {
		t.Fatalf("independent vector rejected: %v %+v", err, res)
	}
}

// Evidence verified for one tenant/user is not lent to another caller that
// merely holds the same key.
func TestAppAttestAssertion_CachedEvidenceIsScopedToTheVerifiedCaller(t *testing.T) {
	e := newAssertionE2E(t, wiaNeedsAssertionRules)
	owner := userPtr("owner")
	// The key attested for no user: re-attest for a user-bound key instead.
	if err := e.appKeys.Revoke(context.Background(), e.dev.keyIDB64()); err != nil {
		t.Fatal(err)
	}
	e.dev = newTestAppAttestDevice(t)
	pub, _ := e.dev.key.PublicKey.ECDH()
	_ = e.appKeys.Create(context.Background(), &domain.AppAttestKeyRecord{
		KeyID: e.dev.keyIDB64(), PublicKey: pub.Bytes(), Environment: domain.AppAttestProduction, AppID: testAppAttestAppID,
		ChainVerified: true, TenantID: domain.DefaultTenantID, UserID: owner, Status: domain.AppAttestKeyActive,
	})

	// The owner endorses a PoP key; the record is bound to the owner.
	ctx := context.Background()
	challenge, _, _ := e.svc.CreateChallenge(ctx, domain.DefaultTenantID)
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)
	a := e.dev.assertion(t, AppAttestClientDataHash(challenge, jkt), assertionOpts{appID: testAppAttestAppID, counter: 1})
	raw, _ := json.Marshal(map[string]string{"type": "app_attest_assertion", "key_id": e.dev.keyIDB64(), "assertion": a})
	if _, err := e.svc.GenerateWIA(ctx, domain.DefaultTenantID, owner, &WIARequest{Pop: pop, Challenge: challenge, KeyAttestation: &KeyAttestation{Type: KeyAttestationAppAttestAssertion, Raw: raw}}); err != nil {
		t.Fatal(err)
	}
	rec, err := e.records.GetByKeyThumbprint(ctx, jkt)
	if err != nil || rec.UserID != "owner" || rec.TenantID != domain.DefaultTenantID {
		t.Fatalf("record scope = %+v (%v)", rec, err)
	}

	renew := func(tenant domain.TenantID, user *domain.UserID) error {
		c, _, _ := e.svc.CreateChallenge(ctx, tenant)
		p := resignPop(t, key, c)
		_, err := e.svc.GenerateWIA(ctx, tenant, user, &WIARequest{Pop: p, Challenge: c})
		return err
	}
	// The same user renews from the cache without resubmitting.
	if err := renew(domain.DefaultTenantID, owner); err != nil {
		t.Fatalf("owner renewal from cached evidence: %v", err)
	}
	// Another user, a caller with no user, and another tenant holding the same key get nothing.
	for name, c := range map[string]struct {
		tenant domain.TenantID
		user   *domain.UserID
	}{
		"other user": {domain.DefaultTenantID, userPtr("thief")},
		"no user":    {domain.DefaultTenantID, nil},
	} {
		if err := renew(c.tenant, c.user); !errors.Is(err, ErrWIARefusedByPolicy) {
			t.Errorf("%s: cached evidence was lent (err=%v)", name, err)
		}
	}
	if got := e.svc.instanceKeyEvidence(ctx, "other-tenant", "owner", jkt); got != nil {
		t.Error("cached evidence was lent to another tenant")
	}
}

type failingMarkStore struct{ storage.KeyAttestationStore }

func (failingMarkStore) MarkKeyAttested(context.Context, *domain.KeyAttestationRecord) error {
	return errors.New("db down")
}

// An outage while storing the verified record is "unavailable" (503), not an
// unclassified 500, and no WIA is issued.
func TestAppAttestAssertion_RecordStoreOutageIsUnavailable(t *testing.T) {
	e := newAssertionE2E(t, wiaAnyRules)
	e.svc.SetKeyAttestations(failingMarkStore{e.records})
	_, _, err := e.wia(t, nil, e.assertion(t, 1))
	if !errors.Is(err, ErrWIAKeyAttestationUnavailable) {
		t.Fatalf("err = %v, want unavailable", err)
	}
}

// A renewal WIA, which carries no native attestation object (platform source
// backend_attested), still gets S1 from the documented template.
func TestAppAttestAssertion_RenewalSelectsS1ThroughTheShippedTemplate(t *testing.T) {
	rules := "# id: s1-app-attest\n" +
		"(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform)(hsm)(instance_key (kind app_attest_assertion)(home)(level)(boot)(binding assertion)))))\n" +
		"# id: issue\n(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key))))\n"
	e := newAssertionE2E(t, rules)
	tok, _, err := e.wia(t, nil, e.assertion(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if got := wiaClaims(t, tok)["attestation_source"]; got != "platform_attested" {
		t.Fatalf("attestation_source = %v, want the S1 value", got)
	}
	tok, _, err = e.wia(t, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := wiaClaims(t, tok)["attestation_source"]; got != "backend_attested" {
		t.Fatalf("no evidence: attestation_source = %v, want the floor", got)
	}
}

// A key-storage (K) decision never reads instance-key evidence: a record of an
// instance-key kind for a key submitted as a credential key does not vouch for
// it, only a FIDO2 record does.
func TestKeyAttestationTrustsBatch_InstanceKeyEvidenceIsNotKeyStorageEvidence(t *testing.T) {
	svc, _, keys := newTestWalletProviderServiceWithInstances(t)
	ctx := context.Background()
	// One fresh key per case: a stored record is never replaced by a different kind.
	freshKey := func() (map[string]interface{}, string) {
		ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]interface{}{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(ck.PublicKey.X.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(ck.PublicKey.Y.FillBytes(make([]byte, 32))),
		}, expectedThumbprint(t, &ck.PublicKey)
	}
	for name, c := range map[string]struct {
		rec  domain.KeyAttestationRecord
		want bool
	}{
		"app_attest_assertion": {domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAppAttestAssertion, Home: domain.KeyHomeSecureEnclaveAsserted}, false},
		"android_key":          {domain.KeyAttestationRecord{Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox}, false},
		"fido2":                {domain.KeyAttestationRecord{Kind: domain.KeyEvidenceFIDO2, Home: domain.KeyHomeFIDO2Hardware, AAGUID: "a"}, true},
	} {
		j, tp := freshKey()
		rec := c.rec
		rec.KeyThumbprint, rec.VerifiedAt = tp, time.Now()
		if err := keys.MarkKeyAttested(ctx, &rec); err != nil {
			t.Fatal(err)
		}
		if got := svc.keyAttestationTrustsBatch(ctx, "", []map[string]interface{}{j}); got != c.want {
			t.Errorf("%s evidence: batch trusted = %v, want %v", name, got, c.want)
		}
	}
}

// Storage failures while recording an attested key refuse the WIA as
// unavailable (retryable), never as an invalid attestation.
type failingAppAttestCreate struct {
	storage.AppAttestKeyStore
	create, get    error
	failCreateOnce bool // when set, the first Create fails (once), later ones succeed
}

func (f *failingAppAttestCreate) Create(ctx context.Context, r *domain.AppAttestKeyRecord) error {
	if f.failCreateOnce {
		f.failCreateOnce = false
		return errors.New("db blip")
	}
	if f.create != nil {
		return f.create
	}
	return f.AppAttestKeyStore.Create(ctx, r)
}

func (f *failingAppAttestCreate) Get(ctx context.Context, id string) (*domain.AppAttestKeyRecord, error) {
	if f.get != nil {
		return nil, f.get
	}
	return f.AppAttestKeyStore.Get(ctx, id)
}

func TestAppAttest_PersistenceFailureIsUnavailableNotInvalid(t *testing.T) {
	d := newTestAppAttestDevice(t)
	t.Run("create fails", func(t *testing.T) {
		h := newAppAttestHarness(t, "production")
		h.svc.SetAppAttestKeys(&failingAppAttestCreate{AppAttestKeyStore: h.keys, create: errors.New("db down")})
		_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{})
		if !errors.Is(err, ErrNativeAttestationUnavailable) || errors.Is(err, ErrNativeAttestationInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("get fails after a duplicate", func(t *testing.T) {
		h := newAppAttestHarness(t, "production")
		if _, err := h.verify(t, testBinding, d, d.keyIDB64(), "c", attOpts{}); err != nil {
			t.Fatal(err)
		}
		h.svc.SetAppAttestKeys(&failingAppAttestCreate{AppAttestKeyStore: h.keys, get: errors.New("db down")})
		_, err := h.verify(t, testBinding, d, d.keyIDB64(), "c2", attOpts{})
		if !errors.Is(err, ErrNativeAttestationUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("through GenerateWIA", func(t *testing.T) {
		h := newAppAttestHarness(t, "production")
		h.svc.SetAppAttestKeys(&failingAppAttestCreate{AppAttestKeyStore: h.keys, create: errors.New("db down")})
		svc, _ := newTestWIAServiceWithInstances(t)
		svc.nativeAttSvc = h.svc
		ctx := context.Background()
		challenge, _, _ := svc.CreateChallenge(ctx, domain.DefaultTenantID)
		pop, _ := createTestPop(t, challenge)
		_, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{
			Pop: pop, Challenge: challenge,
			NativeAttestation: &NativeAttestationRequest{
				Type: NativeAttestationAppleAppAttest, KeyID: d.keyIDB64(), Challenge: challenge,
				Token: d.attestation(t, h.ca, challenge, attOpts{appID: testAppAttestAppID}),
			},
		})
		if !errors.Is(err, ErrWIANativeAttestationUnavailable) || errors.Is(err, ErrWIAPopInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
}

// The preview reads the instance key's evidence like GenerateWIA does, so it
// applies the same caller scope: evidence verified for another user is not used.
func TestPreview_InstanceKeyEvidenceIsScopedToTheCaller(t *testing.T) {
	rules := "# id: needs-assertion\n(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key (kind app_attest_assertion)(home secure_enclave_asserted)(level)(boot)(binding assertion)))))\n"
	svc, instances, keys := assuranceSvc(t, nil, rules)
	ctx := context.Background()
	owner := domain.UserIDFromString("owner")
	for id, c := range map[string]struct {
		recUser string
		want    bool
	}{"inst-own": {"owner", true}, "inst-foreign": {"someone-else", false}} {
		if err := instances.Upsert(ctx, &domain.WalletInstance{
			ID: id, TenantID: "t1", UserID: &owner, AttestationSource: "backend_attested", Status: domain.InstanceStatusActive, LastAttestedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
		rec := domain.KeyAttestationRecord{
			KeyThumbprint: id, TenantID: "t1", UserID: c.recUser,
			Kind: domain.KeyEvidenceAppAttestAssertion, Home: domain.KeyHomeSecureEnclaveAsserted, VerifiedAt: time.Now(),
		}
		if err := keys.MarkKeyAttested(ctx, &rec); err != nil {
			t.Fatal(err)
		}
		got, err := svc.PreviewAssurance(WithKeyAttestationCaller(ctx, KeyAttestationCaller{TenantID: "t1", UserID: "owner"}), &AssurancePreviewRequest{WalletInstanceID: id})
		if err != nil {
			t.Fatal(err)
		}
		if got.WIAIssue != c.want {
			t.Errorf("%s: WIAIssue = %v, want %v", id, got.WIAIssue, c.want)
		}
	}
}

// A storage failure while enrolling the App Attest key must not strand the
// client: Apple's attestation object is once per key and its nonce binds the
// original challenge, so the identical request has to succeed on retry.
func TestAppAttest_FailedEnrollmentCanBeRetriedWithTheSameRequest(t *testing.T) {
	h := newAppAttestHarness(t, "production")
	flaky := &failingAppAttestCreate{AppAttestKeyStore: h.keys, failCreateOnce: true}
	h.svc.SetAppAttestKeys(flaky)
	svc, _ := newTestWIAServiceWithInstances(t)
	svc.nativeAttSvc = h.svc
	d := newTestAppAttestDevice(t)
	ctx := context.Background()
	challenge, _, _ := svc.CreateChallenge(ctx, domain.DefaultTenantID)
	pop, _ := createTestPop(t, challenge)
	req := &WIARequest{Pop: pop, Challenge: challenge, NativeAttestation: &NativeAttestationRequest{
		Type: NativeAttestationAppleAppAttest, KeyID: d.keyIDB64(), Challenge: challenge,
		Token: d.attestation(t, h.ca, challenge, attOpts{appID: testAppAttestAppID}),
	}}
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, req); !errors.Is(err, ErrWIANativeAttestationUnavailable) {
		t.Fatalf("first attempt: %v", err)
	}
	if _, err := h.keys.Get(ctx, d.keyIDB64()); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("key stored by the failed attempt")
	}
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, req); err != nil {
		t.Fatalf("retry of the identical request: %v", err)
	}
	if _, err := h.keys.Get(ctx, d.keyIDB64()); err != nil {
		t.Fatalf("key not stored after the retry: %v", err)
	}
	// And the challenge is single-use again after the successful retry.
	if _, err := svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, req); !errors.Is(err, ErrWIAChallengeExpired) {
		t.Fatalf("challenge reusable after success: %v", err)
	}
}
