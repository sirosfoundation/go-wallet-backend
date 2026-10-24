package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage/memory"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Issue only when the instance key is verified hardware-backed Android evidence.
const wiaNeedsAndroidRules = "# id: ik-android\n(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key (kind android_key)(home (* set strongbox tee))(level)(boot)(binding attested)))))\n"

// akWIA is a WIA service with the real Android verifier trusting a test root.
type akWIA struct {
	t     *testing.T
	svc   *WIAService
	inst  storage.WalletInstanceStore
	keys  storage.KeyAttestationStore
	fx    *chainFixture
	fetch *fakeStatusFetcher
}

func newAKWIA(t *testing.T, rules string) *akWIA {
	t.Helper()
	svc, inst := wiaAssuranceSvc(t, rules)
	keys := memory.NewStore().KeyAttestations()
	svc.SetKeyAttestations(keys)
	fx := newChainFixture(t)
	fetch := &fakeStatusFetcher{body: emptyStatusList, maxAge: time.Hour}
	v, err := NewAndroidKeyAttestationVerifier(config.AndroidKeyAttestationConfig{
		TrustAnchorsPEM: fx.rootPEM(), AllowedAppDigests: []string{testAppDigestHex()},
	}, zap.NewNop(), fetch)
	if err != nil {
		t.Fatal(err)
	}
	svc.RegisterInstanceKeyVerifier(v)
	return &akWIA{t: t, svc: svc, inst: inst, keys: keys, fx: fx, fetch: fetch}
}

// request prepares one WIA request: a fresh challenge and PoP, with the
// attestation built by chain(challenge, popPublicKey).
func (a *akWIA) request(chain func(challenge string, pub *ecdsa.PublicKey) [][]byte) (jkt string, req *WIARequest, key *ecdsa.PrivateKey) {
	a.t.Helper()
	challenge, _, err := a.svc.CreateChallenge(context.Background(), domain.DefaultTenantID)
	if err != nil {
		a.t.Fatal(err)
	}
	pop, key := createTestPop(a.t, challenge)
	req = &WIARequest{Pop: pop, Challenge: challenge}
	if chain != nil {
		raw, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(chain(challenge, &key.PublicKey))})
		req.KeyAttestation = &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: raw}
	}
	return expectedThumbprint(a.t, &key.PublicKey), req, key
}

func (a *akWIA) good(mut func(*kdParams)) func(string, *ecdsa.PublicKey) [][]byte {
	return func(challenge string, pub *ecdsa.PublicKey) [][]byte {
		kd := goodParams(InstanceKeyAttestationChallenge(challenge))
		if mut != nil {
			mut(&kd)
		}
		return a.fx.leaf(pub, encodeKeyDescription(kd), leafOpts{})
	}
}

func (a *akWIA) generate(req *WIARequest) error {
	_, err := a.svc.GenerateWIA(context.Background(), domain.DefaultTenantID, nil, req)
	return err
}

func (a *akWIA) record(jkt string) *domain.KeyAttestationRecord {
	rec, err := a.keys.GetByKeyThumbprint(context.Background(), jkt)
	if err != nil {
		a.t.Fatalf("no record: %v", err)
	}
	return rec
}

func TestWIAAndroidKey_VerifiedEvidenceFillsRecordInstanceTypeAndSlot(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(*kdParams)
		home domain.KeyHome
	}{
		"tee":       {nil, domain.KeyHomeTEE},
		"strongbox": {func(k *kdParams) { k.AttLevel, k.KmLevel = androidLevelStrongBox, androidLevelStrongBox }, domain.KeyHomeStrongBox},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAKWIA(t, wiaNeedsAndroidRules)
			jkt, req, _ := a.request(a.good(tc.mut))
			// The policy requires the attested android_key slot: issuance
			// proves the slot was filled from the verified record.
			if err := a.generate(req); err != nil {
				t.Fatalf("WIA refused: %v", err)
			}
			rec := a.record(jkt)
			if rec.Kind != domain.KeyEvidenceAndroidKey || rec.Home != tc.home || rec.WalletInstanceID != jkt || rec.TenantID != domain.DefaultTenantID {
				t.Fatalf("record = %+v", rec)
			}
			if got := instanceType(t, a.inst, jkt); got != domain.WSCDTypeNativeAndroid {
				t.Fatalf("wscd_type = %s", got)
			}
		})
	}
}

func TestWIAAndroidKey_WithoutEvidenceThePolicyRefusesAndTypeIsUnknown(t *testing.T) {
	a := newAKWIA(t, wiaNeedsAndroidRules)
	_, req, _ := a.request(nil)
	if err := a.generate(req); !errors.Is(err, ErrWIARefusedByPolicy) {
		t.Fatalf("err = %v", err)
	}
	// Policy off: the same absence simply yields an unknown home.
	b := newAKWIA(t, "")
	b.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	jkt, req, _ := b.request(nil)
	if err := b.generate(req); err != nil {
		t.Fatal(err)
	}
	if got := instanceType(t, b.inst, jkt); got != domain.WSCDTypeUnknown {
		t.Fatalf("wscd_type = %s", got)
	}
}

// The evidence is bound to the WIA challenge: a chain captured for one
// challenge is refused under another, and a challenge cannot be replayed.
func TestWIAAndroidKey_ChallengeBindingAndReplay(t *testing.T) {
	a := newAKWIA(t, "")
	a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false

	// Chain made for a different challenge than the request's.
	_, req, _ := a.request(a.good(func(k *kdParams) { k.Challenge = InstanceKeyAttestationChallenge("another") }))
	if err := a.generate(req); !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("foreign challenge: err = %v", err)
	}

	// Replay: the challenge is single use, even when the first try succeeded.
	jkt, req, _ := a.request(a.good(nil))
	if err := a.generate(req); err != nil {
		t.Fatal(err)
	}
	if err := a.generate(req); !errors.Is(err, ErrWIAChallengeExpired) {
		t.Fatalf("replayed request: err = %v", err)
	}
	_ = a.record(jkt)

	// A captured chain re-submitted with a fresh challenge and PoP fails: the
	// leaf key is the old PoP key, the challenge is the old one.
	_, req2, _ := a.request(nil)
	old := a.fx.leaf(&genKey(t).PublicKey, encodeKeyDescription(goodParams(InstanceKeyAttestationChallenge("stale"))), leafOpts{})
	raw, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(old)})
	req2.KeyAttestation = &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: raw}
	if err := a.generate(req2); !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("captured chain: err = %v", err)
	}
}

func TestWIAAndroidKey_InvalidEvidenceRefusesTheWIAAndRecordsNothing(t *testing.T) {
	a := newAKWIA(t, "")
	a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	other := genKey(t)
	jkt, req, _ := a.request(func(challenge string, _ *ecdsa.PublicKey) [][]byte {
		// Attests a key that is not the PoP key.
		return a.fx.leaf(&other.PublicKey, encodeKeyDescription(goodParams(InstanceKeyAttestationChallenge(challenge))), leafOpts{})
	})
	if err := a.generate(req); !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		t.Fatalf("err = %v", err)
	}
	if _, err := a.keys.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("record stored: %v", err)
	}
	if _, err := a.inst.GetByID(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("instance created: %v", err)
	}
}

func TestWIAAndroidKey_RevocationOutageRefusesAndRecordsNothing(t *testing.T) {
	a := newAKWIA(t, "")
	a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	a.fetch.err = errors.New("status endpoint down")
	jkt, req, _ := a.request(a.good(nil))
	if err := a.generate(req); !errors.Is(err, ErrWIAKeyAttestationUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if _, err := a.keys.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("record stored while the status list was unavailable: %v", err)
	}
}

func TestWIAAndroidKey_SoftwareEvidenceGivesNoHomeButIssues(t *testing.T) {
	a := newAKWIA(t, "")
	a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	jkt, req, _ := a.request(a.good(func(k *kdParams) { k.AttLevel, k.KmLevel = -1, -1 }))
	if err := a.generate(req); err != nil {
		t.Fatalf("software evidence must not refuse the WIA: %v", err)
	}
	if _, err := a.keys.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("a software chain produced a record: %v", err)
	}
	if got := instanceType(t, a.inst, jkt); got != domain.WSCDTypeUnknown {
		t.Fatalf("wscd_type = %s", got)
	}
}

// Stored evidence is never replaced by weaker or absent evidence: a key with a
// verified strongbox record that later submits (or omits) weaker evidence keeps it.
func TestWIAAndroidKey_NeverOverwrittenByWeakerOrAbsentEvidence(t *testing.T) {
	a := newAKWIA(t, "")
	a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	ctx := context.Background()

	// First a strongbox record for a key (as a prior verified WIA would have stored).
	challenge, _, _ := a.svc.CreateChallenge(ctx, domain.DefaultTenantID)
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)
	chain := a.fx.leaf(&key.PublicKey, encodeKeyDescription(func() kdParams {
		k := goodParams(InstanceKeyAttestationChallenge(challenge))
		k.AttLevel, k.KmLevel = androidLevelStrongBox, androidLevelStrongBox
		return k
	}()), leafOpts{})
	raw, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(chain)})
	if _, err := a.svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, &WIARequest{Pop: pop, Challenge: challenge, KeyAttestation: &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: raw}}); err != nil {
		t.Fatal(err)
	}
	if a.record(jkt).Home != domain.KeyHomeStrongBox {
		t.Fatal("strongbox record missing")
	}

	refresh := func(kd func(*kdParams), withEvidence bool) {
		t.Helper()
		c, _, _ := a.svc.CreateChallenge(ctx, domain.DefaultTenantID)
		pop := signPopWithKey(t, key, c)
		req := &WIARequest{Pop: pop, Challenge: c}
		if withEvidence {
			k := goodParams(InstanceKeyAttestationChallenge(c))
			kd(&k)
			raw, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(a.fx.leaf(&key.PublicKey, encodeKeyDescription(k), leafOpts{}))})
			req.KeyAttestation = &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: raw}
		}
		if _, err := a.svc.GenerateWIA(ctx, domain.DefaultTenantID, nil, req); err != nil {
			t.Fatal(err)
		}
	}
	refresh(func(*kdParams) {}, false)                                  // absent
	refresh(func(k *kdParams) {}, true)                                 // weaker (TEE)
	refresh(func(k *kdParams) { k.AttLevel, k.KmLevel = -1, -1 }, true) // software
	if rec := a.record(jkt); rec.Home != domain.KeyHomeStrongBox || rec.SecurityLevel != "strongbox" {
		t.Fatalf("stored evidence was weakened: %+v", rec)
	}
	// The instance still reads strongbox-backed evidence on every later WIA.
	if got := instanceType(t, a.inst, jkt); got != domain.WSCDTypeNativeAndroid {
		t.Fatalf("wscd_type = %s", got)
	}
}

// A different instance's record is not consulted: evidence is per key.
func TestWIAAndroidKey_EvidenceIsPerKey(t *testing.T) {
	a := newAKWIA(t, "")
	a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	_, req, _ := a.request(a.good(nil))
	if err := a.generate(req); err != nil {
		t.Fatal(err)
	}
	jkt2, req2, _ := a.request(nil)
	if err := a.generate(req2); err != nil {
		t.Fatal(err)
	}
	if got := instanceType(t, a.inst, jkt2); got != domain.WSCDTypeUnknown {
		t.Fatalf("another key inherited evidence: %s", got)
	}
}

func TestAndroidKeyBuilder_RendersAttestedSlotFromRecordOnly(t *testing.T) {
	ik := instanceKeyVerifiedFromRecord(&domain.KeyAttestationRecord{
		Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox, SecurityLevel: "strongbox", VerifiedBootState: "verified",
	})
	if ik == nil || ik.Kind != "android_key" || ik.Home != "strongbox" || ik.Level != "strongbox" || ik.Boot != "verified" || ik.Binding != "attested" {
		t.Fatalf("slot = %+v", ik)
	}
}

// signPopWithKey builds a WIA-PoP for an existing key (a later WIA of the same instance).
func signPopWithKey(t *testing.T, key *ecdsa.PrivateKey, nonce string) string {
	t.Helper()
	claims := &WIAPopClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "urn:wallet:instance:test-123",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce: nonce,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	tok.Header["jwk"] = map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.FillBytes(make([]byte, 32))),
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Cached instance-key evidence is used only for the tenant and user it was
// verified for.
func TestWIAAndroidKey_EvidenceIsScopedToTenantAndUser(t *testing.T) {
	a := newAKWIA(t, "")
	a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	ctx := context.Background()
	alice, bob := domain.UserIDFromString("alice"), domain.UserIDFromString("bob")

	challenge, _, _ := a.svc.CreateChallenge(ctx, domain.DefaultTenantID)
	pop, key := createTestPop(t, challenge)
	jkt := expectedThumbprint(t, &key.PublicKey)
	raw, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(a.good(nil)(challenge, &key.PublicKey))})
	if _, err := a.svc.GenerateWIA(ctx, domain.DefaultTenantID, &alice, &WIARequest{Pop: pop, Challenge: challenge, KeyAttestation: &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: raw}}); err != nil {
		t.Fatal(err)
	}
	if rec := a.record(jkt); rec.UserID != alice.String() {
		t.Fatalf("record user = %q", rec.UserID)
	}

	later := func(tenant domain.TenantID, user *domain.UserID) domain.WSCDType {
		t.Helper()
		c, _, err := a.svc.CreateChallenge(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.svc.GenerateWIA(ctx, tenant, user, &WIARequest{Pop: signPopWithKey(t, key, c), Challenge: c}); err != nil {
			t.Fatal(err)
		}
		return instanceType(t, a.inst, jkt)
	}
	if got := later(domain.DefaultTenantID, &bob); got != domain.WSCDTypeUnknown {
		t.Fatalf("another user reused the evidence: %s", got)
	}
	if got := later(domain.DefaultTenantID, nil); got != domain.WSCDTypeUnknown {
		t.Fatalf("an unauthenticated request reused the evidence: %s", got)
	}
	if got := later("other-tenant", &alice); got != domain.WSCDTypeUnknown {
		t.Fatalf("another tenant reused the evidence: %s", got)
	}
	if got := later(domain.DefaultTenantID, &alice); got != domain.WSCDTypeNativeAndroid {
		t.Fatalf("the verified user lost its evidence: %s", got)
	}
}

func TestPreview_WIAHalfHonoursEvidenceScope(t *testing.T) {
	svc, instances, keys := previewSvc(t, wiaNeedsAndroidRules, true)
	const jkt = "instance-key-jkt-android"
	if err := instances.Upsert(context.Background(), &domain.WalletInstance{ID: jkt, TenantID: domain.DefaultTenantID, Status: domain.InstanceStatusActive, LastAttestedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: jkt, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeTEE, TenantID: domain.DefaultTenantID, UserID: "u1"})
	issue := func(user string) bool {
		ctx := WithKeyAttestationCaller(context.Background(), KeyAttestationCaller{TenantID: domain.DefaultTenantID, UserID: user})
		got, err := svc.PreviewAssurance(ctx, &AssurancePreviewRequest{WalletInstanceID: jkt})
		if err != nil {
			t.Fatal(err)
		}
		return got.WIAIssue
	}
	if !issue("u1") || issue("u2") || issue("") {
		t.Fatal("the preview did not honour the evidence's user scope")
	}
}

// Policy disabled: a stored instance-key record that outranks a FIDO2
// submission becomes the preview's overlay, and the no-JWKS fallback must not
// treat it as FIDO2 evidence (actual issuance clamps).
func TestPreview_PolicyDisabledFallbackIgnoresInstanceKeyOverlay(t *testing.T) {
	svc, _, keys := previewSvc(t, "", true)
	svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	aaguid := uuid.MustParse("00000000-0000-0000-0000-0000000000aa")
	sub, tp := fido2Submission(t, aaguid, 0x40|0x04|0x01)
	req := &AssurancePreviewRequest{FIDO2: sub, SecurityProperties: &SecurityProperties{KeyStorage: []string{"iso_18045_high"}}}

	// Control: with no stored record the FIDO2 submission itself vouches.
	got, err := svc.PreviewAssurance(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyStorage[0] != "iso_18045_high" {
		t.Fatalf("control: %+v", got)
	}
	// A stored android_key record of equal rank is not superseded by the submission.
	putRecord(t, keys, domain.KeyAttestationRecord{KeyThumbprint: tp, Kind: domain.KeyEvidenceAndroidKey, Home: domain.KeyHomeStrongBox, TenantID: domain.DefaultTenantID})
	got, err = svc.PreviewAssurance(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyStorage[0] == "iso_18045_high" {
		t.Fatalf("an instance-key overlay vouched for key storage: %+v", got)
	}
}
