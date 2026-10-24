package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

type fakeStatusFetcher struct {
	body   string
	maxAge time.Duration
	err    error
	calls  int
}

func (f *fakeStatusFetcher) Fetch(context.Context) ([]byte, time.Duration, error) {
	f.calls++
	if f.err != nil {
		return nil, 0, f.err
	}
	return []byte(f.body), f.maxAge, nil
}

const emptyStatusList = `{"entries":{}}`

// akHarness wires a verifier that trusts only the fixture root and the test app.
type akHarness struct {
	t         *testing.T
	fx        *chainFixture
	v         *AndroidKeyAttestationVerifier
	fetch     *fakeStatusFetcher
	pop       *ecdsa.PrivateKey
	challenge string // the WIA challenge C
}

func newAKHarness(t *testing.T, mutate func(*config.AndroidKeyAttestationConfig)) *akHarness {
	t.Helper()
	fx := newChainFixture(t)
	cfg := config.AndroidKeyAttestationConfig{
		TrustAnchorsPEM:   fx.rootPEM(),
		AllowedAppDigests: []string{testAppDigestHex()},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	fetch := &fakeStatusFetcher{body: emptyStatusList, maxAge: time.Hour}
	v, err := NewAndroidKeyAttestationVerifier(cfg, zap.NewNop(), fetch)
	if err != nil {
		t.Fatal(err)
	}
	return &akHarness{t: t, fx: fx, v: v, fetch: fetch, pop: genKey(t), challenge: "test-wia-challenge-AAAAAAAAAAAAAAAAAAAAAAAAAAA"}
}

func (h *akHarness) goodKD() kdParams {
	return goodParams(InstanceKeyAttestationChallenge(h.challenge))
}

// chain issues [leaf, intermediate, root] for the PoP key.
func (h *akHarness) chain(kd kdParams, o leafOpts) [][]byte {
	return h.fx.leaf(&h.pop.PublicKey, encodeKeyDescription(kd), o)
}

func (h *akHarness) verifyX5C(x5c []string) (*InstanceKeyEvidenceResult, error) {
	payload, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": x5c})
	return h.verifyPayload(payload)
}

func (h *akHarness) verifyPayload(payload []byte) (*InstanceKeyEvidenceResult, error) {
	return h.v.Verify(context.Background(), &InstanceKeyEvidenceInput{
		Payload: payload, PoPKey: &h.pop.PublicKey, WIAChallenge: h.challenge,
		TenantID: domain.DefaultTenantID, Now: time.Now().UTC(),
	})
}

func (h *akHarness) verify(chain [][]byte) (*InstanceKeyEvidenceResult, error) {
	return h.verifyX5C(b64chain(chain))
}

func (h *akHarness) ok(chain [][]byte) *domain.KeyAttestationRecord {
	h.t.Helper()
	res, err := h.verify(chain)
	if err != nil {
		h.t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.Record == nil {
		h.t.Fatalf("expected a verified record, got none (reason %q)", res.Reason)
	}
	return res.Record
}

func (h *akHarness) noHome(chain [][]byte, reasonContains string) {
	h.t.Helper()
	res, err := h.verify(chain)
	if err != nil {
		h.t.Fatalf("expected no-home, got error: %v", err)
	}
	if res == nil || res.Record != nil {
		h.t.Fatalf("expected no record, got %+v", res)
	}
	if !strings.Contains(res.Reason, reasonContains) {
		h.t.Fatalf("reason %q does not contain %q", res.Reason, reasonContains)
	}
}

func (h *akHarness) invalid(chain [][]byte, contains string) {
	h.t.Helper()
	res, err := h.verify(chain)
	h.wantInvalid(res, err, contains)
}

func (h *akHarness) wantInvalid(res *InstanceKeyEvidenceResult, err error, contains string) {
	h.t.Helper()
	if !errors.Is(err, ErrWIAKeyAttestationInvalid) {
		h.t.Fatalf("expected invalid, got res=%+v err=%v", res, err)
	}
	if !strings.Contains(err.Error(), contains) {
		h.t.Fatalf("error %q does not contain %q", err, contains)
	}
}

func TestAndroidKey_PositiveTEE(t *testing.T) {
	h := newAKHarness(t, nil)
	rec := h.ok(h.chain(h.goodKD(), leafOpts{}))
	if rec.Kind != domain.KeyEvidenceAndroidKey || rec.Home != domain.KeyHomeTEE || rec.SecurityLevel != "trusted_environment" {
		t.Fatalf("record = %+v", rec)
	}
	if rec.VerifiedBootState != "verified" || rec.DeviceLocked == nil || !*rec.DeviceLocked || rec.PatchLevel != "20241005" {
		t.Fatalf("boot evidence = %q locked=%v patch=%q", rec.VerifiedBootState, rec.DeviceLocked, rec.PatchLevel)
	}
	if rec.AppDigest != testAppDigestHex() || len(rec.ChainFingerprint) != 64 {
		t.Fatalf("app digest %q fingerprint %q", rec.AppDigest, rec.ChainFingerprint)
	}
	// ChainNotAfter is the earliest NotAfter of the chain: the leaf's (+12h)
	// here, the intermediate's is +24h and the root's +48h.
	if d := time.Until(rec.ChainNotAfter) - 12*time.Hour; d < -time.Minute || d > time.Minute {
		t.Fatalf("ChainNotAfter = %v", rec.ChainNotAfter)
	}
}

func TestAndroidKey_PositiveStrongBox(t *testing.T) {
	h := newAKHarness(t, nil)
	kd := h.goodKD()
	kd.AttLevel, kd.KmLevel = androidLevelStrongBox, androidLevelStrongBox
	rec := h.ok(h.chain(kd, leafOpts{}))
	if rec.Home != domain.KeyHomeStrongBox || rec.SecurityLevel != "strongbox" {
		t.Fatalf("record = %+v", rec)
	}
}

// A StrongBox attestation of a TEE keymaster (or the reverse) is as strong as
// the weaker of the two.
func TestAndroidKey_MixedLevelsTakeTheWeaker(t *testing.T) {
	for _, lv := range [][2]int{{androidLevelStrongBox, androidLevelTrustedEnvironment}, {androidLevelTrustedEnvironment, androidLevelStrongBox}} {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.AttLevel, kd.KmLevel = lv[0], lv[1]
		if rec := h.ok(h.chain(kd, leafOpts{})); rec.Home != domain.KeyHomeTEE {
			t.Fatalf("levels %v -> home %s", lv, rec.Home)
		}
	}
}

// Unknown attestation versions and unknown authorization tags must not break
// parsing (the format grows with every Android release).
func TestAndroidKey_ToleratesUnknownVersionsAndTags(t *testing.T) {
	h := newAKHarness(t, nil)
	kd := h.goodKD()
	kd.Version = 400
	kd.ExtraSoftware = [][]byte{explicit(9999, integer(7)), explicit(701, mustMarshal(time.Now().Unix()))}
	kd.ExtraTEE = [][]byte{explicit(3, integer(256)), explicit(5, derSet(integer(4))), explicit(5555, octets([]byte("x")))}
	if rec := h.ok(h.chain(kd, leafOpts{})); rec.Home != domain.KeyHomeTEE {
		t.Fatalf("home = %s", rec.Home)
	}
}

func TestAndroidKey_BootEvidenceIsRecordedNotRequired(t *testing.T) {
	h := newAKHarness(t, nil)
	kd := h.goodKD()
	kd.BootState, kd.Locked = 2, false // unverified, unlocked bootloader
	rec := h.ok(h.chain(kd, leafOpts{}))
	if rec.VerifiedBootState != "unverified" || rec.DeviceLocked == nil || *rec.DeviceLocked {
		t.Fatalf("boot = %q locked=%v", rec.VerifiedBootState, rec.DeviceLocked)
	}
	kd = h.goodKD()
	kd.NoRootOfTrust, kd.Patch = true, nil
	rec = h.ok(h.chain(kd, leafOpts{}))
	if rec.VerifiedBootState != "" || rec.DeviceLocked != nil || rec.PatchLevel != "" {
		t.Fatalf("absent evidence was invented: %+v", rec)
	}
}

func TestAndroidKey_WrongChallengeIsInvalid(t *testing.T) {
	h := newAKHarness(t, nil)
	kd := h.goodKD()
	kd.Challenge = InstanceKeyAttestationChallenge("another challenge")
	h.invalid(h.chain(kd, leafOpts{}), "challenge")
	// A challenge that is the bare WIA challenge (no domain separation) is wrong too.
	kd.Challenge = []byte(h.challenge)
	h.invalid(h.chain(kd, leafOpts{}), "challenge")
	kd.Challenge = nil
	h.invalid(h.chain(kd, leafOpts{}), "challenge")
}

func TestAndroidKey_WrongLeafKeyIsInvalid(t *testing.T) {
	h := newAKHarness(t, nil)
	other := genKey(t)
	chain := h.fx.leaf(&other.PublicKey, encodeKeyDescription(h.goodKD()), leafOpts{})
	h.invalid(chain, "not the WIA-PoP key")
}

func TestAndroidKey_SoftwareLevelsGiveNoHome(t *testing.T) {
	for _, lv := range [][2]int{
		{androidLevelSoftware, androidLevelSoftware},
		{androidLevelTrustedEnvironment, androidLevelSoftware},
		{androidLevelSoftware, androidLevelTrustedEnvironment},
		{7, androidLevelTrustedEnvironment}, // not a level at all
	} {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.AttLevel, kd.KmLevel = lv[0], lv[1]
		if lv[0] == 0 && lv[1] == 0 {
			// encodeKeyDescription defaults 0/0 to TEE; force software through a non-zero sentinel.
			kd.AttLevel, kd.KmLevel = -1, -1
		}
		h.noHome(h.chain(kd, leafOpts{}), "not hardware")
	}
}

func TestAndroidKey_UnknownRootGivesNoHome(t *testing.T) {
	h := newAKHarness(t, nil)
	// A complete, internally valid chain under a root nobody pinned.
	other := newChainFixture(t)
	chain := other.leaf(&h.pop.PublicKey, encodeKeyDescription(h.goodKD()), leafOpts{})
	h.noHome(chain, "pinned trust anchor")
	// The root need not be sent: a chain that stops below a PINNED root still
	// verifies against the operator's copy of it.
	h.ok(h.chain(h.goodKD(), leafOpts{})[:2])
	// But a chain whose last certificate is not issued by any pinned anchor
	// does not, however complete it looks.
	h.noHome(other.leaf(&h.pop.PublicKey, encodeKeyDescription(h.goodKD()), leafOpts{})[:2], "pinned trust anchor")
}

func TestAndroidKey_NoAnchorsOrNoAppsVerifiesNothing(t *testing.T) {
	for name, mut := range map[string]func(*config.AndroidKeyAttestationConfig){
		"no anchors":  func(c *config.AndroidKeyAttestationConfig) { c.TrustAnchorsPEM = "" },
		"no app list": func(c *config.AndroidKeyAttestationConfig) { c.AllowedAppDigests = nil },
	} {
		t.Run(name, func(t *testing.T) {
			h := newAKHarness(t, mut)
			h.noHome(h.chain(h.goodKD(), leafOpts{}), "not configured")
			// Not even a malformed payload is looked at: nothing is learned from it.
			res, err := h.verifyPayload([]byte(`not json`))
			if err != nil || res.Record != nil {
				t.Fatalf("res=%+v err=%v", res, err)
			}
			if h.fetch.calls != 0 {
				t.Fatal("fetched a revocation list without trust configured")
			}
		})
	}
}

func TestAndroidKey_OriginAndPurposeMustBeHardwareGeneratedSigning(t *testing.T) {
	cases := map[string]struct {
		mut    func(*kdParams)
		reason string
	}{
		"origin imported":   {func(k *kdParams) { k.Origin = intp(2) }, "not generated"},
		"origin derived":    {func(k *kdParams) { k.Origin = intp(1) }, "not generated"},
		"origin missing":    {func(k *kdParams) { k.Origin = nil }, "not generated"},
		"origin only in sw": {func(k *kdParams) { k.Origin = nil; k.ExtraSoftware = [][]byte{explicit(akTagOrigin, integer(0))} }, "not generated"},
		"no sign purpose":   {func(k *kdParams) { k.Purposes = []int{3, 4} }, "SIGN"},
		"no purposes":       {func(k *kdParams) { k.Purposes = nil }, "SIGN"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newAKHarness(t, nil)
			kd := h.goodKD()
			tc.mut(&kd)
			h.noHome(h.chain(kd, leafOpts{}), tc.reason)
		})
	}
	// Sign among other purposes is fine.
	h := newAKHarness(t, nil)
	kd := h.goodKD()
	kd.Purposes = []int{2, 3}
	h.ok(h.chain(kd, leafOpts{}))
}

func TestAndroidKey_AlgorithmAndCurveMismatchIsInvalid(t *testing.T) {
	h := newAKHarness(t, nil)
	kd := h.goodKD()
	kd.Algorithm = intp(1) // RSA
	h.invalid(h.chain(kd, leafOpts{}), "algorithm")
	kd = h.goodKD()
	kd.Curve = intp(3) // P-384
	h.invalid(h.chain(kd, leafOpts{}), "curve")
}

func TestAndroidKey_AppAllowlist(t *testing.T) {
	otherDigest := make([]byte, 32)
	t.Run("digest not allowed", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.Digests = [][]byte{otherDigest}
		h.noHome(h.chain(kd, leafOpts{}), "allowlist")
	})
	t.Run("one of two digests not allowed", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.Digests = [][]byte{testAppDigest[:], otherDigest}
		h.noHome(h.chain(kd, leafOpts{}), "allowlist")
	})
	t.Run("no app id", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.NoAppID = true
		h.noHome(h.chain(kd, leafOpts{}), "allowlist")
	})
	t.Run("no digests", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.Digests = nil
		h.noHome(h.chain(kd, leafOpts{}), "allowlist")
	})
	t.Run("package restriction", func(t *testing.T) {
		h := newAKHarness(t, func(c *config.AndroidKeyAttestationConfig) { c.AllowedPackages = []string{"org.other.app"} })
		h.noHome(h.chain(h.goodKD(), leafOpts{}), "allowlist")
		h2 := newAKHarness(t, func(c *config.AndroidKeyAttestationConfig) { c.AllowedPackages = []string{testAppPackage} })
		h2.ok(h2.chain(h2.goodKD(), leafOpts{}))
	})
	t.Run("app id in the hardware list is accepted", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.AppIDInTEE = true
		h.ok(h.chain(kd, leafOpts{}))
	})
	t.Run("digest notation", func(t *testing.T) {
		h := newAKHarness(t, func(c *config.AndroidKeyAttestationConfig) {
			d := strings.ToUpper(testAppDigestHex())
			var parts []string
			for i := 0; i < len(d); i += 2 {
				parts = append(parts, d[i:i+2])
			}
			c.AllowedAppDigests = []string{strings.Join(parts, ":")}
		})
		h.ok(h.chain(h.goodKD(), leafOpts{}))
	})
}

func TestAndroidKey_ExpiredAndNotYetValidCertificatesAreInvalid(t *testing.T) {
	h := newAKHarness(t, nil)
	h.invalid(h.chain(h.goodKD(), leafOpts{NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour)}), "chain")
	h.invalid(h.chain(h.goodKD(), leafOpts{NotBefore: time.Now().Add(time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}), "chain")
	// Validity is judged at the submission time given to the verifier.
	chain := h.chain(h.goodKD(), leafOpts{})
	payload, _ := json.Marshal(map[string]any{"type": "android_key", "x5c": b64chain(chain)})
	res, err := h.v.Verify(context.Background(), &InstanceKeyEvidenceInput{
		Payload: payload, PoPKey: &h.pop.PublicKey, WIAChallenge: h.challenge, Now: time.Now().Add(72 * time.Hour),
	})
	h.wantInvalid(res, err, "chain")
}

func TestAndroidKey_BrokenChainLinksAreInvalid(t *testing.T) {
	h := newAKHarness(t, nil)
	t.Run("tampered leaf", func(t *testing.T) {
		chain := h.chain(h.goodKD(), leafOpts{})
		leaf := append([]byte(nil), chain[0]...)
		leaf[len(leaf)/2] ^= 0xff
		chain[0] = leaf
		res, err := h.verify(chain)
		if !errors.Is(err, ErrWIAKeyAttestationInvalid) {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})
	t.Run("leaf signed by a key that is not the intermediate", func(t *testing.T) {
		rogue := genKey(t)
		rogueParent := *h.fx.inter // same name as the intermediate, a different key
		rogueParent.PublicKey = &rogue.PublicKey
		chain := h.fx.leaf(&h.pop.PublicKey, encodeKeyDescription(h.goodKD()), leafOpts{Parent: &rogueParent, ParentKey: rogue})
		h.invalid(chain, "signature")
	})
	t.Run("swapped order", func(t *testing.T) {
		chain := h.chain(h.goodKD(), leafOpts{})
		chain[1], chain[2] = chain[2], chain[1]
		h.invalid(chain, "not issued by")
	})
}

// A key that holds a genuine leaf cannot extend the chain: only CA
// certificates may sign certificates. Without this check an app could
// attest ANY key by signing a forged KeyDescription with its own attested key.
func TestAndroidKey_LeafCannotIssueFurtherCertificates(t *testing.T) {
	h := newAKHarness(t, nil)
	appKey := genKey(t)
	// A genuine leaf for appKey (the app's own hardware key).
	genuine := h.fx.leaf(&appKey.PublicKey, encodeKeyDescription(h.goodKD()), leafOpts{})
	genuineCert, err := x509.ParseCertificate(genuine[0])
	if err != nil {
		t.Fatal(err)
	}
	// The app now forges a "leaf" for the PoP key, signed with appKey.
	forged := h.fx.leaf(&h.pop.PublicKey, encodeKeyDescription(h.goodKD()), leafOpts{Parent: genuineCert, ParentKey: appKey})
	chain := [][]byte{forged[0], genuine[0], genuine[1], genuine[2]}
	h.invalid(chain, "not a CA")
}

func TestAndroidKey_RevocationFailsClosed(t *testing.T) {
	t.Run("revoked leaf", func(t *testing.T) {
		h := newAKHarness(t, nil)
		h.fetch.body = `{"entries":{"` + big.NewInt(4242).Text(16) + `":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`
		h.invalid(h.chain(h.goodKD(), leafOpts{Serial: 4242}), "revoked")
	})
	t.Run("revoked intermediate", func(t *testing.T) {
		h := newAKHarness(t, nil)
		h.fetch.body = `{"entries":{"2":{"status":"SUSPENDED"}}}`
		h.invalid(h.chain(h.goodKD(), leafOpts{}), "revoked")
	})
	t.Run("list keyed with leading zeros and upper case", func(t *testing.T) {
		h := newAKHarness(t, nil)
		h.fetch.body = `{"entries":{"000F4A":{"status":"REVOKED"}}}`
		h.invalid(h.chain(h.goodKD(), leafOpts{Serial: 0xf4a}), "revoked")
	})
	t.Run("other serials are fine", func(t *testing.T) {
		h := newAKHarness(t, nil)
		h.fetch.body = `{"entries":{"abc123":{"status":"REVOKED"}}}`
		h.ok(h.chain(h.goodKD(), leafOpts{}))
	})
	for name, f := range map[string]*fakeStatusFetcher{
		"fetch error":        {err: errors.New("network down")},
		"not json":           {body: "<html>"},
		"no entries object":  {body: `{"keys":[]}`},
		"entries wrong type": {body: `{"entries":[1]}`},
	} {
		t.Run("unavailable: "+name, func(t *testing.T) {
			h := newAKHarness(t, nil)
			h.v.status.fetcher = f
			_, err := h.verify(h.chain(h.goodKD(), leafOpts{}))
			if !errors.Is(err, ErrWIAKeyAttestationUnavailable) || errors.Is(err, ErrWIAKeyAttestationInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("revocation is not consulted for evidence that names no home", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.AttLevel, kd.KmLevel = -1, -1
		h.noHome(h.chain(kd, leafOpts{}), "not hardware")
		if h.fetch.calls != 0 {
			t.Fatal("fetched a revocation list for software evidence")
		}
	})
}

func TestAndroidStatusList_CacheHonoursCacheControlAndNeverServesStale(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	serial := []*big.Int{big.NewInt(77)}

	t.Run("max-age is honoured", func(t *testing.T) {
		f := &fakeStatusFetcher{body: emptyStatusList, maxAge: 10 * time.Minute}
		l := newAndroidStatusList(f, time.Hour)
		l.now = clock
		for i := 0; i < 3; i++ {
			if _, _, err := l.check(context.Background(), serial); err != nil {
				t.Fatal(err)
			}
		}
		if f.calls != 1 {
			t.Fatalf("fetched %d times within max-age", f.calls)
		}
		now = now.Add(11 * time.Minute)
		if _, _, err := l.check(context.Background(), serial); err != nil || f.calls != 2 {
			t.Fatalf("after expiry: err=%v calls=%d", err, f.calls)
		}
	})
	t.Run("expired and unfetchable fails closed", func(t *testing.T) {
		now = time.Now()
		f := &fakeStatusFetcher{body: emptyStatusList, maxAge: time.Minute}
		l := newAndroidStatusList(f, time.Hour)
		l.now = clock
		if _, _, err := l.check(context.Background(), serial); err != nil {
			t.Fatal(err)
		}
		f.err = errors.New("down")
		now = now.Add(2 * time.Minute)
		if _, _, err := l.check(context.Background(), serial); !errors.Is(err, ErrAndroidStatusUnavailable) {
			t.Fatalf("served a stale list: %v", err)
		}
		// and recovers once the source does
		f.err = nil
		if _, _, err := l.check(context.Background(), serial); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no header uses the default ttl", func(t *testing.T) {
		now = time.Now()
		f := &fakeStatusFetcher{body: emptyStatusList, maxAge: -1}
		l := newAndroidStatusList(f, 5*time.Minute)
		l.now = clock
		_, _, _ = l.check(context.Background(), serial)
		now = now.Add(4 * time.Minute)
		_, _, _ = l.check(context.Background(), serial)
		if f.calls != 1 {
			t.Fatalf("calls = %d", f.calls)
		}
		now = now.Add(2 * time.Minute)
		_, _, _ = l.check(context.Background(), serial)
		if f.calls != 2 {
			t.Fatalf("calls = %d", f.calls)
		}
	})
	t.Run("no-cache refetches every time", func(t *testing.T) {
		f := &fakeStatusFetcher{body: emptyStatusList, maxAge: 0}
		l := newAndroidStatusList(f, time.Hour)
		l.now = clock
		for i := 0; i < 3; i++ {
			_, _, _ = l.check(context.Background(), serial)
		}
		if f.calls != 3 {
			t.Fatalf("calls = %d", f.calls)
		}
	})
	t.Run("a refreshed list that now revokes is applied", func(t *testing.T) {
		now = time.Now()
		f := &fakeStatusFetcher{body: emptyStatusList, maxAge: time.Minute}
		l := newAndroidStatusList(f, time.Hour)
		l.now = clock
		_, _, _ = l.check(context.Background(), serial)
		f.body = `{"entries":{"4d":{"status":"REVOKED"}}}` // 77 = 0x4d
		now = now.Add(2 * time.Minute)
		if _, revoked, err := l.check(context.Background(), serial); err != nil || !revoked {
			t.Fatalf("revoked=%v err=%v", revoked, err)
		}
	})
}

func TestCacheControlMaxAge(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"":                          -1,
		"public, max-age=300":       300 * time.Second,
		"max-age=0":                 0,
		"no-cache":                  0,
		"no-store, max-age=100":     0,
		"max-age=abc":               -1,
		"max-age=-5":                -1,
		"MAX-AGE=60":                60 * time.Second,
		"max-age=99999999":          maxAndroidStatusTTL,
		"s-maxage=60":               -1,
		`max-age="120"`:             120 * time.Second,
		"public,max-age=30,private": 30 * time.Second,
	} {
		if got := cacheControlMaxAge(in); got != want {
			t.Errorf("cacheControlMaxAge(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAndroidKey_MalformedInputIsInvalid(t *testing.T) {
	h := newAKHarness(t, nil)
	good := h.chain(h.goodKD(), leafOpts{})
	b64 := b64chain(good)

	t.Run("payload", func(t *testing.T) {
		for _, p := range []string{`{}`, `{"x5c":null}`, `{"x5c":"abc"}`, `{"x5c":[1]}`, `[]`, `null`} {
			res, err := h.verifyPayload([]byte(p))
			h.wantInvalid(res, err, "")
		}
	})
	t.Run("chain shape", func(t *testing.T) {
		for name, x5c := range map[string][]string{
			"empty":         {},
			"single cert":   b64[:1],
			"not base64":    {"!!!", b64[1]},
			"not DER":       {"AAAA", b64[1]},
			"empty member":  {"", b64[1]},
			"truncated":     {b64[0][:len(b64[0])/2], b64[1], b64[2]},
			"too many":      {b64[0], b64[1], b64[1], b64[1], b64[1], b64[1], b64[1], b64[1], b64[2]},
			"oversized one": {strings.Repeat("A", maxAndroidX5CB64Length+4), b64[1]},
		} {
			res, err := h.verifyX5C(x5c)
			if !errors.Is(err, ErrWIAKeyAttestationInvalid) {
				t.Errorf("%s: res=%+v err=%v", name, res, err)
			}
		}
	})
	t.Run("too many certificates", func(t *testing.T) {
		x5c := []string{b64[0]}
		for i := 0; i < maxAndroidChainCerts; i++ {
			x5c = append(x5c, b64[1])
		}
		res, err := h.verifyX5C(x5c)
		h.wantInvalid(res, err, "at most")
	})
	t.Run("oversized chain overall", func(t *testing.T) {
		// Each certificate is under the per-certificate bound; together they
		// are over the chain bound.
		bigKD := h.goodKD()
		bigKD.ExtraSoftware = [][]byte{explicit(9999, octets(make([]byte, 7000)))}
		leaf := h.chain(bigKD, leafOpts{})[0]
		if len(leaf) >= maxAndroidCertBytes || len(leaf)*5 <= maxAndroidChainBytes {
			t.Fatalf("fixture sizes are off: %d", len(leaf))
		}
		l := b64chain([][]byte{leaf})[0]
		res, err := h.verifyX5C([]string{l, l, l, l, l})
		h.wantInvalid(res, err, "size out of bounds")
	})
}

func TestAndroidKey_MalformedExtensionsAreInvalid(t *testing.T) {
	h := newAKHarness(t, nil)
	valid := encodeKeyDescription(h.goodKD())
	cases := map[string][]byte{
		"empty":                       {},
		"garbage":                     []byte("not asn1 at all"),
		"truncated":                   valid[:len(valid)/2],
		"trailing bytes":              append(append([]byte(nil), valid...), 0x00),
		"not a sequence":              octets(valid),
		"too few members":             seq(integer(4), enum(1)),
		"wrong member":                seq(octets(nil), enum(1), integer(4), enum(1), octets(nil), octets(nil), seq(), seq()),
		"challenge not oct":           seq(integer(4), enum(1), integer(4), enum(1), integer(1), octets(nil), seq(), seq()),
		"oversized":                   append(append([]byte(nil), valid...), make([]byte, maxKeyDescriptionBytes)...),
		"indefinite length":           {0x30, 0x80, 0x00, 0x00},
		"duplicate origin":            encodeKeyDescription(func() kdParams { k := h.goodKD(); k.DuplicateOrigin = true; return k }()),
		"auth list member not tagged": seq(integer(4), enum(1), integer(4), enum(1), octets(nil), octets(nil), seq(integer(1)), seq()),
		"origin wrong type":           seq(integer(4), enum(1), integer(4), enum(1), octets(nil), octets(nil), seq(), seq(explicit(akTagOrigin, octets([]byte("x"))))),
		"origin huge":                 seq(integer(4), enum(1), integer(4), enum(1), octets(nil), octets(nil), seq(), seq(explicit(akTagOrigin, mustMarshal(new(big.Int).Lsh(big.NewInt(1), 200))))),
		"root of trust short":         seq(integer(4), enum(1), integer(4), enum(1), octets(nil), octets(nil), seq(), seq(explicit(akTagRootOfTrust, seq(octets(nil))))),
		"app id not DER":              seq(integer(4), enum(1), integer(4), enum(1), octets(nil), octets(nil), seq(explicit(akTagAppID, octets([]byte{1, 2, 3}))), seq()),
	}
	for name, ext := range cases {
		t.Run(name, func(t *testing.T) {
			chain := h.fx.leaf(&h.pop.PublicKey, nil, leafOpts{Extension: ext})
			if len(ext) == 0 {
				// An empty value cannot be installed as an extension; patch is
				// covered by the parser test below.
				_, err := parseAndroidKeyDescription(ext)
				if err == nil {
					t.Fatal("empty extension parsed")
				}
				return
			}
			res, err := h.verify(chain)
			h.wantInvalid(res, err, "")
			if _, perr := parseAndroidKeyDescription(ext); perr == nil {
				t.Fatalf("parser accepted %s", name)
			}
		})
	}
}

func TestAndroidKey_MissingAndDuplicateExtensionAreInvalid(t *testing.T) {
	h := newAKHarness(t, nil)
	h.invalid(h.fx.leaf(&h.pop.PublicKey, nil, leafOpts{NoExtension: true}), "no key attestation extension")

	// Two attestation extensions in one certificate: Go refuses to parse the
	// certificate, which is the same outcome (the verifier must not pick one).
	kd := encodeKeyDescription(h.goodKD())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	tmpl.ExtraExtensions = nil
	chain := h.fx.leaf(&h.pop.PublicKey, kd, leafOpts{})
	dup := duplicateExtension(t, chain[0], kd)
	chain[0] = dup
	res, err := h.verify(chain)
	h.wantInvalid(res, err, "")
}

// The attestation extension on a non-leaf certificate is ignored: only the
// leaf's counts.
func TestAndroidKey_ExtensionOnlyReadFromLeaf(t *testing.T) {
	h := newAKHarness(t, nil)
	kd := h.goodKD()
	kd.Challenge = InstanceKeyAttestationChallenge("wrong")
	// Leaf has the wrong challenge; nothing else in the chain can rescue it.
	h.invalid(h.chain(kd, leafOpts{}), "challenge")
}

func TestAndroidKey_ConfigErrorsAreErrors(t *testing.T) {
	good := newChainFixture(t)
	for name, cfg := range map[string]config.AndroidKeyAttestationConfig{
		"bad PEM":        {TrustAnchorsPEM: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
		"not a cert":     {TrustAnchorsPEM: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"},
		"trailing":       {TrustAnchorsPEM: good.rootPEM() + "junk"},
		"missing file":   {TrustAnchorsPath: "/nonexistent/anchors.pem"},
		"short digest":   {AllowedAppDigests: []string{"abcd"}},
		"non-hex digest": {AllowedAppDigests: []string{strings.Repeat("zz", 32)}},
	} {
		if _, err := NewAndroidKeyAttestationVerifier(cfg, zap.NewNop(), &fakeStatusFetcher{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if CheckAndroidKeyAttestationConfig(cfg) == nil {
			t.Errorf("%s: CheckAndroidKeyAttestationConfig accepted", name)
		}
	}
	if err := CheckAndroidKeyAttestationConfig(config.AndroidKeyAttestationConfig{}); err != nil {
		t.Fatalf("an empty configuration must load (it verifies nothing): %v", err)
	}
	// Anchors can come from a file.
	dir := t.TempDir()
	path := dir + "/roots.pem"
	if err := writeFile(path, good.rootPEM()); err != nil {
		t.Fatal(err)
	}
	v, err := NewAndroidKeyAttestationVerifier(config.AndroidKeyAttestationConfig{TrustAnchorsPath: path, AllowedAppDigests: []string{testAppDigestHex()}}, zap.NewNop(), &fakeStatusFetcher{})
	if err != nil || !v.configured() {
		t.Fatalf("file anchors: err=%v configured=%v", err, v != nil && v.configured())
	}
}
