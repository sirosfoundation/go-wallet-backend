package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/domain"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

type fakeStatusFetcher struct {
	body   string
	maxAge time.Duration
	age    time.Duration
	err    error
	calls  int
	// gate, when set, blocks Fetch until it is closed (or the context ends).
	gate chan struct{}
	mu   sync.Mutex
}

func (f *fakeStatusFetcher) Fetch(ctx context.Context) ([]byte, StatusFreshness, error) {
	f.mu.Lock()
	f.calls++
	gate := f.gate
	f.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, StatusFreshness{}, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, StatusFreshness{}, f.err
	}
	return []byte(f.body), StatusFreshness{MaxAge: f.maxAge, Age: f.age}, nil
}

func (f *fakeStatusFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
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
		h.noHome(h.chain(kd, leafOpts{}), NoHomeSoftwareSecurityLevel)
	}
}

func TestAndroidKey_UnknownRootGivesNoHome(t *testing.T) {
	h := newAKHarness(t, nil)
	// A complete, internally valid chain under a root nobody pinned.
	other := newChainFixture(t)
	chain := other.leaf(&h.pop.PublicKey, encodeKeyDescription(h.goodKD()), leafOpts{})
	h.noHome(chain, NoHomeUntrustedRoot)
	// The root need not be sent: a chain that stops below a PINNED root still
	// verifies against the operator's copy of it.
	h.ok(h.chain(h.goodKD(), leafOpts{})[:2])
	// But a chain whose last certificate is not issued by any pinned anchor
	// does not, however complete it looks.
	h.noHome(other.leaf(&h.pop.PublicKey, encodeKeyDescription(h.goodKD()), leafOpts{})[:2], NoHomeUntrustedRoot)
}

func TestAndroidKey_NoAnchorsOrNoAppsVerifiesNothing(t *testing.T) {
	for name, mut := range map[string]func(*config.AndroidKeyAttestationConfig){
		"no anchors":  func(c *config.AndroidKeyAttestationConfig) { c.TrustAnchorsPEM = "" },
		"no app list": func(c *config.AndroidKeyAttestationConfig) { c.AllowedAppDigests = nil },
	} {
		t.Run(name, func(t *testing.T) {
			h := newAKHarness(t, mut)
			h.noHome(h.chain(h.goodKD(), leafOpts{}), NoHomeNotConfigured)
			// Not even a malformed payload is looked at: nothing is learned from it.
			res, err := h.verifyPayload([]byte(`not json`))
			if err != nil || res.Record != nil {
				t.Fatalf("res=%+v err=%v", res, err)
			}
			if h.fetch.callCount() != 0 {
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
		"origin imported":   {func(k *kdParams) { k.Origin = intp(2) }, NoHomeKeyNotGenerated},
		"origin derived":    {func(k *kdParams) { k.Origin = intp(1) }, NoHomeKeyNotGenerated},
		"origin missing":    {func(k *kdParams) { k.Origin = nil }, NoHomeKeyNotGenerated},
		"origin only in sw": {func(k *kdParams) { k.Origin = nil; k.ExtraSoftware = [][]byte{explicit(akTagOrigin, integer(0))} }, NoHomeKeyNotGenerated},
		"no sign purpose":   {func(k *kdParams) { k.Purposes = []int{3, 4} }, NoHomeNoSignPurpose},
		"no purposes":       {func(k *kdParams) { k.Purposes = nil }, NoHomeNoSignPurpose},
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
		h.noHome(h.chain(kd, leafOpts{}), NoHomeAppNotAllowed)
	})
	t.Run("one of two digests not allowed", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.Digests = [][]byte{testAppDigest[:], otherDigest}
		h.noHome(h.chain(kd, leafOpts{}), NoHomeAppNotAllowed)
	})
	t.Run("no app id", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.NoAppID = true
		h.noHome(h.chain(kd, leafOpts{}), NoHomeAppNotAllowed)
	})
	t.Run("no digests", func(t *testing.T) {
		h := newAKHarness(t, nil)
		kd := h.goodKD()
		kd.Digests = nil
		h.noHome(h.chain(kd, leafOpts{}), NoHomeAppNotAllowed)
	})
	t.Run("package restriction", func(t *testing.T) {
		h := newAKHarness(t, func(c *config.AndroidKeyAttestationConfig) { c.AllowedPackages = []string{"org.other.app"} })
		h.noHome(h.chain(h.goodKD(), leafOpts{}), NoHomeAppNotAllowed)
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
		h.noHome(h.chain(kd, leafOpts{}), NoHomeSoftwareSecurityLevel)
		if h.fetch.callCount() != 0 {
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
		if f.callCount() != 1 {
			t.Fatalf("fetched %d times within max-age", f.callCount())
		}
		now = now.Add(11 * time.Minute)
		if _, _, err := l.check(context.Background(), serial); err != nil || f.callCount() != 2 {
			t.Fatalf("after expiry: err=%v calls=%d", err, f.callCount())
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
		// and recovers once the source does (after the failure backoff)
		now = now.Add(androidStatusRetryBackoff + time.Second)
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
		if f.callCount() != 1 {
			t.Fatalf("calls = %d", f.callCount())
		}
		now = now.Add(2 * time.Minute)
		_, _, _ = l.check(context.Background(), serial)
		if f.callCount() != 2 {
			t.Fatalf("calls = %d", f.callCount())
		}
	})
	t.Run("no-cache refetches every time", func(t *testing.T) {
		f := &fakeStatusFetcher{body: emptyStatusList, maxAge: 0}
		l := newAndroidStatusList(f, time.Hour)
		l.now = clock
		for i := 0; i < 3; i++ {
			_, _, _ = l.check(context.Background(), serial)
		}
		if f.callCount() != 3 {
			t.Fatalf("calls = %d", f.callCount())
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

func TestAndroidStatusList_HTTPFreshnessAgeReducesLife(t *testing.T) {
	serial := []*big.Int{big.NewInt(77)}
	now := time.Now()
	clock := func() time.Time { return now }

	t.Run("max-age minus Age", func(t *testing.T) {
		f := &fakeStatusFetcher{body: emptyStatusList, maxAge: time.Hour, age: time.Hour - 10*time.Second}
		l := newAndroidStatusList(f, time.Hour)
		l.now = clock
		if _, _, err := l.check(context.Background(), serial); err != nil {
			t.Fatal(err)
		}
		now = now.Add(5 * time.Second)
		_, _, _ = l.check(context.Background(), serial)
		if f.callCount() != 1 {
			t.Fatalf("calls = %d within the remaining life", f.callCount())
		}
		now = now.Add(6 * time.Second) // 11 s after receipt: past the 10 s that were left
		_, _, _ = l.check(context.Background(), serial)
		if f.callCount() != 2 {
			t.Fatalf("calls = %d, the full max-age was restarted at receipt", f.callCount())
		}
	})
	t.Run("default ttl is reduced by Age too", func(t *testing.T) {
		now = time.Now()
		f := &fakeStatusFetcher{body: emptyStatusList, maxAge: -1, age: 4 * time.Minute}
		l := newAndroidStatusList(f, 5*time.Minute)
		l.now = clock
		_, _, _ = l.check(context.Background(), serial)
		now = now.Add(2 * time.Minute)
		_, _, _ = l.check(context.Background(), serial)
		if f.callCount() != 2 {
			t.Fatalf("calls = %d", f.callCount())
		}
	})
	t.Run("a response already past its max-age is refused", func(t *testing.T) {
		now = time.Now()
		f := &fakeStatusFetcher{body: `{"entries":{}}`, maxAge: time.Minute, age: 2 * time.Minute}
		l := newAndroidStatusList(f, time.Hour)
		l.now = clock
		_, _, err := l.check(context.Background(), serial)
		if !errors.Is(err, ErrAndroidStatusUnavailable) || !errors.Is(err, ErrAndroidStatusStale) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestInitialAge(t *testing.T) {
	recv := time.Now()
	h := http.Header{}
	h.Set("Age", "100")
	if got := initialAge(h, recv.Add(-2*time.Second), recv); got < 101*time.Second || got > 103*time.Second {
		t.Fatalf("Age header: %v", got)
	}
	h = http.Header{}
	h.Set("Date", recv.Add(-90*time.Second).UTC().Format(http.TimeFormat))
	if got := initialAge(h, recv, recv); got < 89*time.Second || got > 91*time.Second {
		t.Fatalf("Date header: %v", got)
	}
	h.Set("Age", "5") // the larger of the two wins
	if got := initialAge(h, recv, recv); got < 89*time.Second {
		t.Fatalf("max of Date and Age: %v", got)
	}
	// No Age and no Date: the time the request and download took still counts.
	if got := initialAge(http.Header{}, recv.Add(-10*time.Second), recv); got < 10*time.Second {
		t.Fatalf("response delay without Age: %v", got)
	}
	// A Date in the future (our clock is behind) is not a negative age.
	h = http.Header{}
	h.Set("Date", recv.Add(time.Hour).UTC().Format(http.TimeFormat))
	if got := initialAge(h, recv, recv); got != 0 {
		t.Fatalf("future Date: %v", got)
	}
	for _, bad := range []string{"-1", "abc", ""} {
		h = http.Header{}
		h.Set("Age", bad)
		if got := initialAge(h, recv, recv); got != 0 {
			t.Fatalf("Age %q: %v", bad, got)
		}
	}
}

// A list that takes time to download is older when it arrives: the body-read
// time counts against its freshness.
func TestHTTPStatusFetcher_SlowBodyCountsTowardsAge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=600")
		w.Header().Set("Age", "5")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond)
		_, _ = w.Write([]byte(emptyStatusList))
	}))
	defer srv.Close()
	_, fresh, err := NewHTTPAttestationStatusFetcher(srv.Client(), srv.URL).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Age < 5*time.Second+350*time.Millisecond {
		t.Fatalf("Age = %v, the body download time was not counted", fresh.Age)
	}
}

// Cache-Control and Age may span several header lines.
func TestHTTPStatusFetcher_RepeatedHeaderLines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "public")
		w.Header().Add("Cache-Control", "max-age=30")
		w.Header().Add("Age", "9")
		w.Header().Add("Age", "3")
		_, _ = w.Write([]byte(emptyStatusList))
	}))
	defer srv.Close()
	_, fresh, err := NewHTTPAttestationStatusFetcher(srv.Client(), srv.URL).Fetch(context.Background())
	if err != nil || fresh.MaxAge != 30*time.Second || fresh.Age < 9*time.Second {
		t.Fatalf("fresh=%+v err=%v", fresh, err)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Cache-Control", "max-age=30")
		w.Header().Add("Cache-Control", "no-store")
		_, _ = w.Write([]byte(emptyStatusList))
	}))
	defer srv2.Close()
	_, fresh, err = NewHTTPAttestationStatusFetcher(srv2.Client(), srv2.URL).Fetch(context.Background())
	if err != nil || fresh.MaxAge != 0 {
		t.Fatalf("later no-store ignored: fresh=%+v err=%v", fresh, err)
	}
}

func TestHTTPStatusFetcher(t *testing.T) {
	var status int
	var hdr map[string]string
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	f := NewHTTPAttestationStatusFetcher(srv.Client(), srv.URL)

	status, hdr, body = 200, map[string]string{"Cache-Control": "public, max-age=600", "Age": "60"}, emptyStatusList
	got, fresh, err := f.Fetch(context.Background())
	if err != nil || string(got) != emptyStatusList || fresh.MaxAge != 600*time.Second || fresh.Age < 60*time.Second {
		t.Fatalf("got=%q fresh=%+v err=%v", got, fresh, err)
	}
	status = 503
	if _, _, err = f.Fetch(context.Background()); err == nil {
		t.Fatal("HTTP 503 accepted")
	}
	status, body = 200, strings.Repeat("x", maxAndroidStatusBytes+10)
	if _, _, err = f.Fetch(context.Background()); err == nil {
		t.Fatal("oversized list accepted")
	}
}

// One refresh at a time; its outcome, a failure included, is shared by the
// callers waiting for it, and a failed refresh is remembered briefly so an
// outage does not cost every caller a timeout.
func TestAndroidStatusList_SharedRefreshAndFailureBackoff(t *testing.T) {
	serial := []*big.Int{big.NewInt(1)}
	now := time.Now()
	var clockMu sync.Mutex
	clock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	advance := func(d time.Duration) { clockMu.Lock(); now = now.Add(d); clockMu.Unlock() }

	f := &fakeStatusFetcher{err: errors.New("down"), gate: make(chan struct{})}
	l := newAndroidStatusList(f, time.Hour)
	l.now = clock

	const callers = 20
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			_, _, err := l.check(context.Background(), serial)
			errs <- err
		}()
	}
	// All callers are waiting on one refresh; let it fail.
	for f.callCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(f.gate)
	for i := 0; i < callers; i++ {
		if err := <-errs; !errors.Is(err, ErrAndroidStatusUnavailable) {
			t.Fatalf("err = %v", err)
		}
	}
	if f.callCount() != 1 {
		t.Fatalf("%d concurrent callers caused %d fetches", callers, f.callCount())
	}
	// Within the backoff: no new fetch, same failure.
	if _, _, err := l.check(context.Background(), serial); !errors.Is(err, ErrAndroidStatusUnavailable) || f.callCount() != 1 {
		t.Fatalf("err=%v calls=%d", err, f.callCount())
	}
	// After it: the source is tried again, and a recovery is picked up.
	advance(androidStatusRetryBackoff + time.Second)
	f.err, f.gate, f.maxAge, f.body = nil, nil, time.Hour, emptyStatusList
	if _, _, err := l.check(context.Background(), serial); err != nil || f.callCount() != 2 {
		t.Fatalf("err=%v calls=%d", err, f.callCount())
	}
}

func TestAndroidStatusList_WaitingHonoursTheCallersContext(t *testing.T) {
	f := &fakeStatusFetcher{body: emptyStatusList, maxAge: time.Hour, gate: make(chan struct{})}
	l := newAndroidStatusList(f, time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := l.check(ctx, []*big.Int{big.NewInt(1)})
	if !errors.Is(err, ErrAndroidStatusUnavailable) || time.Since(start) > 5*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
	// The refresh the first caller started is not tied to its context: a
	// second caller joins it and gets the list once the source answers.
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(f.gate)
	}()
	if _, _, err = l.check(context.Background(), []*big.Int{big.NewInt(1)}); err != nil {
		t.Fatalf("second caller: %v", err)
	}
	if f.callCount() != 1 {
		t.Fatalf("%d fetches", f.callCount())
	}
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

func TestAndroidKey_PartiallyReadAnchorsAreRefused(t *testing.T) {
	a, b := newChainFixture(t), newChainFixture(t)
	bad := "-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n"
	for name, pemData := range map[string]string{
		"malformed before valid":  bad + a.rootPEM(),
		"malformed between valid": a.rootPEM() + bad + b.rootPEM(),
		"malformed after valid":   a.rootPEM() + bad,
		"garbage before":          "junk\n" + a.rootPEM(),
		"undecodable DER":         "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" + a.rootPEM(),
	} {
		if _, err := NewAndroidKeyAttestationVerifier(config.AndroidKeyAttestationConfig{TrustAnchorsPEM: pemData}, zap.NewNop(), &fakeStatusFetcher{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	v, err := NewAndroidKeyAttestationVerifier(config.AndroidKeyAttestationConfig{TrustAnchorsPEM: "\n" + a.rootPEM() + "\n\n" + b.rootPEM() + "\n"}, zap.NewNop(), &fakeStatusFetcher{})
	if err != nil || v.numAnchors != 2 {
		t.Fatalf("two clean anchors: err=%v n=%d", err, v.numAnchors)
	}
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
