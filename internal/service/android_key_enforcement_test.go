package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func rejectCfg(mut func(*config.AndroidKeyAttestationConfig)) func(*config.AndroidKeyAttestationConfig) {
	return func(c *config.AndroidKeyAttestationConfig) {
		c.Enforcement = config.AndroidEnforcementReject
		if mut != nil {
			mut(c)
		}
	}
}

// counterValue reads a counter of the default registry by metric name and
// labels (the testutil package needs modules this repo does not carry).
func counterValue(name string, labels map[string]string) float64 {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		panic(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := len(m.GetLabel()) == len(labels)
			for _, l := range m.GetLabel() {
				if labels[l.GetName()] != l.GetValue() {
					match = false
				}
			}
			if match {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func boolp(b bool) *bool { return &b }

// refusal asserts the outcome is a reject-mode refusal with exactly reason, that
// it is not the invalid error, and that the error text carries only the enum.
func (h *akHarness) refusal(chain [][]byte, reason string) {
	h.t.Helper()
	res, err := h.verify(chain)
	var nq *KeyAttestationNotQualifyingError
	if !errors.As(err, &nq) || !errors.Is(err, ErrWIAKeyAttestationNotQualifying) {
		h.t.Fatalf("want NotQualifying %q, got res=%+v err=%v", reason, res, err)
	}
	if errors.Is(err, ErrWIAKeyAttestationInvalid) || errors.Is(err, ErrWIAKeyAttestationUnavailable) {
		h.t.Fatalf("NotQualifying must be its own class: %v", err)
	}
	if nq.Reason != reason {
		h.t.Fatalf("reason = %q, want %q", nq.Reason, reason)
	}
	if res != nil {
		h.t.Fatalf("a refusal must not carry a result: %+v", res)
	}
}

// Every "no home" case is a refusal with its own reason in reject mode.
func TestAndroidKeyEnforcement_RejectModeRefusesEveryNoHomeCase(t *testing.T) {
	type tc struct {
		cfg    func(*config.AndroidKeyAttestationConfig)
		kd     func(*kdParams)
		other  bool // chain under a root nobody pinned
		reason string
	}
	cases := map[string]tc{
		"no anchors":       {cfg: rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.TrustAnchorsPEM = "" }), reason: NoHomeNotConfigured},
		"no digests":       {cfg: rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.AllowedAppDigests = nil }), reason: NoHomeNotConfigured},
		"unknown root":     {cfg: rejectCfg(nil), other: true, reason: NoHomeUntrustedRoot},
		"software":         {cfg: rejectCfg(nil), kd: func(k *kdParams) { k.AttLevel, k.KmLevel = -1, -1 }, reason: NoHomeSoftwareSecurityLevel},
		"imported key":     {cfg: rejectCfg(nil), kd: func(k *kdParams) { k.Origin = intp(2) }, reason: NoHomeKeyNotGenerated},
		"no sign":          {cfg: rejectCfg(nil), kd: func(k *kdParams) { k.Purposes = []int{3} }, reason: NoHomeNoSignPurpose},
		"app digest":       {cfg: rejectCfg(nil), kd: func(k *kdParams) { k.Digests = [][]byte{[]byte("0123456789abcdef0123456789abcdef")} }, reason: NoHomeAppNotAllowed},
		"app package":      {cfg: rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.AllowedPackages = []string{"org.other.app"} }), reason: NoHomeAppNotAllowed},
		"boot state":       {cfg: rejectCfg(nil), kd: func(k *kdParams) { k.BootState = 2 }, reason: NoHomeBootNotVerified},
		"self signed boot": {cfg: rejectCfg(nil), kd: func(k *kdParams) { k.BootState = 1 }, reason: NoHomeBootNotVerified},
		"no root of trust": {cfg: rejectCfg(nil), kd: func(k *kdParams) { k.NoRootOfTrust = true }, reason: NoHomeBootNotVerified},
		"unlocked":         {cfg: rejectCfg(nil), kd: func(k *kdParams) { k.Locked = false }, reason: NoHomeBootloaderUnlocked},
		"unlocked, boot check off, no root of trust": {
			cfg:    rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.RequireVerifiedBoot = boolp(false) }),
			kd:     func(k *kdParams) { k.NoRootOfTrust = true },
			reason: NoHomeBootloaderUnlocked,
		},
		"old patch": {
			cfg:    rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.MinPatchLevel = 202501 }),
			kd:     func(k *kdParams) { k.Patch = intp(202412) },
			reason: NoHomePatchLevelTooOld,
		},
		"old patch with day": {
			cfg:    rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.MinPatchLevel = 202501 }),
			kd:     func(k *kdParams) { k.Patch = intp(20241231) },
			reason: NoHomePatchLevelTooOld,
		},
		"no patch": {
			cfg:    rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.MinPatchLevel = 202501 }),
			kd:     func(k *kdParams) { k.Patch = nil },
			reason: NoHomePatchLevelMissing,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newAKHarness(t, c.cfg)
			kd := h.goodKD()
			if c.kd != nil {
				c.kd(&kd)
			}
			var chain [][]byte
			if c.other {
				chain = newChainFixture(t).leaf(&h.pop.PublicKey, encodeKeyDescription(kd), leafOpts{})
			} else {
				chain = h.chain(kd, leafOpts{})
			}
			h.refusal(chain, c.reason)
			// Nothing is learned from, or fetched for, evidence that does not qualify.
			if h.fetch.callCount() != 0 {
				t.Fatal("fetched a revocation list for evidence that does not qualify")
			}
		})
	}
	// Every reason of the enum is exercised above.
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.reason] = true
	}
	for _, r := range NoHomeReasons {
		if r == NoHomeAppAttestKeyNotEligible {
			continue // App Attest reason, covered in app_attest_assertion_test.go
		}
		if !seen[r] {
			t.Errorf("reason %q has no test case", r)
		}
	}
}

// The boot requirements are switchable one by one, and qualifying evidence passes.
func TestAndroidKeyEnforcement_BootRequirementsAreIndividuallySwitchable(t *testing.T) {
	h := newAKHarness(t, rejectCfg(nil))
	h.ok(h.chain(h.goodKD(), leafOpts{})) // verified boot, locked: qualifies

	bad := h.goodKD()
	bad.BootState, bad.Locked = 2, false
	h.refusal(h.chain(bad, leafOpts{}), NoHomeBootNotVerified)

	noBoot := newAKHarness(t, rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.RequireVerifiedBoot = boolp(false) }))
	bad = noBoot.goodKD()
	bad.BootState, bad.Locked = 2, false
	noBoot.refusal(noBoot.chain(bad, leafOpts{}), NoHomeBootloaderUnlocked)
	bad.Locked = true
	noBoot.ok(noBoot.chain(bad, leafOpts{}))

	noLock := newAKHarness(t, rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.RequireLockedBootloader = boolp(false) }))
	bad = noLock.goodKD()
	bad.Locked = false
	noLock.ok(noLock.chain(bad, leafOpts{}))
	bad.BootState = 3
	noLock.refusal(noLock.chain(bad, leafOpts{}), NoHomeBootNotVerified)

	off := newAKHarness(t, rejectCfg(func(c *config.AndroidKeyAttestationConfig) {
		c.RequireVerifiedBoot, c.RequireLockedBootloader = boolp(false), boolp(false)
	}))
	bad = off.goodKD()
	bad.BootState, bad.Locked, bad.NoRootOfTrust = 2, false, true
	off.ok(off.chain(bad, leafOpts{}))

	// MinPatchLevel: at the level and above passes; unset is no requirement.
	pl := newAKHarness(t, rejectCfg(func(c *config.AndroidKeyAttestationConfig) { c.MinPatchLevel = 202410 }))
	kd := pl.goodKD()
	kd.Patch = intp(20241005)
	pl.ok(pl.chain(kd, leafOpts{}))
	kd.Patch = intp(202410)
	pl.ok(pl.chain(kd, leafOpts{}))
}

// Evidence that is invalid stays invalid, and a revoked or unavailable status
// list stays what it was, in reject mode too.
func TestAndroidKeyEnforcement_RejectModeKeepsInvalidAndUnavailable(t *testing.T) {
	h := newAKHarness(t, rejectCfg(nil))
	kd := h.goodKD()
	kd.Challenge = InstanceKeyAttestationChallenge("another")
	h.invalid(h.chain(kd, leafOpts{}), "challenge")

	h.fetch.err = errors.New("down")
	if _, err := h.verify(h.chain(h.goodKD(), leafOpts{})); !errors.Is(err, ErrWIAKeyAttestationUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

// Ignore mode keeps today's behaviour: no error, no record, a reason and a metric.
func TestAndroidKeyEnforcement_IgnoreModeCountsByReason(t *testing.T) {
	for _, mode := range []string{"", config.AndroidEnforcementIgnore} {
		h := newAKHarness(t, func(c *config.AndroidKeyAttestationConfig) { c.Enforcement = mode })
		kd := h.goodKD()
		kd.AttLevel, kd.KmLevel = -1, -1
		h.noHome(h.chain(kd, leafOpts{}), NoHomeSoftwareSecurityLevel)
		// Boot requirements apply only in reject mode.
		kd = h.goodKD()
		kd.BootState, kd.Locked = 2, false
		h.ok(h.chain(kd, leafOpts{}))
	}

	// The envelope counts it, by reason and mode, and logs it.
	svc, _ := newTestWIAServiceWithInstances(t)
	f := &fakeKeyVerifier{typ: KeyAttestationAndroidKey, res: &InstanceKeyEvidenceResult{Reason: NoHomeUntrustedRoot}}
	svc.RegisterInstanceKeyVerifier(f)
	read := func() float64 {
		return counterValue("siros_wia_instance_key_not_qualifying_total", map[string]string{"reason": NoHomeUntrustedRoot, "enforcement": "ignore"})
	}
	before := read()
	if _, err := tryKeyAttestation(t, svc, &KeyAttestation{Type: KeyAttestationAndroidKey, Raw: []byte(`{"type":"android_key"}`)}); err != nil {
		t.Fatal(err)
	}
	if got := read() - before; got != 1 {
		t.Fatalf("counter moved by %v", got)
	}
	// Free text from a verifier cannot mint a label value.
	if noHomeReasonLabel("some client controlled text") != "other" {
		t.Fatal("unknown reason must collapse")
	}
}

// Through the WIA path: reject mode refuses with the reason, burns the
// challenge like an invalid submission, records nothing.
func TestWIAAndroidKey_RejectModeRefusesAndRecordsNothing(t *testing.T) {
	a := newAKWIAWith(t, "", rejectCfg(nil))
	a.svc.cfg.WalletProvider.Attestation.Assurance.Enabled = false
	soft := a.good(func(k *kdParams) { k.AttLevel, k.KmLevel = -1, -1 })
	jkt, req, _ := a.request(soft)
	read := func() float64 {
		return counterValue("siros_wia_instance_key_not_qualifying_total", map[string]string{"reason": NoHomeSoftwareSecurityLevel, "enforcement": "reject"})
	}
	before := read()
	err := a.generate(req)
	var nq *KeyAttestationNotQualifyingError
	if !errors.As(err, &nq) || nq.Reason != NoHomeSoftwareSecurityLevel {
		t.Fatalf("err = %v", err)
	}
	if read()-before != 1 {
		t.Fatal("not counted")
	}
	if _, err := a.keys.GetByKeyThumbprint(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("record stored: %v", err)
	}
	if _, err := a.inst.GetByID(context.Background(), jkt); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("instance created: %v", err)
	}
	// The challenge was consumed, as for KEY_ATTESTATION_INVALID.
	if err := a.generate(req); !errors.Is(err, ErrWIAChallengeExpired) {
		t.Fatalf("replay: %v", err)
	}
	// Qualifying evidence still works in reject mode.
	_, req, _ = a.request(a.good(nil))
	if err := a.generate(req); err != nil {
		t.Fatalf("qualifying evidence refused: %v", err)
	}
}

// Startup: reject mode with nothing to trust is refused; ignore keeps its warning.
func TestAndroidKeyEnforcement_StartupRefusal(t *testing.T) {
	fx := newChainFixture(t)
	good := config.AndroidKeyAttestationConfig{Enforcement: config.AndroidEnforcementReject, TrustAnchorsPEM: fx.rootPEM(), AllowedAppDigests: []string{testAppDigestHex()}}
	if err := CheckAndroidKeyAttestationConfig(good); err != nil {
		t.Fatalf("complete reject config refused: %v", err)
	}
	for name, mut := range map[string]func(*config.AndroidKeyAttestationConfig){
		"no anchors": func(c *config.AndroidKeyAttestationConfig) { c.TrustAnchorsPEM = "" },
		"no digests": func(c *config.AndroidKeyAttestationConfig) { c.AllowedAppDigests = nil },
		"nothing": func(c *config.AndroidKeyAttestationConfig) {
			*c = config.AndroidKeyAttestationConfig{Enforcement: "reject"}
		},
		"blank anchors": func(c *config.AndroidKeyAttestationConfig) { c.TrustAnchorsPEM = "  \n" },
	} {
		c := good
		mut(&c)
		if CheckAndroidKeyAttestationConfig(c) == nil {
			t.Errorf("%s: reject mode started", name)
		}
		c.Enforcement = config.AndroidEnforcementIgnore
		if err := CheckAndroidKeyAttestationConfig(c); err != nil {
			t.Errorf("%s: ignore mode must keep starting: %v", name, err)
		}
	}
	// The config-level validation agrees.
	c := good
	c.TrustAnchorsPEM = ""
	if c.Validate() == nil {
		t.Error("Validate accepted reject without anchors")
	}
}

// A reject deployment whose configuration cannot load must keep refusing, not
// quietly become an ignore deployment.
func TestAndroidKeyEnforcement_UnloadableConfigKeepsRejecting(t *testing.T) {
	cfg := &config.Config{}
	cfg.WalletProvider.Attestation.AndroidKeyAttestation = config.AndroidKeyAttestationConfig{
		Enforcement: config.AndroidEnforcementReject, TrustAnchorsPEM: "not pem -----BEGIN CERTIFICATE-----",
	}
	v := newAndroidKeyVerifierForServer(cfg, zap.NewNop())
	if !v.policy.reject {
		t.Fatal("fallback verifier lost the reject mode")
	}
	res, err := v.Verify(context.Background(), &InstanceKeyEvidenceInput{Payload: []byte(`{}`), Now: time.Now()})
	var nq *KeyAttestationNotQualifyingError
	if res != nil || !errors.As(err, &nq) || nq.Reason != NoHomeNotConfigured {
		t.Fatalf("res=%v err=%v", res, err)
	}
}
