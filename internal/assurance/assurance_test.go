package assurance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func writeRules(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustRuleSet(t *testing.T, content string) *RuleSet {
	t.Helper()
	rs, err := LoadRuleSet(writeRules(t, "p.rules", content))
	if err != nil {
		t.Fatalf("LoadRuleSet: %v", err)
	}
	return rs
}

func defaultCfg() config.AssuranceConfig {
	return config.AssuranceConfig{
		Enabled:                         true,
		RulesFile:                       "x.rules",
		KeyStorageScheme:                config.DefaultLevelSchemeID,
		UserAuthenticationScheme:        config.DefaultLevelSchemeID,
		LowerByClaimsKeyStorage:         true,
		LowerByClaimsUserAuthentication: true,
	}
}

func newAssessor(t *testing.T, cfg config.AssuranceConfig, rules string) *Assessor {
	t.Helper()
	rs := mustRuleSet(t, rules)
	a, err := NewAssessor(cfg, NewSpocpDecider(rs), rs.PolicyVersion)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// --- evidence -------------------------------------------------------------

func TestEvidence_FixedSlotOrderGolden(t *testing.T) {
	full := Evidence{
		Fido2:       &Fido2Verified{AAGUID: "a1", Cert: "c1"},
		Platform:    &PlatformVerified{Source: "platform_attested", AppID: "app"},
		HSM:         &HSMVerified{ID: "h1"},
		InstanceKey: &InstanceKeyVerified{Kind: "android_key", Home: "strongbox", Level: "strongbox", Boot: "verified", Binding: BindingAttested},
		Claimed:     Claimed{Plugin: "soft", KeyStorage: "iso_18045_high", UserAuthentication: "iso_18045_basic", Certification: "EUCC/high"},
	}
	want := "(evidence (verified (fido2 (mds3 trusted)(aaguid a1)(uv none)(cert c1))" +
		"(platform (source platform_attested)(app_id app))(hsm (id h1))" +
		"(instance_key (kind android_key)(home strongbox)(level strongbox)(boot verified)(binding attested)))" +
		"(claimed (plugin soft)(key_storage iso_18045_high)(user_authentication iso_18045_basic)(certification EUCC/high)))"
	if got := render(full.Element()); got != want {
		t.Fatalf("evidence shape changed (bump SchemaVersion if intended)\n got: %s\nwant: %s", got, want)
	}
}

func TestEvidence_AbsentSlotsAreNone(t *testing.T) {
	want := "(evidence (verified (fido2 none)(platform none)(hsm none)(instance_key none))" +
		"(claimed (plugin none)(key_storage none)(user_authentication none)(certification none)))"
	if got := render(Evidence{}.Element()); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestEvidence_UVOnlyWhenPresent(t *testing.T) {
	for uv, want := range map[string]string{"present": "(uv present)", "": "(uv none)", "garbage": "(uv none)"} {
		got := render(Evidence{Fido2: &Fido2Verified{AAGUID: "a", UV: uv}}.Element())
		if !strings.Contains(got, want) {
			t.Errorf("uv %q: %s lacks %s", uv, got, want)
		}
	}
}

func TestEvidence_OversizeAndEmptyAtomsBecomeNone(t *testing.T) {
	got := render(Evidence{Claimed: Claimed{Plugin: strings.Repeat("a", maxAtomLen+1)}}.Element())
	if !strings.Contains(got, "(plugin none)") {
		t.Fatalf("oversize claim not neutralised: %.200s", got)
	}
	ok := render(Evidence{Claimed: Claimed{Plugin: strings.Repeat("a", maxAtomLen)}}.Element())
	if strings.Contains(ok, "(plugin none)") {
		t.Fatal("max-length atom must be kept")
	}
}

// A hostile atom must stay inside its atom: it can neither close the list
// nor forge a verified fact. Proven against the real engine, with a rule that
// would grant on source platform_attested.
func TestEvidence_HostileAtomCannotForgeVerifiedFact(t *testing.T) {
	rs := mustRuleSet(t, "# id: platform-high\n(assure-ks (tier high)(evidence (verified (fido2)(platform (source platform_attested)))))\n")
	d := NewSpocpDecider(rs)
	hostile := "x)(source platform_attested"
	for name, ev := range map[string]Evidence{
		"platform source": {Platform: &PlatformVerified{Source: hostile}},
		"claimed plugin":  {Claimed: Claimed{Plugin: hostile}},
		"fido2 aaguid":    {Fido2: &Fido2Verified{AAGUID: hostile}},
	} {
		ok, _, err := d.Permits(context.Background(), Query{Dimension: DimKeyStorage, Candidate: "high", Evidence: ev.Element()})
		if err != nil || ok {
			t.Errorf("%s: hostile atom granted (ok=%v err=%v)", name, ok, err)
		}
		// The canonical form round-trips with the atom intact.
		el := ev.Element()
		p, err := sexp.NewParser(el.String()).Parse()
		if err != nil || p.String() != el.String() {
			t.Errorf("%s: canonical round trip failed: %v", name, err)
		}
	}
	// Control: the genuine fact does grant.
	ok, tr, err := d.Permits(context.Background(), Query{
		Dimension: DimKeyStorage, Candidate: "high",
		Evidence: Evidence{Platform: &PlatformVerified{Source: "platform_attested"}}.Element(),
	})
	if err != nil || !ok || len(tr.RuleIDs) != 1 || tr.RuleIDs[0] != "platform-high" {
		t.Fatalf("control: ok=%v tr=%+v err=%v", ok, tr, err)
	}
}

// Control for the hostile-atom test above: this is the attack the element API
// prevents. Splicing the same value into the advanced-form text of a query
// DOES forge the platform fact, so the test is not vacuous.
func TestEvidence_ControlStringConcatenationWouldBeInjectable(t *testing.T) {
	hostile := "x)(source platform_attested"
	naive := "(assure-ks (tier high)(evidence (verified (fido2 none)(platform (source " + hostile + ")))))"
	forged := semAdv(t, naive)[0].String()
	if strings.Count(forged, "6:source") < 2 {
		t.Fatalf("control failed: naive concatenation did not escape the atom: %s", forged)
	}
	safe := Evidence{Platform: &PlatformVerified{Source: hostile}}.Element().String()
	if strings.Count(safe, "6:source") != 1 || !strings.Contains(safe, "27:"+hostile) {
		t.Fatalf("element API must keep the hostile value inside one atom: %s", safe)
	}
}

func TestEvidence_ClaimedNeverSatisfiesVerified(t *testing.T) {
	rs := mustRuleSet(t, "# id: v\n(assure-ks (tier high)(evidence (verified (fido2 (mds3 trusted)(aaguid a1)))))\n")
	d := NewSpocpDecider(rs)
	// Client claims everything, backend verified nothing.
	ev := Evidence{Claimed: Claimed{Plugin: "a1", KeyStorage: "iso_18045_high", Certification: "a1"}}
	if ok, _, _ := d.Permits(context.Background(), Query{Dimension: DimKeyStorage, Candidate: "high", Evidence: ev.Element()}); ok {
		t.Fatal("claimed evidence satisfied a verified rule")
	}
}

func render(el sexp.Element) string {
	switch v := el.(type) {
	case *sexp.Atom:
		return v.Value
	case *sexp.List:
		var sb strings.Builder
		sb.WriteString("(" + v.Tag)
		for i, c := range v.Elements {
			if _, isAtom := c.(*sexp.Atom); isAtom || i == 0 {
				sb.WriteString(" ")
			}
			sb.WriteString(render(c))
		}
		sb.WriteString(")")
		return sb.String()
	}
	return el.String()
}

// --- rule loading and ids -------------------------------------------------

func TestLoadRuleSet_IDsPolicyHashAndTrace(t *testing.T) {
	content := "# header comment\n\n# id: first\n(assure-ks (tier moderate)(evidence (verified (fido2 (mds3 trusted)))))\n// other comment\n# id: second\n(assure-ks (tier moderate)(evidence (verified)))\n"
	rs := mustRuleSet(t, content)
	if len(rs.Rules) != 2 || rs.Rules[0].ID != "first" || rs.Rules[1].ID != "second" {
		t.Fatalf("rules: %+v", rs.Rules)
	}
	if len(rs.PolicyVersion) != 64 {
		t.Fatalf("policy version %q", rs.PolicyVersion)
	}
	other := mustRuleSet(t, content+"# trailing change\n")
	if other.PolicyVersion == rs.PolicyVersion {
		t.Fatal("policy hash must cover the file bytes")
	}

	d := NewSpocpDecider(rs)
	ok, tr, err := d.Permits(context.Background(), Query{
		Dimension: DimKeyStorage, Candidate: "moderate",
		Evidence: Evidence{Fido2: &Fido2Verified{AAGUID: "a"}}.Element(),
	})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if strings.Join(tr.RuleIDs, ",") != "first,second" || tr.PolicyVersion != rs.PolicyVersion {
		t.Fatalf("trace: %+v", tr)
	}
	// Only the broader rule matches without fido2.
	_, tr, _ = d.Permits(context.Background(), Query{Dimension: DimKeyStorage, Candidate: "moderate", Evidence: Evidence{}.Element()})
	if strings.Join(tr.RuleIDs, ",") != "second" {
		t.Fatalf("expected only the broad rule, got %+v", tr)
	}
	ok, tr, _ = d.Permits(context.Background(), Query{Dimension: DimKeyStorage, Candidate: "high", Evidence: Evidence{}.Element()})
	if ok || len(tr.RuleIDs) != 0 || tr.PolicyVersion != rs.PolicyVersion {
		t.Fatalf("expected deny trace, got ok=%v %+v", ok, tr)
	}
}

func TestLoadRuleSet_Errors(t *testing.T) {
	rule := "(assure-ks (tier moderate)(evidence))"
	cases := map[string]string{
		"missing id":           rule + "\n",
		"duplicate id":         "# id: a\n" + rule + "\n# id: a\n(assure-ks (tier high)(evidence))\n",
		"dangling id":          "# id: a\n" + rule + "\n# id: b\n",
		"two ids one rule":     "# id: a\n# id: b\n" + rule + "\n",
		"identical rules":      "# id: a\n" + rule + "\n# id: b\n" + rule + "\n",
		"id with space":        "# id: a b\n" + rule + "\n",
		"empty id":             "# id:\n" + rule + "\n",
		"unparsable rule":      "# id: a\n(assure-ks (tier\n",
		"missing close paren":  "# id: a\n(assure-ks (tier moderate)\n",
		"extra close paren":    "# id: a\n(assure-ks (tier moderate)))\n",
		"quoted atom":          "# id: a\n(assure-ks (tier \"moderate\")(evidence))\n",
		"bare atom":            "# id: a\nassure-ks\n",
		"two rules on a line":  "# id: a\n" + rule + rule + "\n",
		"second rule, no id":   "# id: a\n" + rule + "\n(assure-ks (tier high)(evidence))\n",
		"commented id is dead": "#  id: a\n" + rule + "\n",
	}
	for name, content := range cases {
		if _, err := LoadRuleSet(writeRules(t, "p.rules", content)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadRuleSet_EmptyFileIsValid(t *testing.T) {
	for _, content := range []string{"", "# only comments\n\n"} {
		rs, err := LoadRuleSet(writeRules(t, "p.rules", content))
		if err != nil || len(rs.Rules) != 0 {
			t.Fatalf("empty file: %v %+v", err, rs)
		}
	}
}

func TestLoadRuleSet_MissingFile(t *testing.T) {
	if _, err := LoadRuleSet(filepath.Join(t.TempDir(), "nope.rules")); err == nil {
		t.Fatal("missing file must error")
	}
}

func TestLoadRuleSet_RejectsBinaryExtensions(t *testing.T) {
	for _, name := range []string{"p.spocp", "p.bin", "P.SPOCP"} {
		p := writeRules(t, name, "# id: a\n(assure-ks (tier high)(evidence))\n")
		_, err := LoadRuleSet(p)
		if !errors.Is(err, ErrBadRulesFileName) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// --- assessor -------------------------------------------------------------

func fidoFacts(aaguid string) Facts {
	return Facts{Fido2: &Fido2Verified{AAGUID: aaguid}}
}

const ksRules = `# id: fido-moderate
(assure-ks (tier (* set basic enhanced-basic moderate))(evidence (verified (fido2 (mds3 trusted)(aaguid (* set a1 a2))))))
# id: fido-ua
(assure-ua (tier (* set basic enhanced-basic))(evidence (verified (fido2 (mds3 trusted)))))
# id: eucc-substantial
(assure-cert (name eucc-substantial)(evidence (verified (fido2 (mds3 trusted)(aaguid a1)))))
`

func certCfg() config.AssuranceConfig {
	cfg := defaultCfg()
	cfg.Certification = config.CertificationCatalogueConfig{Entries: config.CertificationEntryList{
		{Name: "eucc-high", Scheme: "EUCC", AssuranceLevel: "high"},
		{Name: "eucc-substantial", Scheme: "EUCC", AssuranceLevel: "substantial"},
	}}
	return cfg
}

func TestAssess_GrantsHighestPermittedAndRecordsRules(t *testing.T) {
	a := newAssessor(t, certCfg(), ksRules)
	o := a.Assess(context.Background(), fidoFacts("a1"))
	if o.KeyStorage.Value != "iso_18045_moderate" || o.KeyStorage.Level != "moderate" {
		t.Fatalf("ks = %+v", o.KeyStorage)
	}
	if o.UserAuthentication.Value != "iso_18045_enhanced-basic" {
		t.Fatalf("ua = %+v", o.UserAuthentication)
	}
	if strings.Join(o.KeyStorage.RuleIDs, ",") != "fido-moderate" {
		t.Fatalf("ks rules %v", o.KeyStorage.RuleIDs)
	}
	if got := strings.Join(o.RuleIDs(), ","); got != "fido-moderate,fido-ua,eucc-substantial" {
		t.Fatalf("all rules %q", got)
	}
	cert, _ := o.Certification.(map[string]interface{})
	if cert["scheme"] != "EUCC" || cert["assurance_level"] != "substantial" || cert["basis"] != nil {
		t.Fatalf("certification = %#v", o.Certification)
	}
	if o.SchemaVersion != SchemaVersion || o.PolicyVersion == "" {
		t.Fatalf("version info %+v", o)
	}
}

func TestAssess_UnknownAAGUIDGetsFloor(t *testing.T) {
	a := newAssessor(t, certCfg(), ksRules)
	o := a.Assess(context.Background(), fidoFacts("zzz"))
	if o.KeyStorage.Value != "iso_18045_basic" {
		t.Fatalf("ks = %+v", o.KeyStorage)
	}
	if o.Certification != "none" {
		t.Fatalf("certification = %#v", o.Certification)
	}
}

func TestAssess_EmptyRulesetReturnsFloorNeverErrors(t *testing.T) {
	a := newAssessor(t, certCfg(), "")
	o := a.Assess(context.Background(), fidoFacts("a1"))
	if o.KeyStorage.Value != "iso_18045_basic" || o.UserAuthentication.Value != "iso_18045_basic" || o.Certification != "none" || len(o.Errors) != 0 {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestAssess_CeilingCapsTheResult(t *testing.T) {
	cfg := defaultCfg()
	sc := config.BuiltinISO18045Scheme()
	sc.Ceiling = "enhanced-basic"
	cfg.LevelSchemes = config.LevelSchemeList{sc}
	a := newAssessor(t, cfg, "# id: all\n(assure-ks (tier (* set basic enhanced-basic moderate high))(evidence))\n")
	if got := a.Assess(context.Background(), Facts{}).KeyStorage.Level; got != "enhanced-basic" {
		t.Fatalf("level = %s", got)
	}
}

func TestAssess_FloorLevelReturnedEvenIfFloorIsNotLowest(t *testing.T) {
	cfg := defaultCfg()
	sc := config.BuiltinISO18045Scheme()
	sc.Floor = "enhanced-basic"
	cfg.LevelSchemes = config.LevelSchemeList{sc}
	a := newAssessor(t, cfg, "")
	o := a.Assess(context.Background(), Facts{Claims: Claims{KeyStorage: []string{"iso_18045_basic"}}})
	// Claiming below the floor can never lower the result below the floor.
	if o.KeyStorage.Level != "enhanced-basic" {
		t.Fatalf("level = %s", o.KeyStorage.Level)
	}
}

func TestAssess_LowerByClaims(t *testing.T) {
	rules := "# id: all\n(assure-ks (tier (* set basic enhanced-basic moderate high))(evidence))\n"
	cases := []struct {
		name  string
		lower bool
		claim []string
		want  string
	}{
		{"claim lower than grant lowers", true, []string{"iso_18045_moderate"}, "iso_18045_moderate"},
		{"claim higher than grant keeps grant", true, []string{"iso_18045_high"}, "iso_18045_high"},
		{"no claim, no lowering", true, nil, "iso_18045_high"},
		{"disabled: claim ignored", false, []string{"iso_18045_basic"}, "iso_18045_high"},
		{"unknown claim counts as floor", true, []string{"mystery"}, "iso_18045_basic"},
		{"highest of several claims", true, []string{"iso_18045_basic", "iso_18045_moderate"}, "iso_18045_moderate"},
	}
	for _, c := range cases {
		cfg := defaultCfg()
		cfg.LowerByClaimsKeyStorage = c.lower
		a := newAssessor(t, cfg, rules)
		o := a.Assess(context.Background(), Facts{Claims: Claims{KeyStorage: c.claim}})
		if o.KeyStorage.Value != c.want {
			t.Errorf("%s: got %s want %s", c.name, o.KeyStorage.Value, c.want)
		}
	}
}

func TestAssess_NormalizeClaimMapsLegacyVocabulary(t *testing.T) {
	cfg := defaultCfg()
	a := newAssessor(t, cfg, "# id: all\n(assure-ks (tier (* set basic enhanced-basic moderate high))(evidence))\n")
	a.NormalizeClaim = func(schemeID, raw string) string {
		if raw == "software" {
			return "iso_18045_basic"
		}
		return raw
	}
	if got := a.Assess(context.Background(), Facts{Claims: Claims{KeyStorage: []string{"software"}}}).KeyStorage.Value; got != "iso_18045_basic" {
		t.Fatalf("got %s", got)
	}
}

// The gdc rules key off a claimed plugin; verified evidence is not involved.
func TestAssess_GdcClaimedPluginRule(t *testing.T) {
	data, err := os.ReadFile("../../deploy/assurance/gdc-simulation.rules.example")
	if err != nil {
		t.Fatal(err)
	}
	rules := string(data)

	cfg := defaultCfg()
	cfg.LowerByClaimsKeyStorage, cfg.LowerByClaimsUserAuthentication = false, false
	a := newAssessor(t, cfg, rules)
	soft := a.Assess(context.Background(), Facts{Claims: Claims{Plugin: "soft"}})
	if soft.KeyStorage.Value != "iso_18045_high" || soft.UserAuthentication.Value != "iso_18045_high" {
		t.Fatalf("soft: %+v / %+v", soft.KeyStorage, soft.UserAuthentication)
	}
	if strings.Join(soft.KeyStorage.RuleIDs, ",") != "gdc-soft-ks-high" || strings.Join(soft.UserAuthentication.RuleIDs, ",") != "gdc-soft-ua-high" {
		t.Fatalf("rule ids: %v %v", soft.KeyStorage.RuleIDs, soft.UserAuthentication.RuleIDs)
	}
	if hsm := a.Assess(context.Background(), Facts{Claims: Claims{Plugin: "hsm"}}); hsm.KeyStorage.Value != "iso_18045_basic" {
		t.Fatalf("other plugin must stay at floor: %+v", hsm.KeyStorage)
	}

	// With lower_by_claims on, the grant only shows when the target is claimed.
	cfg.LowerByClaimsKeyStorage = true
	a = newAssessor(t, cfg, rules)
	if got := a.Assess(context.Background(), Facts{Claims: Claims{Plugin: "soft", KeyStorage: []string{"iso_18045_basic"}}}).KeyStorage.Value; got != "iso_18045_basic" {
		t.Fatalf("lowered: %s", got)
	}
	if got := a.Assess(context.Background(), Facts{Claims: Claims{Plugin: "soft", KeyStorage: []string{"iso_18045_high"}}}).KeyStorage.Value; got != "iso_18045_high" {
		t.Fatalf("target claimed: %s", got)
	}
}

func TestAssess_CustomSchemeEmitsConfiguredValuesAndBuckets(t *testing.T) {
	cfg := defaultCfg()
	cfg.LevelSchemes = config.LevelSchemeList{{
		ID: "tiers3", Levels: []string{"k3", "k2", "k1"}, Values: []string{"sw", "hw", "certified"}, Floor: "k3",
	}}
	cfg.KeyStorageScheme = "tiers3"
	a := newAssessor(t, cfg, "# id: r\n(assure-ks (tier (* set k3 k2 k1))(evidence (verified (fido2 (mds3 trusted)))))\n")
	o := a.Assess(context.Background(), fidoFacts("a"))
	if o.KeyStorage.Value != "certified" || o.KeyStorage.Scheme.StatusBucket(o.KeyStorage.LevelIndex) != BucketHigh {
		t.Fatalf("%+v", o.KeyStorage)
	}
	if o.UserAuthentication.Value != "iso_18045_basic" {
		t.Fatalf("ua should use its own scheme: %+v", o.UserAuthentication)
	}
	s, _ := a.Schemes()
	for idx, want := range map[int]Bucket{0: BucketLow, 1: BucketMiddle, 2: BucketHigh} {
		if got := s.StatusBucket(idx); got != want {
			t.Errorf("bucket(%d) = %v want %v", idx, got, want)
		}
	}
}

func TestAssess_CertificationCatalogueOrderURLAndBasis(t *testing.T) {
	cfg := certCfg()
	cfg.Certification.Entries[0].URL = "https://certs.example/eucc-high"
	rules := "# id: both\n(assure-cert (name (* set eucc-high eucc-substantial))(evidence))\n"
	a := newAssessor(t, cfg, rules)
	o := a.Assess(context.Background(), Facts{})
	if o.Certification != "https://certs.example/eucc-high" || o.CertificationName != "eucc-high" {
		t.Fatalf("first permitted entry should win, got %#v", o.Certification)
	}

	cfg.Certification.Entries[0].URL = ""
	cfg.CertificationBasisInClaim = true
	a = newAssessor(t, cfg, rules)
	o = a.Assess(context.Background(), Facts{})
	obj := o.Certification.(map[string]interface{})
	basis := obj["basis"].(map[string]interface{})
	if len(basis["policy"].(string)) != 8 || basis["rules"].([]string)[0] != "both" {
		t.Fatalf("basis = %#v", basis)
	}
}

func TestAssess_DerivedCertificationEntries(t *testing.T) {
	cfg := defaultCfg()
	cfg.Certification = config.CertificationCatalogueConfig{Scheme: "EUCC", Levels: []string{"high", "substantial"}}
	a := newAssessor(t, cfg, "# id: r\n(assure-cert (name substantial)(evidence))\n")
	o := a.Assess(context.Background(), Facts{})
	if o.CertificationName != "substantial" {
		t.Fatalf("%+v", o)
	}
}

type errDecider struct{}

func (errDecider) Permits(context.Context, Query) (bool, Trace, error) {
	return true, Trace{}, errors.New("pdp down")
}

func TestAssess_DeciderErrorFailsClosedToFloor(t *testing.T) {
	a, err := NewAssessor(certCfg(), errDecider{}, "v")
	if err != nil {
		t.Fatal(err)
	}
	o := a.Assess(context.Background(), Facts{})
	if o.KeyStorage.Level != "basic" || o.UserAuthentication.Level != "basic" || o.Certification != "none" || len(o.Errors) == 0 {
		t.Fatalf("%+v", o)
	}
}

// The probing loop only depends on the interface.
type recordingDecider struct{ asked []string }

func (r *recordingDecider) Permits(_ context.Context, q Query) (bool, Trace, error) {
	r.asked = append(r.asked, q.Dimension+":"+q.Candidate)
	return false, Trace{}, nil
}

func TestAssess_ProbesConfiguredLevelsHighToLowAndNeverTheFloor(t *testing.T) {
	cfg := defaultCfg()
	cfg.LevelSchemes = config.LevelSchemeList{{ID: "iso_18045", Levels: []string{"a", "b", "c"}, Values: []string{"va", "vb", "vc"}, Floor: "a"}}
	rec := &recordingDecider{}
	a, err := NewAssessor(cfg, rec, "v")
	if err != nil {
		t.Fatal(err)
	}
	a.Assess(context.Background(), Facts{})
	got := strings.Join(rec.asked, " ")
	if got != "assure-ks:c assure-ks:b assure-ua:c assure-ua:b" {
		t.Fatalf("probe order: %s", got)
	}
}

func TestNewFromConfig_StartupChecks(t *testing.T) {
	good := writeRules(t, "g.rules", "# id: a\n(assure-ks (tier moderate)(evidence))\n")
	cfg := defaultCfg()
	cfg.RulesFile = good
	if _, err := NewFromConfig(cfg, testLogger()); err != nil {
		t.Fatalf("good: %v", err)
	}
	if err := CheckConfig(cfg); err != nil {
		t.Fatalf("CheckConfig good: %v", err)
	}

	empty := writeRules(t, "e.rules", "")
	cfg.RulesFile = empty
	if _, err := NewFromConfig(cfg, testLogger()); err != nil {
		t.Fatalf("explicit empty file must be valid: %v", err)
	}

	cfg.RulesFile = filepath.Join(t.TempDir(), "missing.rules")
	if _, err := NewFromConfig(cfg, testLogger()); err == nil {
		t.Fatal("missing file must be a startup error")
	}
	cfg.RulesFile = ""
	if err := CheckConfig(cfg); err == nil {
		t.Fatal("no rules file must be a startup error")
	}

	dead := writeRules(t, "d.rules", "# id: dead\n(assure-ks (tier moderate)(evidence (claimed (plugin soft))(verified)))\n")
	cfg.RulesFile = dead
	err := CheckConfig(cfg)
	if !errors.Is(err, ErrLintFailed) || !strings.Contains(err.Error(), "dead") {
		t.Fatalf("lint error expected, got %v", err)
	}

	cfg.Enabled = false
	if err := CheckConfig(cfg); err != nil {
		t.Fatalf("disabled policy must never block startup: %v", err)
	}
}

func TestAssess_ExactEmittedValueBeatsNormalizer(t *testing.T) {
	cfg := defaultCfg()
	cfg.LevelSchemes = config.LevelSchemeList{{ID: "iso_18045", Levels: []string{"low", "top"}, Values: []string{"lowv", "certified"}, Floor: "low"}}
	a := newAssessor(t, cfg, "# id: all\n(assure-ks (tier top)(evidence))\n")
	a.NormalizeClaim = func(string, string) string { return "lowv" } // maps everything to the floor
	o := a.Assess(context.Background(), Facts{Claims: Claims{KeyStorage: []string{"certified"}}})
	if o.KeyStorage.Value != "certified" || o.KeyStorage.Lowered {
		t.Fatalf("exact match must win over normalisation: %+v", o.KeyStorage)
	}
	// Input that matches no configured value is still normalised.
	o = a.Assess(context.Background(), Facts{Claims: Claims{KeyStorage: []string{"software"}}})
	if o.KeyStorage.Value != "lowv" {
		t.Fatalf("unmatched input must be normalised: %+v", o.KeyStorage)
	}
}

// go-spocp's advanced-form parser slices into a lone "(" and panics; neither
// the loader nor the CLI/startup path may crash on such a file.
func TestLoadRuleSet_MalformedLinesAreErrorsNotPanics(t *testing.T) {
	for _, line := range []string{"(", ")", "()", "( )", "(((", "(a (b)"} {
		content := "# id: a\n" + line + "\n"
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%q: panicked: %v", line, r)
				}
			}()
			if _, err := LoadRuleSet(writeRules(t, "p.rules", content)); err == nil {
				t.Errorf("%q: expected an error", line)
			}
		}()
	}
}

// Defence in depth: even if a line got past checkRuleLine, a loader panic
// becomes an error.
func TestLoadAdvanced_RecoversFromLoaderPanic(t *testing.T) {
	if _, err := loadAdvanced(writeRules(t, "p.rules", "(\n")); err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("err = %v", err)
	}
}

// go-spocp drops a dangling range operator and builds an unbounded range that
// matches every atom; such rules (and the empty set, which never matches) are
// refused by the loader, wherever they appear in the rule.
func TestLoadRuleSet_RejectsRangesAndEmptySets(t *testing.T) {
	for name, rule := range map[string]string{
		"dangling range operator": "(assure-ks (tier basic)(evidence (verified (fido2 (mds3 trusted)(aaguid (* range alpha ge))))))",
		"range with no bounds":    "(assure-ks (tier basic)(evidence (verified (fido2 (mds3 trusted)(aaguid (* range alpha))))))",
		"complete range":          "(assure-ks (tier basic)(evidence (verified (fido2 (mds3 trusted)(aaguid (* range alpha ge a le z))))))",
		"range inside a set":      "(assure-ks (tier (* set basic (* range alpha ge a)))(evidence))",
		"empty set":               "(assure-ks (tier (* set))(evidence))",
	} {
		if _, err := LoadRuleSet(writeRules(t, "p.rules", "# id: r\n"+rule+"\n")); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// Control: the supported star forms still load.
	ok := "# id: r\n(assure-ks (tier (* set basic moderate))(evidence (verified (fido2 (mds3 trusted)(aaguid (* prefix 0000))(cert (* suffix x))))))\n"
	if _, err := LoadRuleSet(writeRules(t, "p.rules", ok)); err != nil {
		t.Fatalf("set/prefix/suffix must load: %v", err)
	}
}

func TestAssess_ClaimedLevelRecordedEvenWhenLoweringDisabled(t *testing.T) {
	for _, lower := range []bool{true, false} {
		cfg := defaultCfg()
		cfg.LowerByClaimsKeyStorage, cfg.LowerByClaimsUserAuthentication = lower, lower
		a := newAssessor(t, cfg, "# id: all\n(assure-ks (tier high)(evidence))\n# id: all-ua\n(assure-ua (tier high)(evidence))\n")
		o := a.Assess(context.Background(), Facts{Claims: Claims{KeyStorage: []string{"iso_18045_basic"}, UserAuthentication: []string{"iso_18045_moderate"}}})
		if o.KeyStorage.ClaimedLevel != "basic" || o.UserAuthentication.ClaimedLevel != "moderate" {
			t.Errorf("lower=%v: claimed levels %q %q", lower, o.KeyStorage.ClaimedLevel, o.UserAuthentication.ClaimedLevel)
		}
		if o.KeyStorage.Lowered != lower {
			t.Errorf("lower=%v: Lowered=%v", lower, o.KeyStorage.Lowered)
		}
		if none := a.Assess(context.Background(), Facts{}); none.KeyStorage.ClaimedLevel != "" {
			t.Errorf("no claim must leave ClaimedLevel empty, got %q", none.KeyStorage.ClaimedLevel)
		}
	}
}
