package assurance

import (
	"context"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func wiaCfg() config.AssuranceConfig {
	c := defaultCfg()
	c.WIAProfileScheme = config.DefaultWIAProfileSchemeID
	c.WIACertification = config.WIACertificationCatalogueConfig{Entries: config.WIACertificationEntryList{
		{Name: "cert-s1", Information: map[string]interface{}{"scheme": "S1-cert"}},
		{Name: "cert-any", Information: map[string]interface{}{"scheme": "any"}},
	}}
	return c
}

func platformFacts(source string) Facts {
	return Facts{Platform: &PlatformVerified{Source: source}}
}

const wiaRules = `# id: issue-all
(assure-wia-issue (evidence))
# id: s1-platform
(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform (source platform_attested)))))
# id: cert-s1-rule
(assure-wia-cert (name cert-s1)(evidence (verified (fido2)(platform (source platform_attested)))))
# id: cert-any-rule
(assure-wia-cert (name cert-any)(evidence))
`

func TestAssessWIA_ProfileProbesHighestFirstAndFloors(t *testing.T) {
	a := newAssessor(t, wiaCfg(), wiaRules)
	ctx := context.Background()

	got := a.AssessWIA(ctx, platformFacts("platform_attested"))
	if got.Profile.Level != "s1-full-client" || got.Profile.Value != "platform_attested" {
		t.Fatalf("platform_attested: %+v", got.Profile)
	}
	if strings.Join(got.Profile.RuleIDs, ",") != "s1-platform" {
		t.Fatalf("rule ids %v", got.Profile.RuleIDs)
	}

	// development_attested and backend_attested are distinct atoms: neither
	// is granted S1, both fall to the floor.
	for _, src := range []string{"development_attested", "backend_attested"} {
		got = a.AssessWIA(ctx, platformFacts(src))
		if got.Profile.Level != "s3-backend-only" || got.Profile.Value != "backend_attested" {
			t.Fatalf("%s: %+v", src, got.Profile)
		}
	}
}

func TestAssessWIA_EmptyRulesetFloorsAndRefuses(t *testing.T) {
	a := newAssessor(t, wiaCfg(), "")
	got := a.AssessWIA(context.Background(), platformFacts("platform_attested"))
	if got.Profile.Level != "s3-backend-only" {
		t.Fatalf("empty ruleset must give the floor, got %+v", got.Profile)
	}
	if got.Issue {
		t.Fatal("with no assure-wia-issue rule the WIA must be refused")
	}
	if got.CertInfo != nil {
		t.Fatalf("no certification rule: %v", got.CertInfo)
	}
}

func TestAssessWIA_IssueFollowsEvidence(t *testing.T) {
	rules := `# id: issue-native-only
(assure-wia-issue (evidence (verified (fido2)(platform (source platform_attested)))))
`
	a := newAssessor(t, wiaCfg(), rules)
	ctx := context.Background()
	if got := a.AssessWIA(ctx, platformFacts("platform_attested")); !got.Issue || got.IssueRuleIDs[0] != "issue-native-only" {
		t.Fatalf("native must be issued: %+v", got)
	}
	if got := a.AssessWIA(ctx, platformFacts("backend_attested")); got.Issue {
		t.Fatal("backend-only must be refused by a native-only rule")
	}
	if got := a.AssessWIA(ctx, Facts{}); got.Issue {
		t.Fatal("no platform evidence must be refused")
	}
}

func TestAssessWIA_ClaimsNeverRaiseTheProfile(t *testing.T) {
	a := newAssessor(t, wiaCfg(), wiaRules)
	f := platformFacts("backend_attested")
	f.Claims = Claims{Plugin: "platform_attested", KeyStorage: []string{"iso_18045_high"}}
	if got := a.AssessWIA(context.Background(), f); got.Profile.Level != "s3-backend-only" {
		t.Fatalf("claims raised the S profile: %+v", got.Profile)
	}
}

func TestAssessWIA_CertificationInfoFirstPermittedWinsAndIsCopied(t *testing.T) {
	a := newAssessor(t, wiaCfg(), wiaRules)
	ctx := context.Background()

	got := a.AssessWIA(ctx, platformFacts("platform_attested"))
	if got.CertName != "cert-s1" || got.CertInfo["scheme"] != "S1-cert" {
		t.Fatalf("%+v", got)
	}
	got.CertInfo["scheme"] = "mutated"
	if again := a.AssessWIA(ctx, platformFacts("platform_attested")); again.CertInfo["scheme"] != "S1-cert" {
		t.Fatal("catalogue entry was aliased into the outcome")
	}

	got = a.AssessWIA(ctx, platformFacts("backend_attested"))
	if got.CertName != "cert-any" {
		t.Fatalf("second entry should apply to backend: %+v", got)
	}
}

func TestAssessWIA_CeilingCapsTheProfile(t *testing.T) {
	cfg := wiaCfg()
	cfg.WIAProfileSchemes = config.WIAProfileSchemeList{{
		ID: "three", Profiles: []string{"p3", "p2", "p1"}, Values: []string{"v3", "v2", "v1"}, Floor: "p3", Ceiling: "p2",
	}}
	cfg.WIAProfileScheme = "three"
	rules := `# id: all
(assure-wia (profile (* set p2 p1))(evidence))
`
	a := newAssessor(t, cfg, rules)
	got := a.AssessWIA(context.Background(), Facts{})
	if got.Profile.Level != "p2" || got.Profile.Value != "v2" {
		t.Fatalf("ceiling p2 must cap a p1 grant: %+v", got.Profile)
	}
}

func TestSimulate_RecordsNoMetricsAndMatchesAssess(t *testing.T) {
	a := newAssessor(t, wiaCfg(), wiaRules)
	ctx := context.Background()
	f := platformFacts("platform_attested")

	before := counterValue(t, "wia_issue", "issue")
	ka, wia := a.Simulate(ctx, f)
	if after := counterValue(t, "wia_issue", "issue"); after != before {
		t.Fatalf("Simulate recorded a decision metric (%v -> %v)", before, after)
	}
	realKA := a.Assess(ctx, f)
	realWIA := a.AssessWIA(ctx, f)
	if ka.KeyStorage.Value != realKA.KeyStorage.Value || wia.Profile.Value != realWIA.Profile.Value || wia.Issue != realWIA.Issue {
		t.Fatal("Simulate and the real assessment disagree on identical facts")
	}
	if after := counterValue(t, "wia_issue", "issue"); after != before+1 {
		t.Fatalf("AssessWIA must record exactly one wia_issue decision (%v -> %v)", before, after)
	}
}

func TestQuery_WIAIssueHasNoCandidate(t *testing.T) {
	q := Query{Dimension: DimWIAIssue, Candidate: "ignored", Evidence: Evidence{}.Element()}
	if got := render(q.Element()); strings.Contains(got, "ignored") || !strings.HasPrefix(got, "(assure-wia-issue (evidence ") {
		t.Fatalf("unexpected query %s", got)
	}
	if got := render(Query{Dimension: DimWIA, Candidate: "p", Evidence: Evidence{}.Element()}.Element()); !strings.HasPrefix(got, "(assure-wia (profile p)(evidence ") {
		t.Fatalf("unexpected query %s", got)
	}
}

func TestLint_WIADimensions(t *testing.T) {
	cfg := wiaCfg()
	rs := mustRuleSet(t, `# id: i
(assure-wia-issue (evidence))
# id: bad-profile
(assure-wia (profile s2-partial)(evidence))
# id: bad-cert
(assure-wia-cert (name nope)(evidence))
# id: bad-order
(assure-wia (profile s1-full-client)(evidence (claimed)(verified)))
# id: issue-with-candidate
(assure-wia-issue (tier basic)(evidence))
`)
	fs := LintRuleSet(rs, &cfg)
	w, e := findings(fs, SeverityWarn), findings(fs, SeverityError)
	for _, want := range []string{"bad-profile", "bad-cert"} {
		if !strings.Contains(w, want) {
			t.Errorf("no warning for %s: %s", want, w)
		}
	}
	for _, want := range []string{"bad-order", "issue-with-candidate"} {
		if !strings.Contains(e, want) {
			t.Errorf("no error for %s: %s", want, e)
		}
	}
}

func TestLint_NoWIAIssueRuleWarns(t *testing.T) {
	cfg := wiaCfg()
	fs := LintRuleSet(mustRuleSet(t, "# id: ks\n(assure-ks (tier moderate))\n"), &cfg)
	if !strings.Contains(findings(fs, SeverityWarn), "no assure-wia-issue rule") {
		t.Fatalf("%v", fs)
	}
	fs = LintRuleSet(mustRuleSet(t, "# id: i\n(assure-wia-issue (evidence))\n"), &cfg)
	if strings.Contains(findings(fs, SeverityWarn), "no assure-wia-issue rule") {
		t.Fatalf("%v", fs)
	}
}

func counterValue(t *testing.T, dimension, level string) float64 {
	t.Helper()
	var m dto.Metric
	if err := decisionsTotal.WithLabelValues(dimension, level).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// wscd_type is never evidence: nothing in the evidence can carry it and no
// rule can name it.
func TestEvidence_NeverContainsWSCDType(t *testing.T) {
	ev := Evidence{
		Fido2:    &Fido2Verified{AAGUID: "a", UV: UVPresent, Cert: "c"},
		Platform: &PlatformVerified{Source: "platform_attested", AppID: "app"},
		HSM:      &HSMVerified{ID: "h"},
		Claimed:  Claimed{Plugin: "native_ios", KeyStorage: "web_crypto"},
	}
	got := render(ev.Element())
	for _, bad := range []string{"wscd", "(type"} {
		if strings.Contains(got, bad) {
			t.Fatalf("evidence contains %q: %s", bad, got)
		}
	}
	cfg := wiaCfg()
	fs := LintRuleSet(mustRuleSet(t, "# id: w\n(assure-ks (tier moderate)(evidence (verified (fido2)(platform (source platform_attested))(hsm)(wscd (type native_ios)))))\n"), &cfg)
	if !strings.Contains(findings(fs, SeverityError), "rule w") {
		t.Fatalf("a rule naming a wscd slot must be a lint error: %v", fs)
	}
}

// The leaf-slot rule (one atom or one set per leaf) applies to the WIA
// dimensions, including their candidate group (profile / name).
func TestLint_LeafSlotRuleAppliesToWIADimensions(t *testing.T) {
	cases := map[string]bool{
		"(assure-wia (profile s1-full-client s3-backend-only)(evidence))":                 true,
		"(assure-wia (profile (* set s1-full-client s3-backend-only))(evidence))":         false,
		"(assure-wia-cert (name a b)(evidence))":                                          true,
		"(assure-wia-cert (name (* set a b))(evidence))":                                  false,
		"(assure-wia-issue (evidence (verified (fido2)(platform (source a b)))))":         true,
		"(assure-wia-issue (evidence (verified (fido2)(platform (source (* set a b))))))": false,
		"(assure-wia-issue (evidence (verified (fido2)(platform (app_id (x y))))))":       true,
	}
	for rule, wantErr := range cases {
		fs := lintRules(t, "# id: r\n"+rule+"\n")
		if HasErrors(fs) != wantErr {
			t.Errorf("%s: error=%v want %v (%v)", rule, HasErrors(fs), wantErr, fs)
		}
	}
}
