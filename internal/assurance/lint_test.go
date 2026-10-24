package assurance

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func lintRules(t *testing.T, rules string) []Finding {
	t.Helper()
	cfg := defaultCfg()
	cfg.Certification = config.CertificationCatalogueConfig{Entries: config.CertificationEntryList{{Name: "eucc", Scheme: "EUCC", AssuranceLevel: "high"}}}
	return LintRuleSet(mustRuleSet(t, rules), &cfg)
}

func findings(fs []Finding, sev Severity) string {
	var out []string
	for _, f := range fs {
		if f.Severity == sev {
			out = append(out, f.String())
		}
	}
	return strings.Join(out, "\n")
}

func TestLint_CanonicalRulesAreClean(t *testing.T) {
	fs := lintRules(t, `# id: ok1
(assure-ks (tier (* set basic moderate))(evidence (verified (fido2 (mds3 trusted)(aaguid (* set a b))(uv present)(cert c))(platform (source platform_attested)(app_id x))(hsm (id h)))(claimed)))
# id: ok2
(assure-ua (tier basic)(evidence (verified (fido2 none)(platform none)(hsm none))))
# id: ok3
(assure-cert (name eucc)(evidence (verified)))
# id: ok4
(assure-ks (tier moderate))
`)
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %v", fs)
	}
}

func TestLint_SlotOrderIsAnError(t *testing.T) {
	cases := map[string]string{
		"claimed before verified":         "(assure-ks (tier basic)(evidence (claimed (plugin soft))(verified)))",
		"claimed only (verified skipped)": "(assure-ks (tier basic)(evidence (claimed (plugin soft))))",
		"platform before fido2":           "(assure-ks (tier basic)(evidence (verified (platform (source s))(fido2 (mds3 trusted)))))",
		"aaguid before mds3":              "(assure-ks (tier basic)(evidence (verified (fido2 (aaguid a)(mds3 trusted)))))",
		"aaguid without mds3":             "(assure-ks (tier basic)(evidence (verified (fido2 (aaguid a)))))",
		"evidence before tier":            "(assure-ks (evidence (verified))(tier basic))",
		"unknown slot":                    "(assure-ks (tier basic)(evidence (verified (tpm (id x)))))",
		"too many slots":                  "(assure-ks (tier basic)(evidence (verified)(claimed)(extra)))",
		"claimed plugin after claimed ks": "(assure-ks (tier basic)(evidence (verified)(claimed (key_storage x)(plugin soft))))",
		"claimed none":                    "(assure-ks (tier basic)(evidence (verified)(claimed none)))",
		"verified none":                   "(assure-ks (tier basic)(evidence (verified none)))",
		"evidence none":                   "(assure-ks (tier basic)(evidence none))",
		"cert uses tier":                  "(assure-cert (tier eucc)(evidence))",
	}
	for name, rule := range cases {
		fs := lintRules(t, "# id: r\n"+rule+"\n")
		if !strings.Contains(findings(fs, SeverityError), "rule r") {
			t.Errorf("%s: expected an ERROR naming the rule, got %v", name, fs)
		}
	}
}

func TestLint_UnknownDimensionAndNonListAreErrors(t *testing.T) {
	// Non-list rules are rejected by the loader's line check; build the rule
	// set directly to exercise the linter itself.
	for name, tc := range map[string]struct {
		el   sexp.Element
		want string
	}{
		"unknown dimension": {sexp.NewList("assure-bogus", sexp.NewList("tier", sexp.NewAtom("basic"))), "unknown dimension tag"},
		"not a list":        {sexp.NewAtom("assure-ks"), "not a list"},
	} {
		fs := LintRuleSet(&RuleSet{Rules: []Rule{{ID: "r", Element: tc.el, Line: 3}}}, nil)
		if !HasErrors(fs) || !strings.Contains(fs[0].Message, tc.want) || fs[0].RuleID != "r" {
			t.Errorf("%s: %v", name, fs)
		}
	}
}

func TestLint_ClaimedGroupWarnsNamingRuleIDs(t *testing.T) {
	fs := lintRules(t, `# id: uses-claims
(assure-ks (tier basic)(evidence (verified)(claimed (plugin soft))))
# id: no-claims
(assure-ks (tier moderate)(evidence (verified (fido2 (mds3 trusted)))))
# id: empty-claimed
(assure-ua (tier basic)(evidence (verified)(claimed)))
`)
	w := findings(fs, SeverityWarn)
	if !strings.Contains(w, "rule uses-claims") || strings.Contains(w, "no-claims") || strings.Contains(w, "empty-claimed") {
		t.Fatalf("warnings: %s", w)
	}
	if HasErrors(fs) {
		t.Fatalf("claims are a warning, not an error: %v", fs)
	}
}

func TestLint_TierAndCertificationOutsideConfig(t *testing.T) {
	fs := lintRules(t, `# id: bad-tier
(assure-ks (tier (* set basic ultra))(evidence))
# id: bad-cert
(assure-cert (name nope)(evidence))
# id: open
(assure-ks (tier (* prefix mod))(evidence))
`)
	w := findings(fs, SeverityWarn)
	for _, want := range []string{"rule bad-tier", `"ultra"`, "rule bad-cert", `"nope"`, "rule open", "wildcard"} {
		if !strings.Contains(w, want) {
			t.Errorf("missing %q in:\n%s", want, w)
		}
	}
}

func TestLint_NonRegisteredEmittedValueWarns(t *testing.T) {
	cfg := defaultCfg()
	cfg.LevelSchemes = config.LevelSchemeList{{ID: "k", Levels: []string{"k3", "k1"}, Values: []string{"iso_18045_basic", "https://example/k1"}, Floor: "k3"}}
	fs := LintConfig(cfg)
	if len(fs) != 1 || fs[0].Severity != SeverityWarn || !strings.Contains(fs[0].Message, "https://example/k1") {
		t.Fatalf("%v", fs)
	}
	if got := LintConfig(defaultCfg()); len(got) != 0 {
		t.Fatalf("built-in scheme must be clean: %v", got)
	}
}

func TestShippedExamplesLoadAndLint(t *testing.T) {
	cfg := defaultCfg()
	for file, wantWarn := range map[string][]string{
		"../../deploy/assurance/production.rules.example":     nil,
		"../../deploy/assurance/gdc-simulation.rules.example": {"gdc-soft-ks-high", "gdc-soft-ua-high"},
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		rs := mustRuleSet(t, string(data))
		fs := LintRuleSet(rs, &cfg)
		if HasErrors(fs) {
			t.Errorf("%s: %v", file, fs)
		}
		w := findings(fs, SeverityWarn)
		for _, id := range wantWarn {
			if !strings.Contains(w, id) {
				t.Errorf("%s: no warning naming %s", file, id)
			}
		}
		if wantWarn == nil && w != "" {
			t.Errorf("%s: unexpected warnings %s", file, w)
		}
	}
}

// A top-level star form loads (it is valid advanced form) but is not a list
// rule: the linter must refuse it rather than let a catch-all through.
func TestLint_TopLevelWildcardRuleIsAnError(t *testing.T) {
	fs := lintRules(t, "# id: catch-all\n(* )\n")
	if !HasErrors(fs) || !strings.Contains(findings(fs, SeverityError), "rule catch-all") {
		t.Fatalf("%v", fs)
	}
}

// Every leaf slot of the schema takes one atom or one (* set ...). Walk the
// schema so a new slot is covered automatically.
func TestLint_MultipleValuesInAnyLeafSlotAreErrors(t *testing.T) {
	type leaf struct {
		dim  string
		path []string
	}
	var leaves []leaf
	var walk func(dim string, path []string, sl slot)
	walk = func(dim string, path []string, sl slot) {
		p := append(append([]string{}, path...), sl.name)
		if len(sl.children) == 0 {
			leaves = append(leaves, leaf{dim, p})
			return
		}
		for _, c := range sl.children {
			walk(dim, p, c)
		}
	}
	for dim := range KnownDimensions {
		for _, sl := range topLayout(dim) {
			walk(dim, nil, sl)
		}
	}
	if len(leaves) < 14 {
		t.Fatalf("schema walk found only %d leaves", len(leaves))
	}
	// Build a rule that is canonical except for the one leaf under test.
	build := func(l leaf, vals string) string {
		var render func(sl slot, path []string) string
		render = func(sl slot, path []string) string {
			if len(sl.children) == 0 {
				if len(path) > 0 && path[0] == sl.name {
					return "(" + sl.name + " " + vals + ")"
				}
				return "(" + sl.name + " x)"
			}
			var sb strings.Builder
			for _, c := range sl.children {
				// Only descend along the chosen path; list earlier siblings
				// as bare slots so positions stay canonical.
				if len(path) > 1 && path[1] == c.name {
					sb.WriteString(render(c, path[1:]))
					break
				}
				sb.WriteString("(" + c.name + ")")
			}
			return "(" + sl.name + " " + sb.String() + ")"
		}
		var sb strings.Builder
		for _, top := range topLayout(l.dim) {
			if top.name == l.path[0] {
				sb.WriteString(render(top, l.path))
				break
			}
			sb.WriteString("(" + top.name + " x)")
		}
		return "(" + l.dim + " " + sb.String() + ")"
	}
	for _, l := range leaves {
		name := l.dim + "/" + strings.Join(l.path, "/")
		for _, ok := range []string{"a", "(* set a b)", ""} {
			if fs := lintRules(t, "# id: r\n"+build(l, ok)+"\n"); HasErrors(fs) {
				t.Errorf("%s: %q must lint clean, got %v", name, ok, fs)
			}
		}
		for _, bad := range []string{"a b", "a (* set b c)", "(* set a) (* set b)", "(nested a)"} {
			if fs := lintRules(t, "# id: r\n"+build(l, bad)+"\n"); !HasErrors(fs) {
				t.Errorf("%s: %q must be an ERROR (rule can never match)", name, bad)
			}
		}
	}
}

func TestStartupCheckFailsLikeTheCLIOnMultiValueLeaf(t *testing.T) {
	cfg := defaultCfg()
	cfg.RulesFile = writeRules(t, "m.rules", "# id: multi\n(assure-ks (tier moderate high)(evidence))\n")
	err := CheckConfig(cfg)
	if !errors.Is(err, ErrLintFailed) || !strings.Contains(err.Error(), "multi") {
		t.Fatalf("startup check: %v", err)
	}
	if _, err := NewFromConfig(cfg, testLogger()); !errors.Is(err, ErrLintFailed) {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if !HasErrors(LintRuleSet(mustRuleSet(t, "# id: multi\n(assure-ks (tier moderate high)(evidence))\n"), &cfg)) {
		t.Fatal("linter (CLI path) must report the same error")
	}
}
