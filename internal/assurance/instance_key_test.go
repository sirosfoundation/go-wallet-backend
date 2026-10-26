package assurance

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSchemaVersionIsTwoWithInstanceKeySlot(t *testing.T) {
	if SchemaVersion != 2 {
		t.Fatalf("SchemaVersion = %d, want 2 (instance_key slot appended)", SchemaVersion)
	}
}

func TestEvidence_InstanceKeyBindingIsClosedVocabulary(t *testing.T) {
	for in, want := range map[string]string{
		BindingAttested: "(binding attested)", BindingAssertion: "(binding assertion)",
		"": "(binding none)", "garbage": "(binding none)",
	} {
		got := render(Evidence{InstanceKey: &InstanceKeyVerified{Kind: "k", Binding: in}}.Element())
		if !strings.Contains(got, want) {
			t.Errorf("binding %q: %s lacks %s", in, got, want)
		}
	}
}

// Rules written against schema version 1 (prefix of the slots, including the
// full v1 verified group ending in hsm) keep matching: the new slot is
// appended inside verified and queries may carry trailing elements. The
// claimed group is unaffected by the new slot.
func TestInstanceKey_OldRulesStillMatchByPrefix(t *testing.T) {
	rules := "# id: v1-full\n(assure-wia-issue (evidence (verified (fido2 none)(platform (source backend_attested)(app_id none))(hsm none))(claimed (plugin none))))\n" +
		"# id: v1-short\n(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform (source platform_attested)))))\n"
	a := newAssessor(t, wiaCfg(), rules)
	for name, ik := range map[string]*InstanceKeyVerified{
		"slot none":    nil,
		"slot present": {Kind: "android_key", Home: "tee", Binding: BindingAttested},
	} {
		out := simWIA(a, Facts{Platform: &PlatformVerified{Source: "backend_attested"}, InstanceKey: ik})
		if !out.Issue {
			t.Errorf("%s: v1 full-layout rule no longer matches", name)
		}
		out = simWIA(a, Facts{Platform: &PlatformVerified{Source: "platform_attested"}, InstanceKey: ik})
		if out.Profile.Level != "s1-full-client" {
			t.Errorf("%s: v1 prefix rule no longer matches (profile %q)", name, out.Profile.Level)
		}
	}
}

// The documented S1 template (shipped commented in production.rules.example).
const instanceKeyTemplate = "(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform (source platform_attested))(hsm)(instance_key (kind)(home (* set strongbox tee))))))"

func TestInstanceKey_S1TemplateRequiresHardwareHome(t *testing.T) {
	a := newAssessor(t, wiaCfg(), "# id: s1-instance-key\n"+instanceKeyTemplate+"\n")
	plat := &PlatformVerified{Source: "platform_attested"}
	cases := map[string]struct {
		ik   *InstanceKeyVerified
		want string
	}{
		"strongbox":         {&InstanceKeyVerified{Kind: "android_key", Home: "strongbox", Binding: BindingAttested}, "s1-full-client"},
		"tee":               {&InstanceKeyVerified{Kind: "android_key", Home: "tee", Binding: BindingAttested}, "s1-full-client"},
		"enclave asserted":  {&InstanceKeyVerified{Kind: "app_attest_assertion", Home: "secure_enclave_asserted", Binding: BindingAssertion}, "s3-backend-only"},
		"no instance key":   {nil, "s3-backend-only"},
		"home from nowhere": {&InstanceKeyVerified{Kind: "android_key"}, "s3-backend-only"},
	}
	for name, c := range cases {
		out := simWIA(a, Facts{Platform: plat, InstanceKey: c.ik})
		if out.Profile.Level != c.want {
			t.Errorf("%s: profile %q, want %q", name, out.Profile.Level, c.want)
		}
	}
}

// Nothing a client says can populate the verified instance_key slot: only
// Facts.InstanceKey does, and claims land in the claimed group.
func TestInstanceKey_ClaimedGroupCanNeverPopulateIt(t *testing.T) {
	a := newAssessor(t, wiaCfg(), "# id: s1-instance-key\n"+instanceKeyTemplate+"\n")
	hostile := "x)(instance_key (kind android_key)(home strongbox"
	for _, f := range []Facts{
		{Platform: &PlatformVerified{Source: "platform_attested"}, Claims: Claims{Plugin: "strongbox", KeyStorage: []string{"strongbox"}, UserAuthentication: []string{"tee"}, Certification: []string{"tee"}}},
		{Platform: &PlatformVerified{Source: "platform_attested"}, Claims: Claims{Plugin: hostile, Certification: []string{hostile}}},
	} {
		ev := render(a.Evidence(f).Element())
		if !strings.Contains(ev, "(instance_key none)") {
			t.Fatalf("claims populated instance_key: %s", ev)
		}
		if out := simWIA(a, f); out.Profile.Level != "s3-backend-only" {
			t.Fatalf("claims lifted the S profile to %q", out.Profile.Level)
		}
	}
}

func TestInstanceKey_ShippedTemplateIsInTheExampleAndLintsClean(t *testing.T) {
	data, err := os.ReadFile("../../deploy/assurance/production.rules.example")
	if err != nil {
		t.Fatal(err)
	}
	var tpl string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# (assure-wia (profile s1-full-client)") && strings.Contains(line, "(instance_key") && !strings.Contains(line, "app_attest_assertion") {
			tpl = strings.TrimPrefix(line, "# ")
		}
	}
	if tpl == "" {
		t.Fatal("production.rules.example has no commented instance_key S1 template")
	}
	if tpl != instanceKeyTemplate {
		t.Fatalf("template drifted from the tested one:\n got %s\nwant %s", tpl, instanceKeyTemplate)
	}
	cfg := defaultCfg()
	rs := mustRuleSet(t, "# id: s1-instance-key\n"+tpl+"\n")
	if fs := LintRuleSet(rs, &cfg); HasErrors(fs) {
		t.Fatalf("%v", fs)
	}
}

func TestLint_InstanceKeySlotOrderAndLeaves(t *testing.T) {
	ok := lintRules(t, "# id: a\n(assure-wia-issue (evidence (verified (fido2 none)(platform none)(hsm none)(instance_key none))))\n"+
		"# id: b\n(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key (kind android_key)(home (* set strongbox tee))(level)(boot verified)(binding attested)))))\n")
	if HasErrors(ok) {
		t.Fatalf("canonical rules flagged: %v", ok)
	}
	bad := map[string]string{
		"before hsm":       "(assure-wia-issue (evidence (verified (fido2)(platform)(instance_key (kind))(hsm))))",
		"home before kind": "(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key (home strongbox)(kind x)))))",
		"two home values":  "(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key (kind)(home strongbox tee)))))",
	}
	for name, r := range bad {
		if !HasErrors(lintRules(t, "# id: bad\n"+r+"\n")) {
			t.Errorf("%s: not an error", name)
		}
	}
}

func simWIA(a *Assessor, f Facts) *WIAOutcome {
	_, w := a.Simulate(context.Background(), f)
	return w
}

// The documented issuance gate (shipped commented in production.rules.example).
const instanceKeyIssueTemplate = "(assure-wia-issue (evidence (verified (fido2)(platform)(hsm)(instance_key (kind android_key)))))"

// The documented App Attest assertion S1 template (shipped commented in
// production.rules.example).
const appAttestAssertionTemplate = "(assure-wia (profile s1-full-client)(evidence (verified (fido2)(platform)(hsm)(instance_key (kind app_attest_assertion)(home)(level)(boot)(binding assertion)))))"

func TestInstanceKey_AppAttestAssertionTemplate(t *testing.T) {
	a := newAssessor(t, wiaCfg(), "# id: s1-app-attest\n"+appAttestAssertionTemplate+"\n")
	// A renewal WIA carries no native attestation object: its platform source is
	// backend_attested. The template must still select S1 for it.
	plat := &PlatformVerified{Source: "backend_attested"}
	cases := map[string]struct {
		ik   *InstanceKeyVerified
		want string
	}{
		"assertion":                  {&InstanceKeyVerified{Kind: "app_attest_assertion", Home: "secure_enclave_asserted", Binding: BindingAssertion}, "s1-full-client"},
		"attested binding is not it": {&InstanceKeyVerified{Kind: "app_attest_assertion", Home: "secure_enclave_asserted", Binding: BindingAttested}, "s3-backend-only"},
		"no binding":                 {&InstanceKeyVerified{Kind: "app_attest_assertion", Home: "secure_enclave_asserted"}, "s3-backend-only"},
		"android key is not it":      {&InstanceKeyVerified{Kind: "android_key", Home: "strongbox", Binding: BindingAttested}, "s3-backend-only"},
		"fido2 is not it":            {&InstanceKeyVerified{Kind: "fido2", Home: "fido2_hw", Binding: BindingAttested}, "s3-backend-only"},
		"no instance key":            {nil, "s3-backend-only"},
		"assertion kind, other bind": {&InstanceKeyVerified{Kind: "android_key", Home: "tee", Binding: BindingAssertion}, "s3-backend-only"},
	}
	for name, c := range cases {
		out := simWIA(a, Facts{Platform: plat, InstanceKey: c.ik})
		if out.Profile.Level != c.want {
			t.Errorf("%s: profile %q, want %q", name, out.Profile.Level, c.want)
		}
	}
}

func TestInstanceKey_IssueGateTemplateIsShippedLintsCleanAndGates(t *testing.T) {
	data, err := os.ReadFile("../../deploy/assurance/production.rules.example")
	if err != nil {
		t.Fatal(err)
	}
	var tpl string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# (assure-wia-issue ") && strings.Contains(line, "(instance_key") {
			tpl = strings.TrimPrefix(line, "# ")
		}
	}
	if tpl == "" {
		t.Fatal("production.rules.example has no commented instance_key issuance gate")
	}
	if tpl != instanceKeyIssueTemplate {
		t.Fatalf("template drifted from the tested one:\n got %s\nwant %s", tpl, instanceKeyIssueTemplate)
	}
	cfg := defaultCfg()
	rules := "# id: wia-issue-android-key\n" + tpl + "\n"
	if fs := LintRuleSet(mustRuleSet(t, rules), &cfg); len(fs) != 0 {
		t.Fatalf("findings: %v", fs)
	}
	a := newAssessor(t, wiaCfg(), rules)
	plat := &PlatformVerified{Source: "platform_attested"}
	for name, c := range map[string]struct {
		ik   *InstanceKeyVerified
		want bool
	}{
		"android key":          {&InstanceKeyVerified{Kind: "android_key", Home: "tee", Binding: BindingAttested}, true},
		"strongbox":            {&InstanceKeyVerified{Kind: "android_key", Home: "strongbox", Binding: BindingAttested}, true},
		"none":                 {nil, false},
		"fido2 instance key":   {&InstanceKeyVerified{Kind: "fido2", Home: "fido2_hw", Binding: BindingAttested}, false},
		"app attest assertion": {&InstanceKeyVerified{Kind: "app_attest_assertion", Home: "secure_enclave_asserted", Binding: BindingAssertion}, false},
	} {
		if got := simWIA(a, Facts{Platform: plat, InstanceKey: c.ik}).Issue; got != c.want {
			t.Errorf("%s: issue = %v, want %v", name, got, c.want)
		}
	}
}

func TestInstanceKey_AppAttestTemplateIsInTheExampleAndLintsClean(t *testing.T) {
	data, err := os.ReadFile("../../deploy/assurance/production.rules.example")
	if err != nil {
		t.Fatal(err)
	}
	var tpl string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# (assure-wia (profile s1-full-client)") && strings.Contains(line, "app_attest_assertion") {
			tpl = strings.TrimPrefix(line, "# ")
		}
	}
	if tpl != appAttestAssertionTemplate {
		t.Fatalf("template missing or drifted from the tested one:\n got %q\nwant %q", tpl, appAttestAssertionTemplate)
	}
	cfg := defaultCfg()
	if fs := LintRuleSet(mustRuleSet(t, "# id: s1-app-attest\n"+tpl+"\n"), &cfg); HasErrors(fs) {
		t.Fatalf("%v", fs)
	}
}

// instance_key is WIA evidence: no shipped rule file may constrain it from an
// assure-ks or assure-ua rule (commented templates included), so an assertion
// can never be turned into a key-storage or user-authentication level.
func TestInstanceKey_ShippedRulesNeverUseItForKeyStorageOrUserAuth(t *testing.T) {
	for _, path := range []string{"../../deploy/assurance/production.rules.example", "../../rules/default.rules", "../../rules/delegation.rules"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
			if !strings.Contains(body, "(instance_key") {
				continue
			}
			if strings.HasPrefix(body, "(assure-ks") || strings.HasPrefix(body, "(assure-ua") {
				t.Errorf("%s: instance_key used by a key-storage/user-auth rule: %s", path, body)
			}
		}
	}
	// Semantic check: the shipped example plus the App Attest template
	// switched ON lifts no key-storage or user-authentication level from an
	// assertion-only instance key.
	data, err := os.ReadFile("../../deploy/assurance/production.rules.example")
	if err != nil {
		t.Fatal(err)
	}
	a := newAssessor(t, defaultCfg(), string(data)+"\n# id: s1-app-attest\n"+appAttestAssertionTemplate+"\n")
	plat := &PlatformVerified{Source: "platform_attested"}
	with, wWIA := a.Simulate(context.Background(), Facts{Platform: plat, InstanceKey: &InstanceKeyVerified{Kind: "app_attest_assertion", Home: "secure_enclave_asserted", Binding: BindingAssertion}})
	without, _ := a.Simulate(context.Background(), Facts{Platform: plat})
	if !reflect.DeepEqual(with.KeyStorage, without.KeyStorage) || !reflect.DeepEqual(with.UserAuthentication, without.UserAuthentication) {
		t.Fatalf("an App Attest assertion changed key storage / user authentication: %+v vs %+v", with, without)
	}
	// While it does select the S1 profile through the WIA template.
	if wWIA.Profile.Level != "s1-full-client" {
		t.Fatalf("template did not apply: %q", wWIA.Profile.Level)
	}
}
