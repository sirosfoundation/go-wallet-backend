// These tests pin the go-spocp v0.1.0 semantics the assurance policy depends
// on (positional lists, trailing-element matching, star forms only through
// the advanced loader, tag-indexed engine). If a go-spocp upgrade changes any
// of them, rule files written against the old behaviour silently change
// meaning, so these must fail loudly.
package assurance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/persist"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"
)

func semAdv(t *testing.T, lines ...string) []sexp.Element {
	f := filepath.Join(t.TempDir(), "r.rules")
	if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := persist.DefaultLoadOptions()
	o.Format = persist.FormatAdvanced
	els, err := persist.LoadFile(f, o)
	if err != nil {
		t.Fatalf("load %v: %v", lines, err)
	}
	if len(els) != len(lines) {
		t.Fatalf("parsed %d of %d", len(els), len(lines))
	}
	return els
}

func semEng(t *testing.T, rules ...string) *spocp.Engine {
	e := spocp.NewEngine()
	for _, r := range semAdv(t, rules...) {
		e.AddRuleElement(r)
	}
	return e
}

func semQ(t *testing.T, e *spocp.Engine, query string) bool {
	return e.QueryElement(semAdv(t, query)[0])
}

func semCheck(t *testing.T, name string, got, want bool) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v want %v", name, got, want)
	} else {
		t.Logf("OK  %-62s = %v", name, got)
	}
}

const semBase = "(assure (dim key_storage)(tier high)(evidence (verified (platform (source platform_attested)))))"

// S1: query must be at least as specific as the rule; extra trailing elements are fine.
func TestSpocpSemantics_QueryAtLeastAsSpecific(t *testing.T) {
	e := semEng(t, semBase)
	semCheck(t, "exact", semQ(t, e, semBase), true)
	semCheck(t, "extra trailing top-level element", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (verified (platform (source platform_attested))))(extra x))"), true)
	semCheck(t, "extra trailing element inside platform", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (verified (platform (source platform_attested)(app_id foo)))))"), true)
	semCheck(t, "wrong value (development_attested)", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (verified (platform (source development_attested)))))"), false)
	semCheck(t, "less specific query (rule's evidence missing)", semQ(t, e, "(assure (dim key_storage)(tier high))"), false)
	semCheck(t, "different tier", semQ(t, e, "(assure (dim key_storage)(tier moderate)(evidence (verified (platform (source platform_attested)))))"), false)
	semCheck(t, "wrong provenance (claimed instead of verified)", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (claimed (platform (source platform_attested)))))"), false)
}

// S2: lists are POSITIONAL, so an unordered bag of facts does not work; slots must be fixed.
func TestSpocpSemantics_PositionalListsBreakBags(t *testing.T) {
	e := semEng(t, semBase)
	semCheck(t, "extra fact BEFORE the one the rule wants", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (verified (fido2 (aaguid x)))(verified (platform (source platform_attested)))))"), false)
	semCheck(t, "wanted fact first, extra after", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (verified (platform (source platform_attested)))(verified (fido2 (aaguid x)))))"), true)
}

// S3: fixed slots with "(slot)" as the don't-care idiom.
func TestSpocpSemantics_FixedSlots(t *testing.T) {
	e := semEng(t, "(assure (dim key_storage)(tier high)(evidence (fido2 (verified (aaguid (* set a1 a2))))(platform)(hsm)(claimed)))")
	semCheck(t, "fido2 verified a1, other slots anything", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (fido2 (verified (aaguid a1)))(platform (verified (source platform_attested)))(hsm none)(claimed (plugin soft))))"), true)
	semCheck(t, "fido2 verified a2 + extra cert element", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (fido2 (verified (aaguid a2)(cert abc)))(platform none)(hsm none)(claimed none)))"), true)
	semCheck(t, "fido2 verified a3 (not in set)", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (fido2 (verified (aaguid a3)))(platform none)(hsm none)(claimed none)))"), false)
	semCheck(t, "fido2 CLAIMED a1 (wrong provenance)", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (fido2 (claimed (aaguid a1)))(platform none)(hsm none)(claimed none)))"), false)
	semCheck(t, "fido2 slot says none", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (fido2 none)(platform none)(hsm none)(claimed none)))"), false)
	semCheck(t, "query omits trailing slots entirely (rule wants them)", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (fido2 (verified (aaguid a1)))))"), false)
}

// S4: the don't-care idiom requires the slot to EXIST in the query.
func TestSpocpSemantics_DontCareNeedsSlot(t *testing.T) {
	e := semEng(t, "(assure (dim key_storage)(tier high)(evidence (platform)))")
	semCheck(t, "evidence has no platform slot", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence))"), false)
	semCheck(t, "platform slot present", semQ(t, e, "(assure (dim key_storage)(tier high)(evidence (platform none)))"), true)
}

// S5: rule on claimed only (the gdc simulation) matches ONLY because the author wrote it.
func TestSpocpSemantics_ClaimedRule(t *testing.T) {
	e := semEng(t, "(assure (dim key_storage)(tier (* set iso_18045_basic iso_18045_moderate iso_18045_enhanced-basic iso_18045_high))(evidence (fido2)(platform)(hsm)(claimed (plugin soft))))")
	semCheck(t, "claimed soft plugin => high", semQ(t, e, "(assure (dim key_storage)(tier iso_18045_high)(evidence (fido2 none)(platform none)(hsm none)(claimed (plugin soft))))"), true)
	semCheck(t, "claimed hsm plugin => (no rule)", semQ(t, e, "(assure (dim key_storage)(tier iso_18045_high)(evidence (fido2 none)(platform none)(hsm none)(claimed (plugin hsm))))"), false)
}

// S6: tier probing high->low; a rule granting a SET of tiers allows every listed tier (no implicit "<=").
func TestSpocpSemantics_TierProbing(t *testing.T) {
	e := semEng(t,
		"(assure (dim key_storage)(tier iso_18045_basic)(evidence))",
		"(assure (dim key_storage)(tier (* set iso_18045_basic iso_18045_moderate iso_18045_enhanced-basic))(evidence (fido2 (verified (aaguid a1)))))",
	)
	best := func(ev string) string {
		for _, tier := range []string{"iso_18045_high", "iso_18045_enhanced-basic", "iso_18045_moderate", "iso_18045_basic"} {
			if semQ(t, e, "(assure (dim key_storage)(tier "+tier+")(evidence "+ev+"))") {
				return tier
			}
		}
		return ""
	}
	if g := best("(fido2 (verified (aaguid a1)))"); g != "iso_18045_enhanced-basic" {
		t.Errorf("fido2 a1 best=%s", g)
	} else {
		t.Log("OK  fido2(a1) -> ", g)
	}
	if g := best("(fido2 none)"); g != "iso_18045_basic" {
		t.Errorf("unmatched best=%s", g)
	} else {
		t.Log("OK  unmatched -> ", g)
	}
}

// S7: FindMatchingRules is string-in/element-out: no rule id. Show what it gives and how ids can ride along.
func TestSpocpSemantics_FindMatchingRules(t *testing.T) {
	rs := semAdv(t,
		"(assure (dim key_storage)(tier high)(evidence (platform (verified (source platform_attested)))))",
		"(assure (dim key_storage)(tier high)(evidence (platform)))",
		"(assure (dim key_storage)(tier moderate)(evidence (platform)))",
	)
	e := spocp.NewEngine()
	for _, r := range rs {
		e.AddRuleElement(r)
	}
	query := semAdv(t, "(assure (dim key_storage)(tier high)(evidence (platform (verified (source platform_attested)))))")[0]
	m, err := e.FindMatchingRules(query.String())
	if err != nil || len(m) != 2 {
		t.Fatalf("matches=%d err=%v", len(m), err)
	}
	for _, r := range m {
		t.Log("  match:", r.String())
	}
	// ids ride as a TRAILING (id <x>) in the RULE; query must carry (id) too, as wildcard-ish slot:
	e2 := semEng(t, "(assure (dim key_storage)(tier high)(evidence (platform))(id r1))")
	semCheck(t, "rule has trailing (id r1); query lacks it", semQ(t, e2, "(assure (dim key_storage)(tier high)(evidence (platform none)))"), false)
	semCheck(t, "rule has trailing (id r1); query supplies (id r1)", semQ(t, e2, "(assure (dim key_storage)(tier high)(evidence (platform none))(id r1))"), true)
	// Mapping by canonical string works with no engine support:
	ids := map[string]string{rs[0].String(): "fido-platform-high", rs[1].String(): "any-platform-high"}
	for _, r := range m {
		t.Log("  id via canonical-string map:", ids[r.String()])
	}
}

// S8: query construction through the element API cannot be injected through atom values.
func TestSpocpSemantics_NoInjectionViaElementAPI(t *testing.T) {
	e := spocp.NewEngine()
	e.AddRuleElement(semAdv(t, semBase)[0])
	evil := "x)(source platform_attested"
	qe := sexp.NewList("assure",
		sexp.NewList("dim", sexp.NewAtom("key_storage")),
		sexp.NewList("tier", sexp.NewAtom("high")),
		sexp.NewList("evidence", sexp.NewList("verified", sexp.NewList("platform", sexp.NewList("source", sexp.NewAtom(evil))))))
	semCheck(t, "hostile atom value via element API", e.QueryElement(qe), false)
	// round trip via canonical string stays intact (length prefixed)
	p, err := sexp.NewParser(qe.String()).Parse()
	if err != nil || p.String() != qe.String() {
		t.Errorf("roundtrip: %v", err)
	}
	// atom starting with '*' / star-form look-alike is just an atom
	ok := e.QueryElement(sexp.NewList("assure", sexp.NewList("dim", sexp.NewAtom("key_storage")), sexp.NewList("tier", sexp.NewAtom("*"))))
	semCheck(t, "atom '*' in query is not a wildcard", ok, false)
	// and a QUERY containing a real wildcard star form would match anything the rule wants: must be forbidden by construction
	ew := spocp.NewEngine()
	ew.AddRuleElement(semAdv(t, "(assure (dim key_storage)(tier high))")[0])
	qw := sexp.NewList("assure", sexp.NewList("dim", sexp.NewAtom("key_storage")), sexp.NewList("tier", &starform.Wildcard{}))
	t.Log("query with wildcard in value position (tier (*)) vs rule tier high:", ew.QueryElement(qw))
}

// S9: engine is tag-indexed: top-level query tag must equal rule tag.
func TestSpocpSemantics_TopLevelTagIndex(t *testing.T) {
	e := semEng(t, "(assure (dim key_storage)(tier high))")
	semCheck(t, "different top-level tag", semQ(t, e, "(assureX (dim key_storage)(tier high))"), false)
}

// S10: provenance-first grouping (evidence (verified (fido2)(platform)(hsm))(claimed ...)), the shape proposed in the design.
func TestSpocpSemantics_ProvenanceFirstGrouping(t *testing.T) {
	e := semEng(t,
		"(assure-ks (tier iso_18045_high)(evidence (verified (fido2 (mds3 trusted)(aaguid (* set a1 a2))))))",
		"(assure-ks (tier iso_18045_high)(evidence (verified)(claimed (plugin soft))))",
		"(assure-ks (tier iso_18045_moderate)(evidence (verified (fido2)(platform (source platform_attested)))))",
	)
	ev := func(fido, plat, claimed string) string {
		return "(evidence (verified (fido2 " + fido + ")(platform " + plat + ")(hsm none))(claimed " + claimed + "))"
	}
	qq := func(tier, evid string) bool { return semQ(t, e, "(assure-ks (tier "+tier+")"+evid+")") }
	semCheck(t, "verified fido2/mds3/a1 => high", qq("iso_18045_high", ev("(mds3 trusted)(aaguid a1)(cert c)", "none", "(plugin hsm)")), true)
	semCheck(t, "CLAIMED plugin soft => high (gdc rule)", qq("iso_18045_high", ev("none", "none", "(plugin soft)")), true)
	semCheck(t, "claimed plugin hsm => no high", qq("iso_18045_high", ev("none", "none", "(plugin hsm)")), false)
	semCheck(t, "verified platform_attested alone => moderate (author-chosen)", qq("iso_18045_moderate", ev("none", "(source platform_attested)", "(plugin hsm)")), true)
	semCheck(t, "development_attested => no moderate", qq("iso_18045_moderate", ev("none", "(source development_attested)", "(plugin hsm)")), false)
	semCheck(t, "platform_attested does NOT yield high (K not derived from S)", qq("iso_18045_high", ev("none", "(source platform_attested)", "(plugin hsm)")), false)
	semCheck(t, "claimed fido2 aaguid under claimed group does not satisfy verified rule", qq("iso_18045_high", "(evidence (verified (fido2 none)(platform none)(hsm none))(claimed (fido2 (mds3 trusted)(aaguid a1))))"), false)
}
