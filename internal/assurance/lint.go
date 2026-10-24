package assurance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/sirosfoundation/go-spocp/pkg/starform"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Severity of a lint finding.
type Severity string

const (
	// SeverityError findings make a policy unusable: a rule that can never
	// match, or a file whose ids cannot be trusted. Startup refuses it.
	SeverityError Severity = "ERROR"
	// SeverityWarn findings are legal but deserve a human's attention.
	SeverityWarn Severity = "WARN"
)

// Finding is one lint result.
type Finding struct {
	Severity Severity
	// RuleID is empty for findings about the configuration or the file.
	RuleID  string
	Message string
}

func (f Finding) String() string {
	if f.RuleID != "" {
		return fmt.Sprintf("%s: rule %s: %s", f.Severity, f.RuleID, f.Message)
	}
	return fmt.Sprintf("%s: %s", f.Severity, f.Message)
}

// HasErrors reports whether any finding is an error.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// KnownDimensions are the top-level rule tags the engine knows. Later
// features register their own here.
var KnownDimensions = map[string]bool{
	DimKeyStorage:         true,
	DimUserAuthentication: true,
	DimCertification:      true,
}

// slot describes the canonical, positional layout of a rule. A rule lists a
// prefix of its parent's slots, in order: go-spocp matches lists by
// position, so a rule that skips or reorders a slot can never match the
// evidence the builder emits.
type slot struct {
	name     string
	children []slot
	// noneOK marks slots the builder emits as (slot none) when absent, so a
	// rule may name that case. Containers (evidence, verified, claimed) are
	// always emitted with child lists, so "none" there can never match.
	noneOK bool
}

// evidenceLayout MUST mirror Evidence.Element.
var evidenceLayout = slot{name: "evidence", children: []slot{
	{name: "verified", children: []slot{
		{name: "fido2", noneOK: true, children: []slot{{name: "mds3"}, {name: "aaguid"}, {name: "uv"}, {name: "cert"}}},
		{name: "platform", noneOK: true, children: []slot{{name: "source"}, {name: "app_id"}}},
		{name: "hsm", noneOK: true, children: []slot{{name: "id"}}},
	}},
	{name: "claimed", children: []slot{
		{name: "plugin"}, {name: "key_storage"}, {name: "user_authentication"}, {name: "certification"},
	}},
}}

func topLayout(dimension string) []slot {
	return []slot{{name: candidateTag(dimension)}, evidenceLayout}
}

// LintRuleSet checks a loaded rule set. cfg, when non-nil, enables the
// checks that compare rules against the configured level schemes and
// certification catalogue.
func LintRuleSet(rs *RuleSet, cfg *config.AssuranceConfig) []Finding {
	var out []Finding
	for _, r := range rs.Rules {
		out = append(out, lintRule(r, cfg)...)
	}
	return out
}

// LintConfig checks the configured schemes: values that are not registered
// OpenID4VCI key-storage / user-authentication values are legal but visible.
func LintConfig(cfg config.AssuranceConfig) []Finding {
	var out []Finding
	for _, s := range cfg.EffectiveSchemes() {
		for i, v := range s.Values {
			if !config.RegisteredAttackPotentialValues[v] {
				out = append(out, Finding{Severity: SeverityWarn, Message: fmt.Sprintf(
					"scheme %q level %q emits %q, which is not a value registered by OpenID4VCI Appendix D.2; issuers that match on registered values will not recognise it",
					s.ID, s.Levels[i], v)})
			}
		}
	}
	return out
}

func lintRule(r Rule, cfg *config.AssuranceConfig) []Finding {
	errf := func(format string, a ...interface{}) Finding {
		return Finding{Severity: SeverityError, RuleID: r.ID, Message: fmt.Sprintf(format, a...)}
	}
	warnf := func(format string, a ...interface{}) Finding {
		return Finding{Severity: SeverityWarn, RuleID: r.ID, Message: fmt.Sprintf(format, a...)}
	}

	list, ok := r.Element.(*sexp.List)
	if !ok {
		return []Finding{errf("is not a list (line %d); rules must be (assure-... ...)", r.Line)}
	}
	if !KnownDimensions[list.Tag] {
		return []Finding{errf("has unknown dimension tag %q (line %d); known: %s", list.Tag, r.Line, knownList())}
	}

	var out []Finding
	out = append(out, checkLayout(list, topLayout(list.Tag), false, list.Tag, errf)...)

	// Candidate values against the configuration.
	if cfg != nil {
		out = append(out, lintCandidate(list, cfg, warnf)...)
	}

	// Rules that depend on client claims.
	if ev := childList(list, "evidence"); ev != nil {
		if cl := childList(ev, "claimed"); cl != nil && hasRealChildren(cl) {
			out = append(out, warnf("depends on client-claimed evidence ((claimed ...) has children); a client can assert anything it is asked to"))
		}
	}
	return out
}

func knownList() string {
	var names []string
	for k := range KnownDimensions {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// checkLayout verifies that l's child lists appear in the canonical order,
// as a prefix of layout, and recurses into slots that have sub-slots.
func checkLayout(l *sexp.List, layout []slot, noneOK bool, path string, errf func(string, ...interface{}) Finding) []Finding {
	var out []Finding
	if len(layout) == 0 {
		// Leaf slot: the query always carries exactly one atom here, so a
		// rule may carry zero values (don't care), one value or a single
		// (* set ...) of alternatives. Several values, or a nested list,
		// can never match.
		if len(l.Elements) > 1 {
			out = append(out, errf("%s has %d values; a query carries exactly one, so this can never match. Use a single (* set ...) for alternatives", path, len(l.Elements)))
		} else if len(l.Elements) == 1 {
			if _, nested := l.Elements[0].(*sexp.List); nested {
				out = append(out, errf("%s value is a list; a query carries one atom here, so this can never match", path))
			}
		}
		return out
	}
	for i, el := range l.Elements {
		child, isList := el.(*sexp.List)
		if !isList {
			// A value where sub-slots belong can never match, except the
			// "absent" marker (slot none) of an optional verified slot.
			if len(layout) > 0 {
				if a, isAtom := el.(*sexp.Atom); isAtom && a.Value == None && len(l.Elements) == 1 && noneOK {
					continue
				}
				out = append(out, errf("%s position %d: expected slot (%s) but found a value; positional matching would never match", path, i, layout[min(i, len(layout)-1)].name))
			}
			continue
		}
		if i >= len(layout) {
			out = append(out, errf("%s: unexpected (%s) at position %d; the canonical slots are %s", path, child.Tag, i, slotNames(layout)))
			continue
		}
		if child.Tag != layout[i].name {
			out = append(out, errf("%s position %d: slot order is not canonical, found (%s) where (%s) belongs; positional matching makes this rule silently dead. Canonical order: %s",
				path, i, child.Tag, layout[i].name, slotNames(layout)))
			continue
		}
		out = append(out, checkLayout(child, layout[i].children, layout[i].noneOK, path+"/"+child.Tag, errf)...)
	}
	return out
}

func slotNames(layout []slot) string {
	names := make([]string, len(layout))
	for i, s := range layout {
		names[i] = s.name
	}
	return strings.Join(names, ", ")
}

func childList(l *sexp.List, tag string) *sexp.List {
	for _, el := range l.Elements {
		if c, ok := el.(*sexp.List); ok && c.Tag == tag {
			return c
		}
	}
	return nil
}

// hasRealChildren is true when l has any child other than the bare "none"
// atom (which only matches a request with no claims at all).
func hasRealChildren(l *sexp.List) bool {
	for _, el := range l.Elements {
		if a, ok := el.(*sexp.Atom); ok && a.Value == None {
			continue
		}
		return true
	}
	return false
}

// candidateValues returns the atoms a (tier ...)/(name ...) group names and
// whether it uses a star form that is not a plain set (an open grant).
func candidateValues(l *sexp.List) (values []string, open bool) {
	for _, el := range l.Elements {
		switch v := el.(type) {
		case *sexp.Atom:
			values = append(values, v.Value)
		case *starform.Set:
			for _, m := range v.Elements {
				if a, ok := m.(*sexp.Atom); ok {
					values = append(values, a.Value)
				} else {
					open = true
				}
			}
		default:
			open = true
		}
	}
	return values, open
}

func lintCandidate(rule *sexp.List, cfg *config.AssuranceConfig, warnf func(string, ...interface{}) Finding) []Finding {
	group := childList(rule, candidateTag(rule.Tag))
	if group == nil {
		return nil
	}
	values, open := candidateValues(group)
	var out []Finding
	if open {
		out = append(out, warnf("(%s ...) uses a wildcard, prefix, suffix or range; it may grant levels or entries you did not list", group.Tag))
	}
	switch rule.Tag {
	case DimKeyStorage, DimUserAuthentication:
		id := cfg.KeyStorageScheme
		if rule.Tag == DimUserAuthentication {
			id = cfg.UserAuthenticationScheme
		}
		sc, ok := cfg.SchemeByID(id)
		if !ok {
			return out
		}
		known := map[string]bool{}
		for _, l := range sc.Levels {
			known[l] = true
		}
		for _, v := range values {
			if !known[v] {
				out = append(out, warnf("grants tier %q, which is outside the configured scheme %q (levels: %s); it can never be granted", v, sc.ID, strings.Join(sc.Levels, ", ")))
			}
		}
	case DimCertification:
		known := map[string]bool{}
		for _, e := range cfg.EffectiveCertificationEntries() {
			known[e.Name] = true
		}
		for _, v := range values {
			if !known[v] {
				out = append(out, warnf("names certification %q, which is not in the configured catalogue", v))
			}
		}
	}
	return out
}
