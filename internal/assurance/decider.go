package assurance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirosfoundation/go-spocp"
	"github.com/sirosfoundation/go-spocp/pkg/persist"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
)

// Dimension tags: the top-level tag of a policy query, which is also the
// tag go-spocp indexes rules by.
const (
	DimKeyStorage         = "assure-ks"
	DimUserAuthentication = "assure-ua"
	DimCertification      = "assure-cert"
)

// Query asks whether a candidate value may be granted for a dimension given
// the evidence. It renders as
//
//	(<Dimension> (tier <Candidate>)(evidence ...))      for assure-ks / assure-ua
//	(assure-cert (name <Candidate>)(evidence ...))      for assure-cert
type Query struct {
	Dimension string
	Candidate string
	Evidence  sexp.Element
}

// candidateTag is the tag of the candidate group for a dimension.
func candidateTag(dimension string) string {
	if dimension == DimCertification {
		return "name"
	}
	return "tier"
}

// Element builds the query through the element API only; candidate and
// evidence values are atoms, never spliced into text.
func (q Query) Element() *sexp.List {
	return sexp.NewList(q.Dimension,
		sexp.NewList(candidateTag(q.Dimension), sexp.NewAtom(q.Candidate)),
		q.Evidence,
	)
}

// Trace explains a decision: which rules granted it and under which policy.
type Trace struct {
	// RuleIDs are the ids of every rule that matched the query (empty on deny).
	RuleIDs []string
	// PolicyVersion is the sha256 (hex) of the rules file bytes.
	PolicyVersion string
}

// AssuranceDecider answers whether a candidate is permitted. Probing loops
// live above it and only call Permits, so another implementation (for
// example an AuthZEN PDP) can be substituted.
type AssuranceDecider interface {
	Permits(ctx context.Context, q Query) (bool, Trace, error)
}

// Rule is one loaded policy rule.
type Rule struct {
	ID      string
	Element sexp.Element
	// Line is the 1-based line number of the rule in the file.
	Line int
}

// RuleSet is a loaded, id-annotated rules file.
type RuleSet struct {
	Path string
	// PolicyVersion is the sha256 (hex) of the file bytes.
	PolicyVersion string
	Rules         []Rule
}

// ErrBadRulesFileName is returned for names go-spocp would treat as binary.
var ErrBadRulesFileName = errors.New("rules file name must not end in .spocp or .bin (go-spocp loads those as binary); use .rules")

// CheckRulesFileName rejects names that go-spocp auto-detects as binary.
func CheckRulesFileName(path string) error {
	l := strings.ToLower(path)
	if strings.HasSuffix(l, ".spocp") || strings.HasSuffix(l, ".bin") {
		return fmt.Errorf("%w: %q", ErrBadRulesFileName, path)
	}
	return nil
}

// isCommentLine mirrors the loader's comment handling for the line formats
// persist.DefaultLoadOptions skips ("#", "//", ";"), so the id pass and the
// loader see the same rule lines.
func isCommentLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, ";")
}

// checkRuleLine rejects rule lines the go-spocp advanced-form loader would
// misread instead of refusing. In particular it accepts an unbalanced rule
// such as "(assure-ks (tier moderate)" and silently drops the last character
// of the last atom ("moderat"), which would turn a typo into a different
// rule. So the line must be exactly one balanced list, and quote characters
// (which the loader keeps as part of the atom) are not allowed.
func checkRuleLine(line string) error {
	if strings.ContainsRune(line, '"') {
		return errors.New("rule contains a double quote; quoted atoms are not supported")
	}
	if !strings.HasPrefix(line, "(") {
		return errors.New("rule must be one parenthesised list")
	}
	depth := 0
	for i, ch := range line {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return errors.New("unbalanced parentheses: unexpected \")\"")
			}
			if depth == 0 && i != len(line)-1 {
				return errors.New("more than one expression on the line; put one rule per line")
			}
		}
	}
	if depth != 0 {
		return errors.New("unbalanced parentheses: missing \")\"")
	}
	return nil
}

// idPrefix introduces a rule id comment.
const idPrefix = "# id:"

// LoadRuleSet loads rules in advanced form (one rule per line) and attaches
// the ids declared by "# id: <name>" comment lines. go-spocp only returns
// rule elements, so ids are read by a separate pass over the same bytes,
// mapped by order, and cross-checked: the number of ids must equal the
// number of loaded elements, every rule needs exactly one id, ids must be
// unique and no two rules may be identical.
func LoadRuleSet(path string) (*RuleSet, error) {
	if err := CheckRulesFileName(path); err != nil {
		return nil, err
	}
	path = filepath.Clean(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}
	sum := sha256.Sum256(data)

	opts := persist.DefaultLoadOptions()
	opts.Format = persist.FormatAdvanced
	elems, err := persist.LoadFile(path, opts)
	if err != nil {
		return nil, fmt.Errorf("load rules file %s: %w", path, err)
	}

	// The loader reopened the file: refuse a file that changed in between,
	// so the hash we report is the hash of the rules we loaded.
	again, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("re-read rules file: %w", err)
	}
	if !bytes.Equal(again, data) {
		return nil, fmt.Errorf("rules file %s changed while loading", path)
	}

	type idLine struct {
		id   string
		line int
	}
	var ids []idLine
	pending := ""
	pendingLine := 0
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		lineNo := i + 1
		if line == "" {
			continue
		}
		if isCommentLine(line) {
			if strings.HasPrefix(line, idPrefix) {
				id := strings.TrimSpace(strings.TrimPrefix(line, idPrefix))
				if id == "" || strings.ContainsAny(id, " \t") {
					return nil, fmt.Errorf("line %d: malformed rule id %q", lineNo, id)
				}
				if pending != "" {
					return nil, fmt.Errorf("line %d: rule id %q (line %d) is not followed by a rule", lineNo, pending, pendingLine)
				}
				pending, pendingLine = id, lineNo
			}
			continue
		}
		if err := checkRuleLine(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if pending == "" {
			return nil, fmt.Errorf("line %d: rule has no preceding \"# id: <name>\" comment", lineNo)
		}
		ids = append(ids, idLine{id: pending, line: lineNo})
		pending = ""
	}
	if pending != "" {
		return nil, fmt.Errorf("line %d: rule id %q is not followed by a rule", pendingLine, pending)
	}
	if len(ids) != len(elems) {
		return nil, fmt.Errorf("rules file %s: %d rule lines but the loader returned %d rules", path, len(ids), len(elems))
	}

	rs := &RuleSet{Path: path, PolicyVersion: hex.EncodeToString(sum[:])}
	seenID := map[string]int{}
	seenRule := map[string]string{}
	for i, el := range elems {
		il := ids[i]
		if prev, dup := seenID[il.id]; dup {
			return nil, fmt.Errorf("line %d: duplicate rule id %q (first at line %d)", il.line, il.id, prev)
		}
		seenID[il.id] = il.line
		canon := el.String()
		if prevID, dup := seenRule[canon]; dup {
			return nil, fmt.Errorf("line %d: rule %q is identical to rule %q", il.line, il.id, prevID)
		}
		seenRule[canon] = il.id
		rs.Rules = append(rs.Rules, Rule{ID: il.id, Element: el, Line: il.line})
	}
	return rs, nil
}

// SpocpDecider is the in-process go-spocp implementation of AssuranceDecider.
type SpocpDecider struct {
	engine  *spocp.Engine
	version string
	byRule  map[string]string // canonical rule string -> id
}

// NewSpocpDecider builds an engine from a loaded rule set.
func NewSpocpDecider(rs *RuleSet) *SpocpDecider {
	d := &SpocpDecider{
		engine:  spocp.NewEngine(),
		version: rs.PolicyVersion,
		byRule:  make(map[string]string, len(rs.Rules)),
	}
	for _, r := range rs.Rules {
		d.engine.AddRuleElement(r.Element)
		d.byRule[r.Element.String()] = r.ID
	}
	return d
}

// PolicyVersion returns the sha256 (hex) of the rules file.
func (d *SpocpDecider) PolicyVersion() string { return d.version }

// RuleCount returns the number of loaded rules.
func (d *SpocpDecider) RuleCount() int { return d.engine.RuleCount() }

// Permits implements AssuranceDecider. It never errors for a well-formed
// query; an error means the rule ids of a match could not be resolved, and
// callers must treat that as a deny.
func (d *SpocpDecider) Permits(_ context.Context, q Query) (bool, Trace, error) {
	tr := Trace{PolicyVersion: d.version}
	if q.Evidence == nil {
		return false, tr, errors.New("assurance query has no evidence")
	}
	el := q.Element()
	if !d.engine.QueryElement(el) {
		return false, tr, nil
	}
	matches, err := d.engine.FindMatchingRules(el.String())
	if err != nil {
		return false, tr, fmt.Errorf("resolve matching rules: %w", err)
	}
	if len(matches) == 0 {
		return false, tr, errors.New("engine permitted the query but no rule was found for it")
	}
	for _, m := range matches {
		id, ok := d.byRule[m.String()]
		if !ok {
			return false, tr, fmt.Errorf("matching rule %s has no id", m.String())
		}
		tr.RuleIDs = append(tr.RuleIDs, id)
	}
	return true, tr, nil
}
