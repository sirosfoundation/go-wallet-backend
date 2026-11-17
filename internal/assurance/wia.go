package assurance

import (
	"context"
)

// WIAOutcome is the result of assessing a Wallet Instance Attestation
// request: whether a WIA is issued at all, which S-profile it carries and
// which wallet_solution_certification_information entry applies.
type WIAOutcome struct {
	// Issue is false when no assure-wia-issue rule permits the evidence. The
	// caller must then refuse the WIA.
	Issue        bool
	IssueRuleIDs []string

	// Profile is the S-profile result (Level is the profile name, Value the
	// emitted attestation_source string). It is the scheme floor when no rule
	// grants a higher profile.
	Profile DimensionResult

	// CertName and CertInfo are the permitted wallet_solution_certification_
	// information entry; CertInfo is nil when none is permitted (the caller
	// then keeps its static configuration).
	CertName    string
	CertInfo    map[string]interface{}
	CertRuleIDs []string

	PolicyVersion string
	SchemaVersion int
	// Errors are decider failures that were treated as deny.
	Errors []error
}

// RuleIDs returns every rule id that contributed, de-duplicated.
func (o *WIAOutcome) RuleIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range [][]string{o.IssueRuleIDs, o.Profile.RuleIDs, o.CertRuleIDs} {
		for _, id := range group {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// WIAProfileScheme returns the configured S-profile scheme.
func (a *Assessor) WIAProfileScheme() *Scheme { return a.wia }

// AssessWIA decides the WIA: issue or refuse, S-profile, certification
// information. Like Assess it never returns an error: a decider failure is a
// deny, so the worst case is refusing the WIA / the floor profile / the
// static certification information.
func (a *Assessor) AssessWIA(ctx context.Context, f Facts) *WIAOutcome {
	return a.assessWIA(ctx, f, true)
}

func (a *Assessor) assessWIA(ctx context.Context, f Facts, record bool) *WIAOutcome {
	ev := a.Evidence(f).Element()
	out := &WIAOutcome{PolicyVersion: a.version, SchemaVersion: SchemaVersion}

	ok, tr := a.permits(ctx, &out.Errors, Query{Dimension: DimWIAIssue, Evidence: ev})
	out.Issue, out.IssueRuleIDs = ok, tr.RuleIDs

	// No client claim exists for the S dimension, so there is nothing to
	// lower by: claimed is nil and lowering is off.
	out.Profile = a.assessDimension(ctx, &out.Errors, DimWIA, a.wia, ev, nil, false)

	for _, e := range a.cfg.WIACertification.Entries {
		ok, tr := a.permits(ctx, &out.Errors, Query{Dimension: DimWIACert, Candidate: e.Name, Evidence: ev})
		if !ok {
			continue
		}
		out.CertName, out.CertRuleIDs = e.Name, tr.RuleIDs
		out.CertInfo = make(map[string]interface{}, len(e.Information))
		for k, v := range e.Information {
			out.CertInfo[k] = v
		}
		break
	}

	if record {
		issue := "refuse"
		if out.Issue {
			issue = "issue"
		}
		decisionsTotal.WithLabelValues("wia_issue", issue).Inc()
		decisionsTotal.WithLabelValues("wia_profile", out.Profile.Level).Inc()
		cert := out.CertName
		if cert == "" {
			cert = None
		}
		decisionsTotal.WithLabelValues("wia_certification", cert).Inc()
	}
	return out
}

// Simulate is the dry run behind the assurance preview: the same assessment
// as Assess and AssessWIA on the same facts, without recording metrics.
func (a *Assessor) Simulate(ctx context.Context, f Facts) (*Outcome, *WIAOutcome) {
	return a.assess(ctx, f, false), a.assessWIA(ctx, f, false)
}
