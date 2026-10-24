package assurance

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

var (
	decisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "wallet_backend",
		Subsystem: "assurance",
		Name:      "decisions_total",
		Help:      "Assurance policy outcomes by dimension and chosen level (or certification entry, or none).",
	}, []string{"dimension", "level"})

	policyInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "wallet_backend",
		Subsystem: "assurance",
		Name:      "policy_info",
		Help:      "Always 1; labels identify the loaded assurance policy.",
	}, []string{"rules_file", "schema_version", "policy_hash"})
)

// Scheme is a validated, indexed level scheme.
type Scheme struct {
	ID     string
	Levels []string
	Values []string

	floor, ceiling int
	byLevel        map[string]int
	byValue        map[string]int
}

// NewScheme validates c and indexes it.
func NewScheme(c config.LevelSchemeConfig) (*Scheme, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	s := &Scheme{
		ID: c.ID, Levels: c.Levels, Values: c.Values,
		byLevel: map[string]int{}, byValue: map[string]int{},
	}
	for i, l := range c.Levels {
		s.byLevel[l] = i
		s.byValue[c.Values[i]] = i
	}
	s.floor = s.byLevel[c.Floor]
	s.ceiling = len(c.Levels) - 1
	if c.Ceiling != "" {
		s.ceiling = s.byLevel[c.Ceiling]
	}
	return s, nil
}

// Bucket places an emitted level relative to the scheme, for consumers that
// have only three slots (the KA status list indexes high/middle/low).
type Bucket int

const (
	BucketHigh Bucket = iota
	BucketMiddle
	BucketLow
)

// StatusBucket maps a level index onto a coarse bucket by position: the
// scheme's top level is High, the floor (or anything below it) is Low, and
// everything between is Middle. For the built-in iso_18045 scheme this is
// the same grouping the legacy key_storage_status index uses.
func (s *Scheme) StatusBucket(idx int) Bucket {
	switch {
	case idx <= s.floor:
		return BucketLow
	case idx >= len(s.Levels)-1:
		return BucketHigh
	default:
		return BucketMiddle
	}
}

// Claims are the client's request fields. They are only ever rendered into
// the claimed group of the evidence and used for lower_by_claims.
type Claims struct {
	Plugin             string
	KeyStorage         []string
	UserAuthentication []string
	Certification      interface{}
}

// Facts are the inputs to one assessment.
type Facts struct {
	Fido2    *Fido2Verified
	Platform *PlatformVerified
	HSM      *HSMVerified
	Claims   Claims
}

// DimensionResult is the outcome for key_storage or user_authentication.
type DimensionResult struct {
	Level string
	Value string
	// LevelIndex is the index of Level in Scheme.Levels.
	LevelIndex int
	Scheme     *Scheme
	// Granted is the level the rules granted (before lowering by claims).
	Granted string
	// ClaimedLevel is the level the client claimed, "" when it sent none.
	ClaimedLevel string
	Lowered      bool
	RuleIDs      []string
}

// Outcome is the result of one assessment.
type Outcome struct {
	KeyStorage         DimensionResult
	UserAuthentication DimensionResult
	// Certification is the claim value: a URL string, a {scheme,
	// assurance_level[, basis]} object, or "none".
	Certification     interface{}
	CertificationName string
	CertificationRule []string

	PolicyVersion string
	SchemaVersion int
	// Errors are decider failures that were treated as deny.
	Errors []error
}

// RuleIDs returns every rule id that contributed, de-duplicated.
func (o *Outcome) RuleIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range [][]string{o.KeyStorage.RuleIDs, o.UserAuthentication.RuleIDs, o.CertificationRule} {
		for _, id := range group {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// Assessor applies the policy: it builds the evidence, probes the
// configured levels through the decider, and applies lower_by_claims,
// ceiling and floor.
type Assessor struct {
	cfg     config.AssuranceConfig
	decider AssuranceDecider
	ks, ua  *Scheme
	certs   []config.CertificationEntry
	version string
	// NormalizeClaim optionally maps a raw client claim string into a
	// scheme's emitted vocabulary before it is looked up (the service uses
	// it for the legacy "software"/"hardware" vocabulary of iso_18045).
	NormalizeClaim func(schemeID, raw string) string
}

// NewAssessor wires a decider to a validated configuration. policyVersion
// is reported in outcomes (the decider's own trace carries it too).
func NewAssessor(cfg config.AssuranceConfig, decider AssuranceDecider, policyVersion string) (*Assessor, error) {
	if err := validateEnabled(cfg); err != nil {
		return nil, err
	}
	ksCfg, _ := cfg.SchemeByID(cfg.KeyStorageScheme)
	uaCfg, _ := cfg.SchemeByID(cfg.UserAuthenticationScheme)
	ks, err := NewScheme(ksCfg)
	if err != nil {
		return nil, err
	}
	ua, err := NewScheme(uaCfg)
	if err != nil {
		return nil, err
	}
	return &Assessor{
		cfg: cfg, decider: decider, ks: ks, ua: ua,
		certs: cfg.EffectiveCertificationEntries(), version: policyVersion,
	}, nil
}

// validateEnabled runs the structural validation as if enabled, so callers
// that construct an Assessor directly get the same fail-closed checks.
func validateEnabled(cfg config.AssuranceConfig) error {
	cfg.Enabled = true
	if cfg.RulesFile == "" {
		cfg.RulesFile = "in-memory.rules"
	}
	return cfg.Validate()
}

// Schemes returns the key storage and user authentication schemes.
func (a *Assessor) Schemes() (ks, ua *Scheme) { return a.ks, a.ua }

func (a *Assessor) claimIndex(s *Scheme, raws []string) (idx int, atomValue string, ok bool) {
	idx = -1
	for _, raw := range raws {
		v := raw
		if a.NormalizeClaim != nil {
			v = a.NormalizeClaim(s.ID, raw)
		}
		i, known := s.byValue[v]
		if !known {
			// An unrecognised claim cannot be trusted to mean anything:
			// it counts as the scheme's floor.
			i = s.floor
		}
		if i > idx {
			idx, atomValue = i, raw
		}
	}
	return idx, atomValue, idx >= 0
}

func claimedCertificationAtom(c interface{}) string {
	switch v := c.(type) {
	case string:
		return v
	case map[string]interface{}:
		scheme, _ := v["scheme"].(string)
		level, _ := v["assurance_level"].(string)
		if scheme != "" && level != "" {
			return scheme + "/" + level
		}
	}
	return ""
}

// Evidence builds the evidence for the given facts. Claimed key storage and
// user authentication are rendered as the raw client string that maps to the
// highest level of the dimension's scheme.
func (a *Assessor) Evidence(f Facts) Evidence {
	_, ksAtom, _ := a.claimIndex(a.ks, f.Claims.KeyStorage)
	_, uaAtom, _ := a.claimIndex(a.ua, f.Claims.UserAuthentication)
	return Evidence{
		Fido2: f.Fido2, Platform: f.Platform, HSM: f.HSM,
		Claimed: Claimed{
			Plugin:             f.Claims.Plugin,
			KeyStorage:         ksAtom,
			UserAuthentication: uaAtom,
			Certification:      claimedCertificationAtom(f.Claims.Certification),
		},
	}
}

// Assess decides all three dimensions. It does not return an error: every
// failure resolves to a deny, so the worst case is the floor.
func (a *Assessor) Assess(ctx context.Context, f Facts) *Outcome {
	ev := a.Evidence(f).Element()
	out := &Outcome{PolicyVersion: a.version, SchemaVersion: SchemaVersion}

	out.KeyStorage = a.assessDimension(ctx, out, DimKeyStorage, a.ks, ev, f.Claims.KeyStorage, a.cfg.LowerByClaimsKeyStorage)
	out.UserAuthentication = a.assessDimension(ctx, out, DimUserAuthentication, a.ua, ev, f.Claims.UserAuthentication, a.cfg.LowerByClaimsUserAuthentication)
	a.assessCertification(ctx, out, ev)

	decisionsTotal.WithLabelValues("key_storage", out.KeyStorage.Level).Inc()
	decisionsTotal.WithLabelValues("user_authentication", out.UserAuthentication.Level).Inc()
	cert := out.CertificationName
	if cert == "" {
		cert = None
	}
	decisionsTotal.WithLabelValues("certification", cert).Inc()
	return out
}

func (a *Assessor) permits(ctx context.Context, out *Outcome, q Query) (bool, Trace) {
	ok, tr, err := a.decider.Permits(ctx, q)
	if err != nil {
		out.Errors = append(out.Errors, fmt.Errorf("%s %s: %w", q.Dimension, q.Candidate, err))
		return false, tr
	}
	return ok, tr
}

func (a *Assessor) assessDimension(ctx context.Context, out *Outcome, dim string, s *Scheme, ev sexp.Element, claimed []string, lower bool) DimensionResult {
	granted := s.floor
	var ids []string
	// Highest to lowest, from the ceiling; the floor is never probed, it is
	// what remains when nothing above it is permitted.
	for i := s.ceiling; i > s.floor; i-- {
		ok, tr := a.permits(ctx, out, Query{Dimension: dim, Candidate: s.Levels[i], Evidence: ev})
		if ok {
			granted, ids = i, tr.RuleIDs
			break
		}
	}
	res := DimensionResult{Scheme: s, Granted: s.Levels[granted], RuleIDs: ids}
	final := granted
	if lower {
		if ci, _, has := a.claimIndex(s, claimed); has {
			res.ClaimedLevel = s.Levels[ci]
			if ci < final {
				final = ci
				res.Lowered = true
			}
		}
	}
	if final < s.floor {
		final = s.floor
	}
	res.LevelIndex, res.Level, res.Value = final, s.Levels[final], s.Values[final]
	return res
}

func (a *Assessor) assessCertification(ctx context.Context, out *Outcome, ev sexp.Element) {
	out.Certification = None
	for _, e := range a.certs {
		ok, tr := a.permits(ctx, out, Query{Dimension: DimCertification, Candidate: e.Name, Evidence: ev})
		if !ok {
			continue
		}
		out.CertificationName, out.CertificationRule = e.Name, tr.RuleIDs
		if e.URL != "" {
			out.Certification = e.URL
			return
		}
		obj := map[string]interface{}{"scheme": e.Scheme, "assurance_level": e.AssuranceLevel}
		if a.cfg.CertificationBasisInClaim {
			hash := a.version
			if len(hash) > 8 {
				hash = hash[:8]
			}
			obj["basis"] = map[string]interface{}{"policy": hash, "rules": append([]string{}, tr.RuleIDs...)}
		}
		out.Certification = obj
		return
	}
}

// RegisterPolicyInfo publishes the loaded policy's identity as an info
// metric (always 1). Only the latest policy is exported.
func RegisterPolicyInfo(rulesFile, policyHash string) {
	policyInfo.Reset()
	policyInfo.WithLabelValues(rulesFile, fmt.Sprint(SchemaVersion), policyHash).Set(1)
}
