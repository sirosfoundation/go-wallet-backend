package assurance

import (
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// ErrLintFailed is returned when the policy has lint errors.
var ErrLintFailed = errors.New("assurance policy failed lint")

// NewFromConfig loads the rules file named by cfg, lints the rules and the
// configuration, and returns a ready Assessor. It is fail-closed: a missing
// or unparsable file, a rule without a usable id, or any lint ERROR is an
// error. An existing, empty rules file is valid and resolves every
// dimension to its floor. Warnings are logged, never fatal. The rules file
// path, schema version and policy hash are logged and exported as the
// policy info metric.
func NewFromConfig(cfg config.AssuranceConfig, logger *zap.Logger) (*Assessor, error) {
	rs, findings, err := loadAndLint(cfg)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		if f.Severity == SeverityWarn {
			logger.Warn("assurance policy lint", zap.String("rule_id", f.RuleID), zap.String("finding", f.Message))
		} else {
			logger.Error("assurance policy lint", zap.String("rule_id", f.RuleID), zap.String("finding", f.Message))
		}
	}
	if err := lintError(rs, findings); err != nil {
		return nil, err
	}

	a, err := NewAssessor(cfg, NewSpocpDecider(rs), rs.PolicyVersion)
	if err != nil {
		return nil, fmt.Errorf("assurance policy: %w", err)
	}
	RegisterPolicyInfo(rs.Path, rs.PolicyVersion)
	logger.Info("assurance policy loaded",
		zap.String("rules_file", rs.Path),
		zap.Int("rules", len(rs.Rules)),
		zap.Int("schema_version", SchemaVersion),
		zap.String("policy_hash", rs.PolicyVersion),
		zap.Bool("lower_by_claims_key_storage", cfg.LowerByClaimsKeyStorage),
		zap.Bool("lower_by_claims_user_authentication", cfg.LowerByClaimsUserAuthentication),
	)
	return a, nil
}

// CheckConfig is the side-effect-free startup check: it performs the same
// load and lint as NewFromConfig (no logging, no metrics) and returns the
// first problem. A disabled policy always passes.
func CheckConfig(cfg config.AssuranceConfig) error {
	if !cfg.Enabled {
		return nil
	}
	rs, findings, err := loadAndLint(cfg)
	if err != nil {
		return err
	}
	return lintError(rs, findings)
}

func loadAndLint(cfg config.AssuranceConfig) (*RuleSet, []Finding, error) {
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	if !cfg.Enabled {
		return nil, nil, errors.New("assurance policy is not enabled")
	}
	rs, err := LoadRuleSet(cfg.RulesFile)
	if err != nil {
		return nil, nil, fmt.Errorf("assurance policy: %w", err)
	}
	return rs, append(LintRuleSet(rs, &cfg), LintConfig(cfg)...), nil
}

// lintError turns lint ERRORs into one error that lists them.
func lintError(rs *RuleSet, findings []Finding) error {
	if !HasErrors(findings) {
		return nil
	}
	var msgs []string
	for _, f := range findings {
		if f.Severity == SeverityError {
			msgs = append(msgs, f.String())
		}
	}
	return fmt.Errorf("%w: %s: %s", ErrLintFailed, rs.Path, strings.Join(msgs, "; "))
}
