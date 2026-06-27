package as

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestSPOCPEngine_LoadAndEvaluate(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "test.rules")
	// Rule: allow any token request with tac=r
	err := os.WriteFile(rulesFile, []byte("(5:token (3:tac 1:r))\n"), 0600)
	if err != nil {
		t.Fatalf("write rules: %v", err)
	}

	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir: %v", err)
	}

	if pe.RuleCount() != 1 {
		t.Fatalf("expected 1 rule, got %d", pe.RuleCount())
	}

	// Query that should match.
	allowed, err := pe.Evaluate("(5:token (3:tac 1:r))")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !allowed {
		t.Error("expected query to be allowed")
	}
}

func TestSPOCPEngine_Deny(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "test.rules")
	// Rule: only allow tac=r
	err := os.WriteFile(rulesFile, []byte("(5:token (3:tac 1:r))\n"), 0600)
	if err != nil {
		t.Fatalf("write rules: %v", err)
	}

	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir: %v", err)
	}

	// Query asking for write — should be denied.
	allowed, err := pe.Evaluate("(5:token (3:tac 1:w))")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if allowed {
		t.Error("expected query to be denied")
	}
}

func TestSPOCPEngine_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir on empty dir: %v", err)
	}
	if pe.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", pe.RuleCount())
	}
}

func TestSPOCPEngine_SkipsNonRuleFiles(t *testing.T) {
	dir := t.TempDir()
	// Write a .txt file — should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not rules"), 0600); err != nil {
		t.Fatal(err)
	}
	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir: %v", err)
	}
	if pe.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", pe.RuleCount())
	}
}

func TestAllowAllPolicy(t *testing.T) {
	p := AllowAllPolicy{}
	allowed, err := p.Evaluate("anything")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("AllowAllPolicy should always allow")
	}
	if p.RuleCount() != 0 {
		t.Error("AllowAllPolicy should have 0 rules")
	}
}
