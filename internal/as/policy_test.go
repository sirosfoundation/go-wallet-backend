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
	// Rule: allow any token request with tac=r. Rules are loaded in
	// go-spocp's advanced form, not canonical netstring form - see the
	// comment on LoadRulesFromDir's opts.Format for why. The leading
	// (aud (*)) matters, not just tac=r: BuildTokenQuery always emits aud
	// as the (alphabetically) first field, and SPOCP compares rule vs
	// query elements positionally, so a rule missing that leading field
	// would silently never match a real query.
	err := os.WriteFile(rulesFile, []byte("(token (aud (*)) (tac r))\n"), 0600)
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

	// Query is still evaluated in canonical form - only rule *files* use
	// advanced form; BuildTokenQuery emits canonical form and that's what
	// reaches Evaluate() in production. Build it via BuildTokenQuery
	// (rather than a hand-rolled netstring) so the query has the same
	// aud-then-tac shape a real read-only request produces.
	allowed, err := pe.Evaluate(BuildTokenQuery("", "wallet-backend", "", TAC("r"), ""))
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
	// Rule: only allow tac=r. Leading (aud (*)) is required for the same
	// positional-alignment reason as TestSPOCPEngine_LoadAndEvaluate.
	err := os.WriteFile(rulesFile, []byte("(token (aud (*)) (tac r))\n"), 0600)
	if err != nil {
		t.Fatalf("write rules: %v", err)
	}

	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir: %v", err)
	}

	// Query asking for write — should be denied.
	allowed, err := pe.Evaluate(BuildTokenQuery("", "wallet-backend", "", TAC("w"), ""))
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

// The shipped default rules (rules/default.rules, rules/delegation.rules)
// are the baseline AS.RulesDir configuration ships and defaults to, and
// what the Dockerfile ships alongside the binary - nothing else ever loaded
// them from a real checkout, so neither a plain syntax error nor a
// silently-inert wildcard (see TestSPOCPEngine_WildcardsFromFileActuallyMatch)
// went undetected until a real deploy started denying every token request.
func TestSPOCPEngine_LoadsShippedDefaultRules(t *testing.T) {
	dir := shippedRulesDir(t)
	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir(%q): %v", dir, err)
	}
	if pe.RuleCount() == 0 {
		t.Error("expected at least one rule loaded from the shipped rules directory")
	}

	// Exercise the shipped rules against realistic BuildTokenQuery shapes -
	// RuleCount() alone can't catch a wildcard that parses but never matches.
	for _, q := range []struct {
		name  string
		query string
	}{
		{"passkey session, read-only", BuildTokenQuery("user-1", "wallet-backend", "default", TAC("rl"), "urn:siros:acr:passkey")},
		{"session, no acr, read-only", BuildTokenQuery("user-1", "wallet-backend", "default", TAC("r"), "")},
		// "Anonymous" still requires acr - it identifies an already-authenticated
		// session, just one whose token omits "sub". See handleAnonymousTokenRequest.
		{"anonymous (identity-free, session-backed), read-only", BuildTokenQuery("", "wallet-backend", "default", TAC("r"), "urn:siros:acr:passkey")},
	} {
		allowed, err := pe.Evaluate(q.query)
		if err != nil {
			t.Fatalf("%s: Evaluate: %v", q.name, err)
		}
		if !allowed {
			t.Errorf("%s: expected query %q to be allowed by shipped default rules", q.name, q.query)
		}
	}
}

// Regression test for a real Copilot review finding, since superseded by a
// deeper fix: the shipped anonymous (shape C) rules originally didn't
// constrain tenant_id at all, and anonymous requests had no session to
// enforce a tenant match in code either - so an anonymous caller could
// request tenant_id="*" (or any other tenant) and get a read-only token for
// it. The actual fix was to stop treating "anonymous" as unauthenticated at
// all: handleAnonymousTokenRequest now requires the same real session as
// shape A/B, so tenant scoping can be enforced the exact same way shape A/B
// already do it - in code (session.TenantID must match, unless the session
// itself is cross-tenant) - rather than needing the SPOCP rule to pin
// tenant_id to a literal value. At the policy layer alone, tenant_id is
// therefore correctly a wildcard for shape C now, exactly like shape A/B;
// this test documents that and exists mainly to make the "why" traceable
// for a future reader who might otherwise "fix" the wildcard back to a
// literal. The actual enforcement is covered at the HTTP-handler level by
// TestTokenEndpoint_Anonymous_CrossTenantDenied and
// TestTokenEndpoint_Anonymous_NoSessionDenied.
func TestSPOCPEngine_AnonymousShapeTenantIDIsWildcardLikeOtherShapes(t *testing.T) {
	dir := shippedRulesDir(t)
	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir(%q): %v", dir, err)
	}

	for _, tenantID := range []string{"default", "some-other-tenant", "*"} {
		query := BuildTokenQuery("", "wallet-backend", tenantID, TAC("r"), "urn:siros:acr:passkey")
		allowed, err := pe.Evaluate(query)
		if err != nil {
			t.Fatalf("tenant_id=%s: Evaluate: %v", tenantID, err)
		}
		if !allowed {
			t.Errorf("tenant_id=%s: query %q allowed=false, want true (tenant scoping is enforced in code, not by this rule)", tenantID, query)
		}
	}
}

// Regression test for a design gap found alongside the tenant_id fix above:
// the shipped anonymous (shape C) rules previously left `aud` unconstrained
// too ((aud (*))), so an anonymous, wholly unauthenticated caller could mint
// a read-only token for literally any audience just by asking for it - not
// just the specific purposes anonymous access is meant for (trust
// evaluation, engine transport). `aud` is now a specific enumerated set
// (wallet-registry, plus wallet-backend kept temporarily so already-deployed
// clients requesting the old value keep working during migration - see the
// comment in rules/default.rules) rather than a wildcard.
func TestSPOCPEngine_AnonymousRequestsRejectUnlistedAudience(t *testing.T) {
	dir := shippedRulesDir(t)
	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir(%q): %v", dir, err)
	}

	for _, q := range []struct {
		name     string
		audience string
		wantOK   bool
	}{
		{"wallet-registry allowed (intended long-term audience)", "wallet-registry", true},
		{"wallet-backend allowed (transitional back-compat)", "wallet-backend", true},
		{"wallet-engine denied (not a listed anonymous purpose)", "wallet-engine", false},
		{"arbitrary unlisted audience denied", "some-other-service", false},
	} {
		query := BuildTokenQuery("", q.audience, "default", TAC("r"), "urn:siros:acr:passkey")
		allowed, err := pe.Evaluate(query)
		if err != nil {
			t.Fatalf("%s: Evaluate: %v", q.name, err)
		}
		if allowed != q.wantOK {
			t.Errorf("%s: query %q allowed=%v, want %v", q.name, query, allowed, q.wantOK)
		}
	}
}

// Regression test for a bug where rule files were loaded with go-spocp's
// canonical (netstring) format, under which a literal "(1:*)" parses as an
// ordinary empty list tagged "*" rather than a starform.Wildcard - so
// IsStarForm() never returns true and the "wildcard" never matches anything,
// even though the file loads without error and RuleCount() looks correct.
// Only go-spocp's advanced-form parser (persist.FormatAdvanced) actually
// constructs a real starform.Wildcard for a bare "(*)".
func TestSPOCPEngine_WildcardsFromFileActuallyMatch(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "wildcard.rules")
	// Leading (aud (*)) matches the shape BuildTokenQuery actually emits;
	// see the positional-alignment note in TestSPOCPEngine_LoadAndEvaluate.
	if err := os.WriteFile(rulesFile, []byte("(token (aud (*)) (tac (*)))\n"), 0600); err != nil {
		t.Fatal(err)
	}

	pe := NewSPOCPEngine(zap.NewNop())
	if err := pe.LoadRulesFromDir(dir); err != nil {
		t.Fatalf("LoadRulesFromDir: %v", err)
	}

	allowed, err := pe.Evaluate(BuildTokenQuery("", "wallet-backend", "", TAC("rw"), ""))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !allowed {
		t.Error("expected a file-loaded wildcard rule to match any tac value")
	}
}

func shippedRulesDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("shipped rules directory not found at %s: %v", dir, err)
	}
	return dir
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
