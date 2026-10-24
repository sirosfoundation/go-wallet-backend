package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runLint(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	out, err1 := os.Create(filepath.Join(dir, "out"))
	errf, err2 := os.Create(filepath.Join(dir, "err"))
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	code := run(args, out, errf)
	out.Close()
	errf.Close()
	o, _ := os.ReadFile(out.Name())
	e, _ := os.ReadFile(errf.Name())
	return code, string(o), string(e)
}

func TestLintCLI_ShippedExamples(t *testing.T) {
	code, out, _ := runLint(t, "-rules", "../../deploy/assurance/production.rules.example")
	if code != 0 || !strings.Contains(out, "0 finding(s)") {
		t.Fatalf("production: %d %s", code, out)
	}
	code, out, _ = runLint(t, "-rules", "../../deploy/assurance/gdc-simulation.rules.example")
	if code != 0 || !strings.Contains(out, "gdc-soft-ks-high") {
		t.Fatalf("gdc: %d %s", code, out)
	}
}

func TestLintCLI_ErrorsExitNonZero(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.rules")
	if err := os.WriteFile(p, []byte("# id: dead\n(assure-ks (tier basic)(evidence (claimed (plugin soft))(verified)))\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runLint(t, "-rules", p)
	if code != 1 || !strings.Contains(out, "ERROR: rule dead") {
		t.Fatalf("%d %s", code, out)
	}

	bin := filepath.Join(t.TempDir(), "x.spocp")
	if err := os.WriteFile(bin, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := runLint(t, "-rules", bin); code != 1 || !strings.Contains(e, ".spocp") {
		t.Fatalf("%d %s", code, e)
	}
	if code, _, _ := runLint(t); code != 2 {
		t.Fatalf("no rules file must be a usage error, got %d", code)
	}
}

func TestLintCLI_ConfigWithoutRulesFileAcceptsRulesOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "c.yaml")
	// enabled with no rules_file: config.Load would reject this outright.
	if err := os.WriteFile(cfg, []byte("wallet_provider:\n  attestation:\n    assurance:\n      enabled: true\n      key_storage_scheme: tiers\n      level_schemes:\n        - {id: tiers, levels: [k3, k1], values: [sw, hw], floor: k3}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := filepath.Join(dir, "r.rules")
	if err := os.WriteFile(rules, []byte("# id: r\n(assure-ks (tier k1)(evidence))\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, e := runLint(t, "-config", cfg, "-rules", rules)
	if code != 0 {
		t.Fatalf("code %d out=%s err=%s", code, out, e)
	}
	// The configured scheme is in effect: a tier outside it is reported.
	if err := os.WriteFile(rules, []byte("# id: r\n(assure-ks (tier zzz)(evidence))\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, out, _ := runLint(t, "-config", cfg, "-rules", rules); !strings.Contains(out, `"zzz"`) {
		t.Fatalf("scheme from -config not applied: %s", out)
	}
	if code, _, _ := runLint(t, "-config", cfg); code != 2 {
		t.Fatalf("no rules file anywhere must be a usage error, got %d", code)
	}
}
