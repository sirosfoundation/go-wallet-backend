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
