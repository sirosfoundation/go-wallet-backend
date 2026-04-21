package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func testVCTMJSON(vct, name string) []byte {
	m := map[string]interface{}{
		"vct":         vct,
		"name":        name,
		"description": "test credential",
		"claims":      []interface{}{},
	}
	b, _ := json.Marshal(m)
	return b
}

func TestLoadLocalOverrides_SingleFile(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "test.json")
	if err := os.WriteFile(fp, testVCTMJSON("urn:test:1", "Test Cred"), 0644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(filepath.Join(dir, "cache.json"))
	logger := zap.NewNop()

	if err := LoadLocalOverrides(store, []string{fp}, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry, ok := store.Get("urn:test:1")
	if !ok {
		t.Fatal("entry not found in store")
	}
	if !entry.IsLocal {
		t.Error("expected IsLocal=true")
	}
	if entry.Name != "Test Cred" {
		t.Errorf("Name = %q, want %q", entry.Name, "Test Cred")
	}
	if entry.Metadata == nil {
		t.Error("Metadata should not be nil")
	}
}

func TestLoadLocalOverrides_Directory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), testVCTMJSON("urn:test:a", "A"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), testVCTMJSON("urn:test:b", "B"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not json"), 0644); err != nil { // should be skipped
		t.Fatal(err)
	}

	store := NewStore(filepath.Join(dir, "cache.json"))
	logger := zap.NewNop()

	if err := LoadLocalOverrides(store, []string{dir}, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.Count() != 2 {
		t.Errorf("Count = %d, want 2", store.Count())
	}
	if _, ok := store.Get("urn:test:a"); !ok {
		t.Error("entry urn:test:a not found")
	}
	if _, ok := store.Get("urn:test:b"); !ok {
		t.Error("entry urn:test:b not found")
	}
}

func TestLoadLocalOverrides_SkipsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.json"), testVCTMJSON("urn:test:good", "Good"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not valid json"), 0644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(filepath.Join(dir, "cache.json"))
	logger := zap.NewNop()

	// Directory loading skips invalid files with a warning
	if err := LoadLocalOverrides(store, []string{dir}, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if store.Count() != 1 {
		t.Errorf("Count = %d, want 1", store.Count())
	}
}

func TestLoadLocalOverrides_MissingVCT(t *testing.T) {
	dir := t.TempDir()
	noVCT := []byte(`{"name": "no vct field"}`)
	if err := os.WriteFile(filepath.Join(dir, "novct.json"), noVCT, 0644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(filepath.Join(dir, "cache.json"))
	logger := zap.NewNop()

	// In directory mode, files without vct are skipped
	if err := LoadLocalOverrides(store, []string{dir}, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.Count() != 0 {
		t.Errorf("Count = %d, want 0", store.Count())
	}
}

func TestLoadLocalOverrides_FileError(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "cache.json"))
	logger := zap.NewNop()

	err := LoadLocalOverrides(store, []string{"/nonexistent/path"}, logger)
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestLocalOverrides_SurvivePolling(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "local.json")
	if err := os.WriteFile(fp, testVCTMJSON("urn:test:local", "Local"), 0644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(filepath.Join(dir, "cache.json"))
	logger := zap.NewNop()

	if err := LoadLocalOverrides(store, []string{fp}, logger); err != nil {
		t.Fatal(err)
	}

	// Simulate a remote poll that brings entries including a conflicting VCT
	remoteEntries := map[string]*VCTMEntry{
		"urn:test:remote": {
			VCT:  "urn:test:remote",
			Name: "Remote Only",
		},
		"urn:test:local": {
			VCT:  "urn:test:local",
			Name: "Remote Version",
		},
	}
	store.Update(remoteEntries, "https://example.com/registry.json")

	// Local entry should survive and override the remote one
	entry, ok := store.Get("urn:test:local")
	if !ok {
		t.Fatal("local entry lost after Update")
	}
	if !entry.IsLocal {
		t.Error("expected IsLocal=true after Update")
	}
	if entry.Name != "Local" {
		t.Errorf("Name = %q, want %q (local should override remote)", entry.Name, "Local")
	}

	// Remote-only entry should also be present
	if _, ok := store.Get("urn:test:remote"); !ok {
		t.Error("remote entry should be present")
	}
}

func TestLoadLocalOverrides_EmptyPaths(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "cache.json"))
	logger := zap.NewNop()

	if err := LoadLocalOverrides(store, []string{}, logger); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.Count() != 0 {
		t.Errorf("Count = %d, want 0", store.Count())
	}
}

func TestClearLocal_RemovesOnlyLocalEntries(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "cache.json"))

	// Add a local entry and a remote entry
	store.Put(&VCTMEntry{VCT: "urn:test:local", Name: "Local", IsLocal: true})
	store.Put(&VCTMEntry{VCT: "urn:test:remote", Name: "Remote"})
	store.Put(&VCTMEntry{VCT: "urn:test:dynamic", Name: "Dynamic", IsDynamic: true})

	if store.Count() != 3 {
		t.Fatalf("Count = %d, want 3", store.Count())
	}

	store.ClearLocal()

	if store.Count() != 2 {
		t.Errorf("Count = %d, want 2 after ClearLocal", store.Count())
	}
	if _, ok := store.Get("urn:test:local"); ok {
		t.Error("local entry should have been removed")
	}
	if _, ok := store.Get("urn:test:remote"); !ok {
		t.Error("remote entry should still be present")
	}
	if _, ok := store.Get("urn:test:dynamic"); !ok {
		t.Error("dynamic entry should still be present")
	}
}

func TestLoadLocalOverrides_ExtractsOrganization(t *testing.T) {
	dir := t.TempDir()

	data := []byte(`{"vct": "urn:test:org", "name": "Org Test", "description": "desc", "organization": "ACME Corp"}`)
	fp := filepath.Join(dir, "org.json")
	if err := os.WriteFile(fp, data, 0644); err != nil {
		t.Fatal(err)
	}

	store := NewStore(filepath.Join(dir, "cache.json"))
	logger := zap.NewNop()

	if err := LoadLocalOverrides(store, []string{fp}, logger); err != nil {
		t.Fatal(err)
	}

	entry, ok := store.Get("urn:test:org")
	if !ok {
		t.Fatal("entry not found")
	}
	if entry.Organization != "ACME Corp" {
		t.Errorf("Organization = %q, want %q", entry.Organization, "ACME Corp")
	}
}
