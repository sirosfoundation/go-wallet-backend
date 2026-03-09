package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSyncConfig writes a YAML config file to a temp directory and returns the path.
func writeSyncConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tenants.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write sync config: %v", err)
	}
	return path
}

func TestCLISyncCreateTenants(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	cfg := writeSyncConfig(t, `
tenants:
  - id: sync-tenant-1
    name: Sync Tenant 1
    display_name: Sync T1
    enabled: true
    issuers:
      - credential_issuer_identifier: https://issuer-1.example.com
        client_id: client-1
        visible: true
    verifiers:
      - name: Verifier 1
        url: https://verifier-1.example.com
  - id: sync-tenant-2
    name: Sync Tenant 2
`)

	t.Run("dry-run shows creates", func(t *testing.T) {
		result := cli.Run("sync", "--config", cfg, "--dry-run")
		result.Success()
		result.Contains("Dry-run")
		result.Contains("sync-tenant-1")
		result.Contains("sync-tenant-2")
		result.Contains("created")

		// Dry-run should NOT actually create tenants
		cli.Run("tenant", "get", "sync-tenant-1").Failure()
	})

	t.Run("apply creates tenants with issuers and verifiers", func(t *testing.T) {
		result := cli.Run("sync", "--config", cfg)
		result.Success()
		result.Contains("created")

		// Verify tenants exist
		cli.Run("tenant", "get", "sync-tenant-1").Success()
		cli.Run("tenant", "get", "sync-tenant-2").Success()

		// Verify issuer was created
		cli.Run("issuer", "list", "--tenant", "sync-tenant-1").
			Success()

		// Verify verifier was created
		cli.Run("verifier", "list", "--tenant", "sync-tenant-1").
			Success()
	})

	t.Run("re-run is idempotent (all unchanged)", func(t *testing.T) {
		result := cli.Run("sync", "--config", cfg)
		result.Success()
		result.Contains("unchanged")
		// Should not show any creates
		if strings.Count(result.Stdout, "+ tenant") > 0 || strings.Count(result.Stdout, "+ issuer") > 0 {
			t.Error("expected no creates on re-run")
		}
	})
}

func TestCLISyncUpdateTenants(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	// First sync: create initial state
	initialCfg := writeSyncConfig(t, `
tenants:
  - id: update-tenant
    name: Original Name
    display_name: Original Display
    enabled: true
    issuers:
      - credential_issuer_identifier: https://issuer.example.com
        client_id: old-client
        visible: true
    verifiers:
      - name: Original Verifier
        url: https://original-verifier.example.com
`)
	cli.Run("sync", "--config", initialCfg).Success()

	// Second sync: update everything
	updatedCfg := writeSyncConfig(t, `
tenants:
  - id: update-tenant
    name: Updated Name
    display_name: Updated Display
    enabled: true
    issuers:
      - credential_issuer_identifier: https://issuer.example.com
        client_id: new-client
        visible: true
    verifiers:
      - name: Original Verifier
        url: https://updated-verifier.example.com
`)

	t.Run("sync detects and applies updates", func(t *testing.T) {
		result := cli.Run("sync", "--config", updatedCfg)
		result.Success()
		result.Contains("update")

		// Verify tenant was updated
		getResult := cli.Run("-o", "json", "tenant", "get", "update-tenant")
		getResult.Success()
		var tenant map[string]interface{}
		getResult.JSON(&tenant)
		if tenant["name"] != "Updated Name" {
			t.Errorf("expected updated name, got %v", tenant["name"])
		}
		if tenant["display_name"] != "Updated Display" {
			t.Errorf("expected updated display_name, got %v", tenant["display_name"])
		}
	})
}

func TestCLISyncPrune(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	// Create tenants with issuers and verifiers via sync
	fullCfg := writeSyncConfig(t, `
tenants:
  - id: prune-tenant
    name: Prune Tenant
    issuers:
      - credential_issuer_identifier: https://keep-issuer.example.com
      - credential_issuer_identifier: https://remove-issuer.example.com
    verifiers:
      - name: Keep Verifier
        url: https://keep.example.com
      - name: Remove Verifier
        url: https://remove.example.com
`)
	cli.Run("sync", "--config", fullCfg).Success()

	// Sync with reduced set + --prune
	reducedCfg := writeSyncConfig(t, `
tenants:
  - id: prune-tenant
    name: Prune Tenant
    issuers:
      - credential_issuer_identifier: https://keep-issuer.example.com
    verifiers:
      - name: Keep Verifier
        url: https://keep.example.com
`)

	t.Run("without prune keeps extras", func(t *testing.T) {
		result := cli.Run("sync", "--config", reducedCfg)
		result.Success()
		// Should not show any deletes
		if strings.Contains(result.Stdout, "- issuer") || strings.Contains(result.Stdout, "- verifier") {
			t.Error("expected no deletes without --prune")
		}
	})

	t.Run("with prune removes extras", func(t *testing.T) {
		result := cli.Run("sync", "--config", reducedCfg, "--prune")
		result.Success()
		result.Contains("deleted")

		// Verify only one issuer remains
		issResult := cli.Run("-o", "json", "issuer", "list", "--tenant", "prune-tenant")
		issResult.Success()
		var issResp struct {
			Issuers []map[string]interface{} `json:"issuers"`
		}
		issResult.JSON(&issResp)
		if len(issResp.Issuers) != 1 {
			t.Errorf("expected 1 issuer after prune, got %d", len(issResp.Issuers))
		}

		// Verify only one verifier remains
		vResult := cli.Run("-o", "json", "verifier", "list", "--tenant", "prune-tenant")
		vResult.Success()
		var vResp struct {
			Verifiers []map[string]interface{} `json:"verifiers"`
		}
		vResult.JSON(&vResp)
		if len(vResp.Verifiers) != 1 {
			t.Errorf("expected 1 verifier after prune, got %d", len(vResp.Verifiers))
		}
	})
}

func TestCLISyncPruneTenants(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	// Create two tenants
	initialCfg := writeSyncConfig(t, `
tenants:
  - id: stay-tenant
    name: Stay Tenant
  - id: go-tenant
    name: Go Tenant
`)
	cli.Run("sync", "--config", initialCfg).Success()

	// Sync with only one tenant + prune
	reducedCfg := writeSyncConfig(t, `
tenants:
  - id: stay-tenant
    name: Stay Tenant
`)

	t.Run("prune removes tenant not in config", func(t *testing.T) {
		result := cli.Run("sync", "--config", reducedCfg, "--prune")
		result.Success()
		result.Contains("delete")

		// go-tenant should be gone
		cli.Run("tenant", "get", "go-tenant").Failure()

		// stay-tenant should still exist
		cli.Run("tenant", "get", "stay-tenant").Success()
	})
}

func TestCLISyncDefaultTenantNotPruned(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	// Config with a non-default tenant
	cfg := writeSyncConfig(t, `
tenants:
  - id: other-tenant
    name: Other Tenant
`)

	t.Run("prune never removes default tenant", func(t *testing.T) {
		cli.Run("sync", "--config", cfg, "--prune").Success()

		// Default tenant should still exist
		cli.Run("tenant", "get", "default").Success()
	})
}

func TestCLISyncDryRunNoSideEffects(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	cfg := writeSyncConfig(t, `
tenants:
  - id: dry-run-tenant
    name: Dry Run Tenant
    issuers:
      - credential_issuer_identifier: https://dry-issuer.example.com
    verifiers:
      - name: Dry Verifier
        url: https://dry-verifier.example.com
`)

	t.Run("dry-run creates nothing", func(t *testing.T) {
		result := cli.Run("sync", "--config", cfg, "--dry-run")
		result.Success()
		result.Contains("Dry-run")
		result.Contains("created")

		// Nothing should exist
		cli.Run("tenant", "get", "dry-run-tenant").Failure()
	})
}

func TestCLISyncValidationErrors(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	t.Run("missing config flag", func(t *testing.T) {
		cli.Run("sync").Failure()
	})

	t.Run("non-existent config file", func(t *testing.T) {
		cli.Run("sync", "--config", "/tmp/nonexistent-file-12345.yaml").Failure()
	})

	t.Run("empty tenants list", func(t *testing.T) {
		cfg := writeSyncConfig(t, `tenants: []`)
		cli.Run("sync", "--config", cfg).Failure()
	})

	t.Run("missing tenant name", func(t *testing.T) {
		cfg := writeSyncConfig(t, `
tenants:
  - id: bad-tenant
`)
		cli.Run("sync", "--config", cfg).Failure()
	})

	t.Run("duplicate tenant id", func(t *testing.T) {
		cfg := writeSyncConfig(t, `
tenants:
  - id: dup
    name: First
  - id: dup
    name: Second
`)
		cli.Run("sync", "--config", cfg).Failure()
	})

	t.Run("missing issuer identifier", func(t *testing.T) {
		cfg := writeSyncConfig(t, `
tenants:
  - id: bad
    name: Bad
    issuers:
      - client_id: something
`)
		cli.Run("sync", "--config", cfg).Failure()
	})

	t.Run("missing verifier url", func(t *testing.T) {
		cfg := writeSyncConfig(t, `
tenants:
  - id: bad
    name: Bad
    verifiers:
      - name: No URL
`)
		cli.Run("sync", "--config", cfg).Failure()
	})
}

func TestCLISyncTrustConfig(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	cfg := writeSyncConfig(t, `
tenants:
  - id: trust-tenant
    name: Trust Tenant
    trust_config:
      trust_endpoint: https://trust.example.com/authzen
      trust_ttl: 3600
`)

	t.Run("sync creates tenant with trust config", func(t *testing.T) {
		result := cli.Run("sync", "--config", cfg)
		result.Success()
		result.Contains("created")

		// Verify tenant has trust config
		getResult := cli.Run("-o", "json", "tenant", "get", "trust-tenant")
		getResult.Success()
		var tenant map[string]interface{}
		getResult.JSON(&tenant)

		tc, ok := tenant["trust_config"].(map[string]interface{})
		if !ok {
			t.Fatal("expected trust_config in response")
		}
		if tc["trust_endpoint"] != "https://trust.example.com/authzen" {
			t.Errorf("unexpected trust_endpoint: %v", tc["trust_endpoint"])
		}
		ttl, _ := tc["trust_ttl"].(json.Number)
		if ttl.String() != "3600" {
			// Also check float64 (default JSON decode)
			ttlF, _ := tc["trust_ttl"].(float64)
			if ttlF != 3600 {
				t.Errorf("expected trust_ttl 3600, got %v", tc["trust_ttl"])
			}
		}
	})
}

func TestCLISyncMixedOperations(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	// Phase 1: Create initial state
	phase1 := writeSyncConfig(t, `
tenants:
  - id: mixed-tenant
    name: Mixed Tenant
    issuers:
      - credential_issuer_identifier: https://existing-issuer.example.com
        client_id: old-client
      - credential_issuer_identifier: https://to-remove-issuer.example.com
    verifiers:
      - name: Existing Verifier
        url: https://existing.example.com
`)
	cli.Run("sync", "--config", phase1).Success()

	// Phase 2: Mix of create, update, delete (with prune)
	phase2 := writeSyncConfig(t, `
tenants:
  - id: mixed-tenant
    name: Mixed Tenant Updated
    issuers:
      - credential_issuer_identifier: https://existing-issuer.example.com
        client_id: new-client
      - credential_issuer_identifier: https://brand-new-issuer.example.com
    verifiers:
      - name: Existing Verifier
        url: https://existing.example.com
      - name: New Verifier
        url: https://new.example.com
`)

	t.Run("mixed create update delete", func(t *testing.T) {
		result := cli.Run("sync", "--config", phase2, "--prune")
		result.Success()

		stdout := result.Stdout
		// Tenant should be updated (name changed)
		if !strings.Contains(stdout, "~ tenant") {
			t.Error("expected tenant update")
		}
		// New issuer should be created
		if !strings.Contains(stdout, "+ issuer") {
			t.Error("expected issuer create")
		}
		// to-remove-issuer should be deleted
		if !strings.Contains(stdout, "- issuer") {
			t.Error("expected issuer delete")
		}
		// New verifier should be created
		if !strings.Contains(stdout, "+ verifier") {
			t.Error("expected verifier create")
		}

		// Verify final state: 2 issuers, 2 verifiers
		issResult := cli.Run("-o", "json", "issuer", "list", "--tenant", "mixed-tenant")
		issResult.Success()
		var issResp struct {
			Issuers []map[string]interface{} `json:"issuers"`
		}
		issResult.JSON(&issResp)
		if len(issResp.Issuers) != 2 {
			t.Errorf("expected 2 issuers, got %d", len(issResp.Issuers))
		}

		vResult := cli.Run("-o", "json", "verifier", "list", "--tenant", "mixed-tenant")
		vResult.Success()
		var vResp struct {
			Verifiers []map[string]interface{} `json:"verifiers"`
		}
		vResult.JSON(&vResp)
		if len(vResp.Verifiers) != 2 {
			t.Errorf("expected 2 verifiers, got %d", len(vResp.Verifiers))
		}
	})
}

func TestCLISyncHelp(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	t.Run("sync help", func(t *testing.T) {
		cli.Run("sync", "--help").
			Success().
			Contains("--config").
			Contains("--dry-run").
			Contains("--prune").
			Contains("YAML")
	})
}
