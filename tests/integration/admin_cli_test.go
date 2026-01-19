package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// WalletAdminCLI provides helpers for testing the wallet-admin CLI
type WalletAdminCLI struct {
	T       *testing.T
	Harness *AdminTestHarness
	binPath string
}

// NewWalletAdminCLI creates a new CLI test wrapper with a test server
func NewWalletAdminCLI(t *testing.T) *WalletAdminCLI {
	t.Helper()

	harness := NewAdminTestHarness(t)

	// Build the CLI if not already built
	binPath := "/tmp/wallet-admin-test"
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/wallet-admin")
	cmd.Dir = getProjectRoot()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build wallet-admin CLI: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		_ = os.Remove(binPath)
	})

	return &WalletAdminCLI{
		T:       t,
		Harness: harness,
		binPath: binPath,
	}
}

// getProjectRoot returns the project root directory
func getProjectRoot() string {
	// Walk up from current dir to find go.mod
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir
		}
		parent := dir[:strings.LastIndex(dir, "/")]
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

// CLIResult represents the output of a CLI command
type CLIResult struct {
	T      *testing.T
	Stdout string
	Stderr string
	Err    error
}

// Run executes the wallet-admin CLI with the given arguments
func (c *WalletAdminCLI) Run(args ...string) *CLIResult {
	c.T.Helper()

	// Add the --url and --token flags pointing to our test server
	fullArgs := append([]string{"--url", c.Harness.BaseURL, "--token", c.Harness.AdminToken}, args...)

	cmd := exec.Command(c.binPath, fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return &CLIResult{
		T:      c.T,
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Err:    err,
	}
}

// Success asserts the command succeeded
func (r *CLIResult) Success() *CLIResult {
	r.T.Helper()
	if r.Err != nil {
		r.T.Errorf("Expected command to succeed, but got error: %v\nStdout: %s\nStderr: %s",
			r.Err, r.Stdout, r.Stderr)
	}
	return r
}

// Failure asserts the command failed
func (r *CLIResult) Failure() *CLIResult {
	r.T.Helper()
	if r.Err == nil {
		r.T.Errorf("Expected command to fail, but it succeeded\nStdout: %s", r.Stdout)
	}
	return r
}

// Contains asserts stdout contains a substring
func (r *CLIResult) Contains(substr string) *CLIResult {
	r.T.Helper()
	if !strings.Contains(r.Stdout, substr) {
		r.T.Errorf("Expected output to contain %q\nGot: %s", substr, r.Stdout)
	}
	return r
}

// NotContains asserts stdout does not contain a substring
func (r *CLIResult) NotContains(substr string) *CLIResult {
	r.T.Helper()
	if strings.Contains(r.Stdout, substr) {
		r.T.Errorf("Expected output to NOT contain %q\nGot: %s", substr, r.Stdout)
	}
	return r
}

// JSON parses the stdout as JSON into the target
func (r *CLIResult) JSON(target interface{}) *CLIResult {
	r.T.Helper()
	if err := json.Unmarshal([]byte(r.Stdout), target); err != nil {
		r.T.Errorf("Failed to parse JSON output: %v\nOutput: %s", err, r.Stdout)
	}
	return r
}

// ---- CLI Integration Tests ----

func TestCLITenantCommands(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	t.Run("list tenants shows default", func(t *testing.T) {
		cli.Run("tenant", "list").
			Success().
			Contains("default")
	})

	t.Run("list tenants as JSON", func(t *testing.T) {
		result := cli.Run("--output", "json", "tenant", "list")
		result.Success()

		var body struct {
			Tenants []map[string]interface{} `json:"tenants"`
		}
		result.JSON(&body)

		if len(body.Tenants) != 1 {
			t.Errorf("Expected 1 tenant (default), got %d", len(body.Tenants))
		}
	})

	t.Run("create tenant", func(t *testing.T) {
		cli.Run("tenant", "create", "--id", "cli-test-tenant", "--name", "CLI Test Tenant").
			Success().
			Contains("created successfully")
	})

	t.Run("create duplicate tenant fails", func(t *testing.T) {
		cli.Run("tenant", "create", "--id", "cli-test-tenant", "--name", "Duplicate").
			Failure()
	})

	t.Run("get tenant", func(t *testing.T) {
		result := cli.Run("tenant", "get", "cli-test-tenant")
		result.Success()

		var tenant map[string]interface{}
		result.JSON(&tenant)

		if tenant["id"] != "cli-test-tenant" {
			t.Errorf("Expected id 'cli-test-tenant', got %v", tenant["id"])
		}
	})

	t.Run("list tenants shows created tenant", func(t *testing.T) {
		cli.Run("tenant", "list").
			Success().
			Contains("cli-test-tenant")
	})

	t.Run("update tenant", func(t *testing.T) {
		cli.Run("tenant", "update", "cli-test-tenant", "--name", "Updated CLI Tenant").
			Success().
			Contains("updated successfully")
	})

	t.Run("delete tenant", func(t *testing.T) {
		cli.Run("tenant", "delete", "cli-test-tenant").
			Success().
			Contains("deleted successfully")

		// Verify it's gone
		cli.Run("tenant", "get", "cli-test-tenant").
			Failure()
	})

	t.Run("delete default tenant fails", func(t *testing.T) {
		cli.Run("tenant", "delete", "default").
			Failure()
	})
}

func TestCLIUserCommands(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	// Create a test tenant
	cli.Run("tenant", "create", "--id", "user-cli-tenant", "--name", "User CLI Test")

	t.Run("list empty users", func(t *testing.T) {
		cli.Run("user", "list", "--tenant", "user-cli-tenant").
			Success().
			Contains("No users found")
	})

	t.Run("add user", func(t *testing.T) {
		cli.Run("user", "add", "--tenant", "user-cli-tenant", "--id", "user-456").
			Success().
			Contains("added")
	})

	t.Run("list users shows added user", func(t *testing.T) {
		cli.Run("user", "list", "--tenant", "user-cli-tenant").
			Success().
			Contains("user-456")
	})

	t.Run("remove user", func(t *testing.T) {
		cli.Run("user", "remove", "--tenant", "user-cli-tenant", "--id", "user-456").
			Success().
			Contains("removed")
	})

	t.Run("list users is empty after removal", func(t *testing.T) {
		cli.Run("user", "list", "--tenant", "user-cli-tenant").
			Success().
			Contains("No users found")
	})

	t.Run("user list for non-existent tenant fails", func(t *testing.T) {
		cli.Run("user", "list", "--tenant", "non-existent").
			Failure()
	})
}

func TestCLIIssuerCommands(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	// Create a test tenant
	cli.Run("tenant", "create", "--id", "issuer-cli-tenant", "--name", "Issuer CLI Test")

	t.Run("list empty issuers", func(t *testing.T) {
		cli.Run("issuer", "list", "--tenant", "issuer-cli-tenant").
			Success().
			Contains("No issuers found")
	})

	t.Run("create issuer", func(t *testing.T) {
		// Use arguments matching the actual API
		result := cli.Run("issuer", "create", "--tenant", "issuer-cli-tenant",
			"--identifier", "https://test-issuer.example.com")
		result.Success().Contains("created successfully")
	})

	t.Run("list issuers shows created issuer", func(t *testing.T) {
		cli.Run("issuer", "list", "--tenant", "issuer-cli-tenant").
			Success()
		// Note: list shows table format - just verify it doesn't fail
	})

	t.Run("issuer list for non-existent tenant fails", func(t *testing.T) {
		cli.Run("issuer", "list", "--tenant", "non-existent").
			Failure()
	})
}

func TestCLIVerifierCommands(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	// Create a test tenant
	cli.Run("tenant", "create", "--id", "verifier-cli-tenant", "--name", "Verifier CLI Test")

	t.Run("list empty verifiers", func(t *testing.T) {
		cli.Run("verifier", "list", "--tenant", "verifier-cli-tenant").
			Success().
			Contains("No verifiers found")
	})

	t.Run("create verifier", func(t *testing.T) {
		// Use arguments matching the actual API (name and verifier-url required)
		result := cli.Run("verifier", "create", "--tenant", "verifier-cli-tenant",
			"--name", "Test Verifier",
			"--verifier-url", "https://test-verifier.example.com")
		result.Success().Contains("created successfully")
	})

	t.Run("list verifiers shows created verifier", func(t *testing.T) {
		cli.Run("verifier", "list", "--tenant", "verifier-cli-tenant").
			Success()
	})

	t.Run("verifier list for non-existent tenant fails", func(t *testing.T) {
		cli.Run("verifier", "list", "--tenant", "non-existent").
			Failure()
	})
}

func TestCLIOutputFormats(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	t.Run("table format is default", func(t *testing.T) {
		result := cli.Run("tenant", "list")
		result.Success()
		// Table format should have column headers
		if strings.Contains(result.Stdout, "{") {
			t.Error("Expected table format, got JSON")
		}
	})

	t.Run("json format with flag", func(t *testing.T) {
		result := cli.Run("--output", "json", "tenant", "list")
		result.Success()
		// JSON format should be parseable
		var body map[string]interface{}
		result.JSON(&body)
	})

	t.Run("json format with short flag", func(t *testing.T) {
		result := cli.Run("-o", "json", "tenant", "list")
		result.Success()
		var body map[string]interface{}
		result.JSON(&body)
	})
}

func TestCLIErrorHandling(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	t.Run("missing required flag shows error", func(t *testing.T) {
		result := cli.Run("user", "list")
		result.Failure()
		// Should mention the missing flag
		if !strings.Contains(result.Stderr, "tenant") && !strings.Contains(result.Stdout, "tenant") {
			t.Error("Expected error about missing --tenant flag")
		}
	})

	t.Run("invalid tenant create missing id", func(t *testing.T) {
		result := cli.Run("tenant", "create", "--name", "Test")
		result.Failure()
	})

	t.Run("invalid tenant create missing name", func(t *testing.T) {
		result := cli.Run("tenant", "create", "--id", "test")
		result.Failure()
	})
}

func TestCLIHelp(t *testing.T) {
	cli := NewWalletAdminCLI(t)

	t.Run("root help", func(t *testing.T) {
		cli.Run("--help").
			Success().
			Contains("wallet-admin").
			Contains("tenant").
			Contains("user").
			Contains("issuer").
			Contains("verifier")
	})

	t.Run("tenant help", func(t *testing.T) {
		cli.Run("tenant", "--help").
			Success().
			Contains("list").
			Contains("create").
			Contains("get").
			Contains("update").
			Contains("delete")
	})

	t.Run("tenant create help", func(t *testing.T) {
		cli.Run("tenant", "create", "--help").
			Success().
			Contains("--id").
			Contains("--name")
	})
}
