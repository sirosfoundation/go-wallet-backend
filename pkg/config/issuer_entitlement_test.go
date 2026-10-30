package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadWithYAML(t *testing.T, extra string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	body := `server:
  port: 8080
  rp_id: localhost
  rp_origin: http://localhost:8080
storage:
  type: memory
jwt:
  secret: test-secret-that-is-at-least-32-bytes-long
` + extra
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func hasWarning(c *Config, sub string) bool {
	for _, w := range c.Warnings() {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestIssuerEntitlementMode(t *testing.T) {
	t.Run("unset is empty (warn at run time) and does not warn", func(t *testing.T) {
		cfg, err := loadWithYAML(t, "")
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.EffectiveIssuerEntitlementMode(); got != "" {
			t.Errorf("default = %q, want unset (issuertrust.ParseMode maps it to warn)", got)
		}
		if hasWarning(cfg, "issuer_entitlement_mode") {
			t.Error("an unset mode must not warn")
		}
	})
	t.Run("new key", func(t *testing.T) {
		cfg, err := loadWithYAML(t, "trust:\n  issuer_entitlement_mode: fail\n")
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.EffectiveIssuerEntitlementMode(); got != "fail" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("old key still works and warns", func(t *testing.T) {
		cfg, err := loadWithYAML(t, "authzen_proxy:\n  issuer_entitlement_mode: fail\n")
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.EffectiveIssuerEntitlementMode(); got != "fail" {
			t.Errorf("alias not honoured: %q", got)
		}
		if !hasWarning(cfg, "deprecated") {
			t.Error("using the deprecated key must warn at startup")
		}
	})
	t.Run("new key wins over the old", func(t *testing.T) {
		cfg, err := loadWithYAML(t, "trust:\n  issuer_entitlement_mode: off\nauthzen_proxy:\n  issuer_entitlement_mode: fail\n")
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.EffectiveIssuerEntitlementMode(); got != "off" {
			t.Errorf("got %q, want the new key's value", got)
		}
		if hasWarning(cfg, "deprecated") {
			t.Error("no deprecation warning when the new key is set")
		}
	})
	t.Run("environment variables", func(t *testing.T) {
		t.Setenv("WALLET_TRUST_ISSUER_ENTITLEMENT_MODE", "fail")
		cfg, err := loadWithYAML(t, "")
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.EffectiveIssuerEntitlementMode(); got != "fail" {
			t.Errorf("new env var: %q", got)
		}
	})
	t.Run("old environment variable", func(t *testing.T) {
		t.Setenv("WALLET_AUTHZEN_PROXY_ISSUER_ENTITLEMENT_MODE", "off")
		cfg, err := loadWithYAML(t, "")
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.EffectiveIssuerEntitlementMode(); got != "off" || !hasWarning(cfg, "deprecated") {
			t.Errorf("old env var: %q, warned=%v", got, hasWarning(cfg, "deprecated"))
		}
	})
	// Unknown values refuse to start: at run time they would be read as warn,
	// which is safe but silent, and the operator who typed "fial" believes the
	// check refuses.
	t.Run("unknown value is a startup error", func(t *testing.T) {
		for _, extra := range []string{
			"trust:\n  issuer_entitlement_mode: fial\n",
			"authzen_proxy:\n  issuer_entitlement_mode: FAIL\n",
		} {
			if _, err := loadWithYAML(t, extra); err == nil || !strings.Contains(err.Error(), "issuer entitlement mode") {
				t.Errorf("%q: err = %v, want an invalid-mode error", extra, err)
			}
		}
	})
}
