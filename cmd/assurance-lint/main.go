// Command assurance-lint checks an assurance policy rules file.
//
//	assurance-lint -rules deploy/assurance/production.rules.example
//	assurance-lint -config config.yaml
//
// With -config the rules file and level schemes come from the YAML's
// wallet_provider.attestation.assurance section (read alone, so -rules can
// override a rules_file that would not validate); with -rules alone the built-in
// iso_18045 scheme is assumed. Exit status is 1 when any ERROR is found.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/go-wallet-backend/internal/assurance"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	printf := func(w io.Writer, format string, a ...interface{}) { _, _ = fmt.Fprintf(w, format, a...) }
	fs := flag.NewFlagSet("assurance-lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rules := fs.String("rules", "", "path to the rules file (overrides the configured one)")
	cfgFile := fs.String("config", "", "backend configuration file supplying schemes and the catalogue")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := config.AssuranceConfig{
		KeyStorageScheme:         config.DefaultLevelSchemeID,
		UserAuthenticationScheme: config.DefaultLevelSchemeID,
	}
	if *cfgFile != "" {
		// Read only the assurance section from the YAML. config.Load would
		// validate the whole configuration first and reject a config whose
		// rules_file is the very thing -rules is meant to replace.
		loaded, err := readAssuranceConfig(*cfgFile, cfg)
		if err != nil {
			printf(stderr, "load config: %v\n", err)
			return 2
		}
		cfg = loaded
	}
	if *rules != "" {
		cfg.RulesFile = *rules
	}
	if cfg.RulesFile == "" {
		printf(stderr, "no rules file: pass -rules or a -config that sets wallet_provider.attestation.assurance.rules_file\n")
		return 2
	}
	// Lint a file regardless of whether the policy is enabled in the config.
	cfg.Enabled = true
	if err := cfg.Validate(); err != nil {
		printf(stderr, "ERROR: %v\n", err)
		return 1
	}

	rs, err := assurance.LoadRuleSet(cfg.RulesFile)
	if err != nil {
		printf(stderr, "ERROR: %v\n", err)
		return 1
	}
	findings := append(assurance.LintRuleSet(rs, &cfg), assurance.LintConfig(cfg)...)
	for _, f := range findings {
		printf(stdout, "%s\n", f)
	}
	printf(stdout, "%s: %d rules, schema version %d, policy hash %s, %d finding(s)\n",
		rs.Path, len(rs.Rules), assurance.SchemaVersion, rs.PolicyVersion, len(findings))
	if assurance.HasErrors(findings) {
		return 1
	}
	return 0
}

// readAssuranceConfig overlays wallet_provider.attestation.assurance from a
// YAML file onto base (the defaults) without validating anything.
func readAssuranceConfig(path string, base config.AssuranceConfig) (config.AssuranceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return base, err
	}
	var doc struct {
		WalletProvider struct {
			Attestation struct {
				Assurance config.AssuranceConfig `yaml:"assurance"`
			} `yaml:"attestation"`
		} `yaml:"wallet_provider"`
	}
	// A value (not a pointer): an explicit `assurance:` null then leaves
	// the defaults in place instead of nil-ing the section.
	doc.WalletProvider.Attestation.Assurance = base
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return base, err
	}
	return doc.WalletProvider.Attestation.Assurance, nil
}
