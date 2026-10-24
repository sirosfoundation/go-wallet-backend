package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validAssurance() AssuranceConfig {
	return AssuranceConfig{
		Enabled:                  true,
		RulesFile:                "/etc/wallet/assurance.rules",
		KeyStorageScheme:         DefaultLevelSchemeID,
		UserAuthenticationScheme: DefaultLevelSchemeID,
	}
}

func TestAssuranceConfig_DefaultsAreOffAndLowerByClaims(t *testing.T) {
	a := defaultConfig().WalletProvider.Attestation.Assurance
	if a.Enabled {
		t.Fatal("assurance must default to disabled")
	}
	if !a.LowerByClaimsKeyStorage || !a.LowerByClaimsUserAuthentication {
		t.Fatal("lower_by_claims must default to true")
	}
	if a.CertificationBasisInClaim {
		t.Fatal("certification_basis_in_claim must default to false")
	}
	if a.KeyStorageScheme != "iso_18045" || a.UserAuthenticationScheme != "iso_18045" {
		t.Fatalf("scheme defaults: %q %q", a.KeyStorageScheme, a.UserAuthenticationScheme)
	}
}

func TestAssuranceConfig_DisabledIsNeverInspected(t *testing.T) {
	a := AssuranceConfig{RulesFile: "bad.bin", KeyStorageScheme: "nope"}
	if err := a.Validate(); err != nil {
		t.Fatalf("disabled config must not block startup: %v", err)
	}
}

func TestAssuranceConfig_BuiltinSchemeOrderAndValues(t *testing.T) {
	s := BuiltinISO18045Scheme()
	if strings.Join(s.Levels, ",") != "basic,enhanced-basic,moderate,high" || s.Floor != "basic" {
		t.Fatalf("%+v", s)
	}
	for _, v := range s.Values {
		if !RegisteredAttackPotentialValues[v] {
			t.Errorf("%s is not a registered value", v)
		}
	}
	v := validAssurance()
	if err := v.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAssuranceConfig_ValidateFailsClosed(t *testing.T) {
	scheme := func(mut func(*LevelSchemeConfig)) AssuranceConfig {
		c := validAssurance()
		s := LevelSchemeConfig{ID: "s", Levels: []string{"a", "b"}, Values: []string{"va", "vb"}, Floor: "a"}
		mut(&s)
		c.LevelSchemes = LevelSchemeList{s}
		c.KeyStorageScheme = "s"
		return c
	}
	cases := map[string]AssuranceConfig{
		"no rules file": func() AssuranceConfig { c := validAssurance(); c.RulesFile = ""; return c }(),
		"spocp suffix":  func() AssuranceConfig { c := validAssurance(); c.RulesFile = "x.spocp"; return c }(),
		"bin suffix":    func() AssuranceConfig { c := validAssurance(); c.RulesFile = "x.BIN"; return c }(),
		"unknown scheme": func() AssuranceConfig {
			c := validAssurance()
			c.UserAuthenticationScheme = "ghost"
			return c
		}(),
		"no levels":         scheme(func(s *LevelSchemeConfig) { s.Levels, s.Values = nil, nil }),
		"values mismatch":   scheme(func(s *LevelSchemeConfig) { s.Values = []string{"va"} }),
		"duplicate level":   scheme(func(s *LevelSchemeConfig) { s.Levels = []string{"a", "a"} }),
		"duplicate value":   scheme(func(s *LevelSchemeConfig) { s.Values = []string{"v", "v"} }),
		"empty value":       scheme(func(s *LevelSchemeConfig) { s.Values = []string{"va", " "} }),
		"floor not level":   scheme(func(s *LevelSchemeConfig) { s.Floor = "zz" }),
		"no floor":          scheme(func(s *LevelSchemeConfig) { s.Floor = "" }),
		"ceiling not level": scheme(func(s *LevelSchemeConfig) { s.Ceiling = "zz" }),
		"ceiling below floor": scheme(func(s *LevelSchemeConfig) {
			s.Floor, s.Ceiling = "b", "a"
		}),
		"level with paren": scheme(func(s *LevelSchemeConfig) { s.Levels = []string{"a", "b)"} }),
		"level with star":  scheme(func(s *LevelSchemeConfig) { s.Levels = []string{"a", "*"} }),
		"duplicate scheme": func() AssuranceConfig {
			c := validAssurance()
			s := BuiltinISO18045Scheme()
			c.LevelSchemes = LevelSchemeList{s, s}
			return c
		}(),
		"cert entry without scheme": func() AssuranceConfig {
			c := validAssurance()
			c.Certification.Entries = CertificationEntryList{{Name: "x"}}
			return c
		}(),
		"cert entry bad name": func() AssuranceConfig {
			c := validAssurance()
			c.Certification.Entries = CertificationEntryList{{Name: "a b", Scheme: "s", AssuranceLevel: "l"}}
			return c
		}(),
		"cert duplicate names": func() AssuranceConfig {
			c := validAssurance()
			e := CertificationEntry{Name: "x", Scheme: "s", AssuranceLevel: "l"}
			c.Certification.Entries = CertificationEntryList{e, e}
			return c
		}(),
		"cert levels without scheme": func() AssuranceConfig {
			c := validAssurance()
			c.Certification.Levels = []string{"high"}
			return c
		}(),
	}
	for name, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestAssuranceConfig_ConfigValidateWiresIn(t *testing.T) {
	cfg := defaultConfig()
	cfg.JWT.Secret = "0123456789abcdef0123456789abcdef"
	cfg.WalletProvider.Attestation.Assurance.Enabled = true // no rules_file
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "assurance") {
		t.Fatalf("Config.Validate must reject an enabled policy without rules: %v", err)
	}
}

func TestAssuranceConfig_YAMLAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(`
jwt:
  secret: "0123456789abcdef0123456789abcdef"
wallet_provider:
  attestation:
    assurance:
      enabled: true
      rules_file: /etc/a.rules
      key_storage_scheme: tiers
      lower_by_claims_user_authentication: false
      level_schemes:
        - id: tiers
          levels: [k3, k1]
          values: [sw, certified]
          floor: k3
      certification:
        scheme: EUCC
        levels: [high]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WALLET_WALLET_PROVIDER_ATTESTATION_ASSURANCE_RULES_FILE", "/etc/override.rules")
	t.Setenv("WALLET_WALLET_PROVIDER_ATTESTATION_ASSURANCE_CERTIFICATION_ENTRIES", `[{"name":"e1","scheme":"EUCC","assurance_level":"high"}]`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.WalletProvider.Attestation.Assurance
	if !a.Enabled || a.RulesFile != "/etc/override.rules" || a.KeyStorageScheme != "tiers" {
		t.Fatalf("%+v", a)
	}
	if !a.LowerByClaimsKeyStorage || a.LowerByClaimsUserAuthentication {
		t.Fatalf("lower_by_claims: %+v", a)
	}
	if len(a.LevelSchemes) != 1 || a.LevelSchemes[0].Values[1] != "certified" {
		t.Fatalf("schemes: %+v", a.LevelSchemes)
	}
	if len(a.Certification.Entries) != 1 || a.Certification.Entries[0].Name != "e1" {
		t.Fatalf("entries: %+v", a.Certification.Entries)
	}
}

func TestAssuranceConfig_EnvLevelSchemesJSON(t *testing.T) {
	var l LevelSchemeList
	if err := l.Decode(`[{"id":"s","levels":["a"],"values":["v"],"floor":"a"}]`); err != nil || len(l) != 1 {
		t.Fatalf("%v %+v", err, l)
	}
	if err := l.Decode(`not json`); err == nil {
		t.Fatal("bad json must error")
	}
	if err := l.Decode(``); err != nil || l != nil {
		t.Fatal("empty clears")
	}
	var e CertificationEntryList
	if err := e.Decode(`{`); err == nil {
		t.Fatal("bad json must error")
	}
}

func TestAssuranceConfig_CertificationURLValidation(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://certs.example/eucc-high": true,
		"http://certs.example/x":          true,
		" ":                               false,
		"not a url":                       false,
		"https://":                        false,
		"https:///path":                   false,
		"ftp://certs.example/x":           false,
		"/relative/path":                  false,
		"https://certs.example/a b":       false,
		" https://certs.example/x":        false,
		"https://certs.example/x\n":       false,
		"urn:cert:x":                      false,
	} {
		c := validAssurance()
		c.Certification.Entries = CertificationEntryList{{Name: "e", URL: url}}
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("url %q: ok=%v err=%v", url, ok, err)
		}
	}
}
