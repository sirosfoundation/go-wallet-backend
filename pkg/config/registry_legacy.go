package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

// legacyRegistryFile is the layout of the retired standalone registry
// configuration (configs/registry.yaml, REGISTRY_* environment variables).
// It is only read to support the deprecated aliases; see
// ApplyLegacyRegistryConfig.
type legacyRegistryFile struct {
	RegistryConfig `yaml:",inline"`

	Server struct {
		Host           string     `yaml:"host"`
		Port           int        `yaml:"port"`
		ServedByHeader *string    `yaml:"served_by_header"`
		TLS            TLSConfig  `yaml:"tls"`
		CORS           CORSConfig `yaml:"cors" envconfig:"CORS"`
	} `yaml:"server"`

	JWT struct {
		Secret      string `yaml:"secret"`
		SecretPath  string `yaml:"secret_path" envconfig:"SECRET_PATH"`
		Issuer      string `yaml:"issuer"`
		RequireAuth bool   `yaml:"require_auth" envconfig:"REQUIRE_AUTH"`
	} `yaml:"jwt"`

	Logging    LoggingConfig    `yaml:"logging"`
	HTTPClient HTTPClientConfig `yaml:"http_client" envconfig:"HTTP_CLIENT"`
}

func newLegacyRegistryFile() *legacyRegistryFile {
	f := &legacyRegistryFile{RegistryConfig: DefaultRegistryConfig()}
	f.Server.Host = "0.0.0.0"
	f.Server.Port = 8097
	f.Server.CORS.SetDefaults()
	f.JWT.Issuer = "wallet-backend"
	f.Logging.Level = "info"
	f.Logging.Format = "json"
	return f
}

// ApplyLegacyRegistryConfig supports the deprecated standalone registry
// configuration (--registry-config / configs/registry.yaml / REGISTRY_*
// environment variables) for one release. It returns human-readable warnings
// the caller must log.
//
//   - Nothing is done, and no warning is returned, when neither the file exists
//     nor any REGISTRY_* variable changes a setting.
//   - The deprecated settings are mapped onto Config.Registry (see
//     docs/REGISTRY_MIGRATION.md for the table), merged per key: a key set
//     explicitly in the new `registry:` section (or WALLET_REGISTRY_*) wins,
//     while keys it leaves unset are still filled from the deprecated
//     configuration. A warning names every key where both set a value, and
//     the new value was kept. Of the old `jwt` block only jwt.require_auth is used
//     (-> registry.require_auth); jwt.secret / jwt.secret_path / jwt.issuer are IGNORED with a
//     loud warning (the secret file is never read). Without as.external_url, ValidateRegistry
//     fails startup when require_auth is set.
//
// standalone is true when the registry role runs without any backend role; the
// old server, logging, CORS, TLS and http_client settings then map onto the
// corresponding backend settings (server.registry_host / registry_port,
// logging, server.cors, server.tls, http_client) because there is no other
// config to take them from. In a combined process those were already ignored.
func (c *Config) ApplyLegacyRegistryConfig(path string, standalone bool) ([]string, error) {
	f := newLegacyRegistryFile()

	fileFound := false
	if path != "" {
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			fileFound = true
			if err := yaml.Unmarshal(data, f); err != nil {
				return nil, fmt.Errorf("failed to parse registry config file %s: %w", path, err)
			}
		case !os.IsNotExist(err):
			return nil, fmt.Errorf("failed to read registry config file %s: %w", path, err)
		}
	}

	// Presence is detected with LookupEnv, not by comparing values: a
	// variable that sets the built-in default (REGISTRY_SERVER_PORT=8097) or
	// an empty value is still a use of the deprecated configuration.
	presentEnv, err := presentLegacyRegistryEnv(f)
	if err != nil {
		return nil, err
	}
	if err := envconfig.Process("REGISTRY", f); err != nil {
		return nil, fmt.Errorf("failed to process deprecated REGISTRY_* environment variables: %w", err)
	}
	envSet := len(presentEnv) > 0

	if !fileFound && !envSet {
		return nil, nil
	}

	envDesc := "REGISTRY_* environment variables (" + strings.Join(presentEnv, ", ") + ")"
	src := envDesc
	if fileFound && envSet {
		src = fmt.Sprintf("registry config file %s and %s", path, envDesc)
	} else if fileFound {
		src = fmt.Sprintf("registry config file %s", path)
	}
	warnings := []string{fmt.Sprintf(
		"DEPRECATED: %s (--registry-config, configs/registry.yaml, REGISTRY_*) will be removed in the next release; "+
			"move these settings to the `registry:` section of the backend config file (or WALLET_REGISTRY_* variables), "+
			"see docs/REGISTRY_MIGRATION.md", src)}

	// Per key, the new registry section wins; keys it leaves at their
	// defaults (for example the bundled helper-image config) are filled from
	// the deprecated configuration.
	var conflicts []string
	c.mergeLegacyRegistry(reflect.ValueOf(&c.Registry).Elem(), reflect.ValueOf(&f.RegistryConfig).Elem(),
		reflect.ValueOf(DefaultRegistryConfig()), nil, nil, &conflicts)
	if len(conflicts) > 0 {
		warnings = append(warnings, "both the new `registry:` section (or WALLET_REGISTRY_*) and the deprecated registry "+
			"configuration set "+strings.Join(conflicts, ", ")+": the new `registry:` values take precedence")
	}

	// jwt block: only jwt.require_auth is kept (-> registry.require_auth; ValidateRegistry then
	// needs as.external_url). The HMAC secret has nothing left to validate and is IGNORED, loudly.
	if f.JWT.RequireAuth && !c.registryKeyExplicit([]string{"require_auth"}, "WALLET_REGISTRY_REQUIRE_AUTH") {
		c.Registry.RequireAuth = true
		warnings = append(warnings, "deprecated registry jwt.require_auth=true is mapped to registry.require_auth; "+
			"it needs as.external_url (the AS JWKS) and as.issuer, or startup fails")
	}
	if f.JWT.Secret != "" || f.JWT.SecretPath != "" || f.JWT.Issuer != "wallet-backend" {
		warnings = append(warnings, "DEPRECATED registry `jwt` block (secret, secret_path, issuer) is IGNORED: HMAC (HS256) tokens are "+
			"no longer accepted because the legacy HMAC authorization server was removed. The registry validates only AS-issued "+
			"ES256 tokens, through the JWKS at <as.external_url>/auth/.well-known/jwks.json with audience \"wallet-registry\"; "+
			"clients still sending HMAC tokens are rejected (401 with registry.require_auth, otherwise served as unauthenticated). "+
			"Set as.external_url and as.issuer and migrate clients (see docs/REGISTRY_MIGRATION.md)")
	}

	if standalone {
		def := newLegacyRegistryFile()
		if f.Server.Host != def.Server.Host {
			c.Server.RegistryHost = f.Server.Host
		}
		if f.Server.Port != def.Server.Port {
			c.Server.RegistryPort = f.Server.Port
		}
		if f.Server.ServedByHeader != nil {
			c.Server.ServedByHeader = f.Server.ServedByHeader
		}
		if f.Server.TLS != def.Server.TLS {
			c.Server.TLS = f.Server.TLS
		}
		if !reflect.DeepEqual(f.Server.CORS, def.Server.CORS) {
			c.Server.CORS = f.Server.CORS
		}
		if f.Logging != def.Logging {
			c.Logging.Level = f.Logging.Level
			c.Logging.Format = f.Logging.Format
		}
		if !reflect.DeepEqual(f.HTTPClient, def.HTTPClient) {
			c.HTTPClient = f.HTTPClient
		}
	}
	return warnings, nil
}

// presentLegacyRegistryEnv returns, sorted, the REGISTRY_* variables that are
// set in the environment (even to an empty value or to the default) and that
// map to a field of the legacy registry configuration. Unrelated variables,
// and REGISTRY_* names no field uses, are not reported.
func presentLegacyRegistryEnv(spec *legacyRegistryFile) ([]string, error) {
	var keys strings.Builder
	if err := envconfig.Usagef("REGISTRY", spec, &keys, "{{range .}}{{.Key}}\n{{end}}"); err != nil {
		return nil, fmt.Errorf("failed to inspect deprecated REGISTRY_* environment variables: %w", err)
	}
	var present []string
	for _, key := range strings.Fields(keys.String()) {
		if _, ok := os.LookupEnv(key); ok {
			present = append(present, key)
		}
	}
	sort.Strings(present)
	return present, nil
}

// mergeLegacyRegistry fills every leaf of dst the new configuration did not
// set explicitly (key absent from the `registry:` YAML mapping and its
// WALLET_REGISTRY_* variable unset) from legacy. Explicitly set leaves keep
// their value, even if it equals the default; when legacy customised the same
// leaf to a different value, its path is appended to conflicts.
func (c *Config) mergeLegacyRegistry(dst, legacy, def reflect.Value, yamlPath, envParts []string, conflicts *[]string) {
	if dst.Kind() == reflect.Struct {
		for i := 0; i < dst.NumField(); i++ {
			if !dst.Field(i).CanSet() {
				continue // unexported (compiled patterns)
			}
			f := dst.Type().Field(i)
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			env := f.Tag.Get("envconfig")
			if env == "" {
				env = strings.ToUpper(f.Name)
			}
			c.mergeLegacyRegistry(dst.Field(i), legacy.Field(i), def.Field(i),
				append(append([]string{}, yamlPath...), name), append(append([]string{}, envParts...), env), conflicts)
		}
		return
	}
	if !c.registryKeyExplicit(yamlPath, "WALLET_REGISTRY_"+strings.Join(envParts, "_")) {
		dst.Set(legacy)
		return
	}
	if !reflect.DeepEqual(legacy.Interface(), def.Interface()) && !reflect.DeepEqual(dst.Interface(), legacy.Interface()) {
		*conflicts = append(*conflicts, "registry."+strings.Join(yamlPath, "."))
	}
}
