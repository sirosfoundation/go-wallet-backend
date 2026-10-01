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
//   - When the new `registry:` section (or WALLET_REGISTRY_*) is also
//     configured, the new section wins and the deprecated configuration is
//     ignored entirely, with a warning saying so.
//   - Otherwise the deprecated settings are mapped onto Config.Registry (see
//     docs/REGISTRY_MIGRATION.md for the table). The old `jwt` block is not used for
//     validation any more: jwt.require_auth becomes registry.require_auth, and
//     jwt.secret / jwt.secret_path / jwt.issuer keep validating legacy HMAC
//     tokens by mapping to the backend's jwt.* when those are unset.
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

	// jwt block: auth is now the shared go-tokenauth validator.
	if f.JWT.RequireAuth && !c.registryKeyExplicit([]string{"require_auth"}, "WALLET_REGISTRY_REQUIRE_AUTH") {
		c.Registry.RequireAuth = true
		if c.AS.ExternalURL == "" {
			c.registryLegacyTolerateNoJWKS = true
			warnings = append(warnings, "deprecated registry jwt.require_auth=true is mapped to registry.require_auth, "+
				"but as.external_url is not set: only legacy HMAC tokens can be validated until you set as.external_url "+
				"(new-style tokens are validated against <as.external_url>/auth/.well-known/jwks.json)")
		}
	}
	// The old secret file is only read when it is going to be used: the
	// registry runs alone, legacy HMAC validation is enabled and no shared
	// secret has been loaded already (the new jwt.secret / jwt.secret_path
	// wins). Otherwise a missing file must not fail startup.
	secret := f.JWT.Secret
	if standalone && f.JWT.SecretPath != "" && c.AS.Legacy.Enabled && c.JWT.Secret == "" {
		s, err := readSecretFile(f.JWT.SecretPath)
		if err != nil {
			return warnings, fmt.Errorf("registry jwt.secret_path: %w", err)
		}
		secret = s
	}
	if secret != "" || f.JWT.SecretPath != "" || f.JWT.Issuer != "wallet-backend" {
		if standalone {
			if secret != "" && c.JWT.Secret == "" {
				c.JWT.Secret = secret
			}
			// Like the secret, an explicitly configured shared jwt.issuer
			// (file or WALLET_JWT_ISSUER) wins; otherwise the new secret
			// would be paired with the old issuer and the shared config's
			// HMAC tokens would be rejected.
			if f.JWT.Issuer != "" && f.JWT.Issuer != "wallet-backend" && !c.jwtIssuerExplicit {
				c.JWT.Issuer = f.JWT.Issuer
			}
			warnings = append(warnings, "deprecated registry `jwt` block: secret and issuer are mapped to the backend jwt.secret / jwt.issuer "+
				"(legacy HMAC validation); the block itself is no longer used")
		} else {
			warnings = append(warnings, "deprecated registry `jwt` block is ignored: tokens are validated with the backend's "+
				"as.* / jwt.* configuration")
		}
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
