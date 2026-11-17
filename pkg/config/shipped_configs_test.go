package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Shipped sample configs that enable the AS must set as.external_url (the AS JWKS is fetched from
// it at startup) and, when they list CORS headers explicitly, include X-Token-Mode (mandatory on
// /auth/passkey/*; an explicit list replaces the defaults).
func TestShippedConfigs_ASRequirements(t *testing.T) {
	placeholder := regexp.MustCompile(`__SOFTHSM_SLOT_ID__`)
	for _, name := range []string{"config.yaml", "config.production.yaml", "config.pkcs11-softhsm.yaml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "configs", name))
			require.NoError(t, err)
			raw = placeholder.ReplaceAll(raw, []byte("0"))
			cfg := defaultConfig()
			require.NoError(t, yaml.Unmarshal(raw, cfg))

			require.True(t, cfg.AS.Enabled, "sample must enable the AS")
			_, err = cfg.AS.ExternalBaseURL()
			assert.NoError(t, err, "as.external_url must be set")
			assert.Contains(t, cfg.Server.CORS.AllowedHeaders, "X-Token-Mode")
		})
	}
}

// A sample served over plain HTTP must set as.insecure_cookies (a Secure __Host- cookie is dropped
// over http); a sample behind https must not.
func TestShippedConfigs_InsecureCookiesMatchScheme(t *testing.T) {
	for _, name := range []string{"config.yaml", "config.production.yaml", "config.pkcs11-softhsm.yaml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "configs", name))
			require.NoError(t, err)
			raw = regexp.MustCompile(`__SOFTHSM_SLOT_ID__`).ReplaceAll(raw, []byte("0"))
			cfg := defaultConfig()
			require.NoError(t, yaml.Unmarshal(raw, cfg))
			u, err := cfg.AS.ExternalBaseURL()
			require.NoError(t, err)
			assert.Equal(t, u.Scheme == "http", cfg.AS.InsecureCookies,
				"as.insecure_cookies must be true exactly when as.external_url is http (%s)", u)
		})
	}
}

// A file bind mount of a path that does not exist on a clean checkout is created as a directory;
// the compose files must mount a directory for generated files (the AS signing key).
func TestShippedCompose_NoBindMountOfGeneratedKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "compose.yaml"))
	require.NoError(t, err)
	var c struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &c))
	require.NotEmpty(t, c.Services)
	for name, svc := range c.Services {
		for _, v := range svc.Volumes {
			assert.NotContains(t, v, ".pem", "service %s: bind-mount the directory, not the generated key file", name)
		}
	}
}
