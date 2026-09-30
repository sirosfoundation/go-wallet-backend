package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRegistryConfig(t *testing.T) {
	c := DefaultRegistryConfig()
	assert.Equal(t, "https://registry.siros.org/api/v1/schemas.json", c.Source.URL)
	assert.Equal(t, 5*time.Minute, c.Source.PollInterval)
	assert.Equal(t, 30*time.Second, c.Source.Timeout)
	assert.Equal(t, "data/vctm-cache.json", c.Cache.Path)
	assert.Equal(t, 24*time.Hour, c.Cache.MaxAge)
	assert.False(t, c.DynamicCache.Enabled)
	assert.True(t, c.RateLimit.Enabled)
	assert.Equal(t, 1000, c.RateLimit.AuthenticatedRPM)
	assert.Equal(t, 100, c.RateLimit.UnauthenticatedRPM)
	assert.Equal(t, 3, c.RateLimit.BurstMultiplier)
	assert.False(t, c.RequireAuth)
	// Present in the backend defaults too
	assert.Equal(t, c, defaultConfig().Registry)
}

func TestRegistryConfig_Validate(t *testing.T) {
	tests := []struct {
		name     string
		modify   func(*RegistryConfig)
		errorMsg string
	}{
		{"valid default", func(c *RegistryConfig) {}, ""},
		{"empty source URL", func(c *RegistryConfig) { c.Source.URL = "" }, "registry.source.url is required"},
		{"poll interval too short", func(c *RegistryConfig) { c.Source.PollInterval = 500 * time.Millisecond }, "poll_interval must be at least 1 second"},
		{"empty cache path", func(c *RegistryConfig) { c.Cache.Path = "" }, "registry.cache.path is required"},
		{"invalid include pattern", func(c *RegistryConfig) { c.Filter.IncludePatterns = []string{"[invalid"} }, "invalid include pattern"},
		{"invalid exclude pattern", func(c *RegistryConfig) { c.Filter.ExcludePatterns = []string{"(unclosed"} }, "invalid exclude pattern"},
		{"authenticated rpm", func(c *RegistryConfig) { c.RateLimit.AuthenticatedRPM = 0 }, "authenticated_rpm must be positive"},
		{"unauthenticated rpm", func(c *RegistryConfig) { c.RateLimit.UnauthenticatedRPM = -1 }, "unauthenticated_rpm must be positive"},
		{"rate limit disabled ok", func(c *RegistryConfig) {
			c.RateLimit.Enabled = false
			c.RateLimit.AuthenticatedRPM = 0
			c.RateLimit.UnauthenticatedRPM = 0
		}, ""},
		{"sources entry without url", func(c *RegistryConfig) {
			c.Sources = []RegistryRemoteSourceConfig{{URL: ""}}
		}, "registry.sources[0].url is required"},
		{"sources bad mode", func(c *RegistryConfig) {
			c.Sources = []RegistryRemoteSourceConfig{{URL: "https://x", Mode: "nope"}}
		}, "registry.sources[0].mode"},
		{"dynamic cache bad pattern", func(c *RegistryConfig) {
			c.DynamicCache.Enabled = true
			c.DynamicCache.AllowedHosts = []string{"("}
		}, "invalid registry.dynamic_cache"},
		{"dynamic cache ttl too small", func(c *RegistryConfig) {
			c.DynamicCache.Enabled = true
			c.DynamicCache.DefaultTTL = time.Millisecond
		}, "default_ttl must be at least 1 second"},
		{"dynamic cache min>max", func(c *RegistryConfig) {
			c.DynamicCache.Enabled = true
			c.DynamicCache.MinTTL = 2 * time.Hour
			c.DynamicCache.MaxTTL = time.Hour
		}, "min_ttl cannot be greater than max_ttl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultRegistryConfig()
			tt.modify(&c)
			err := c.Validate()
			if tt.errorMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}

	t.Run("legacy source is normalized into sources", func(t *testing.T) {
		c := DefaultRegistryConfig()
		require.NoError(t, c.Validate())
		require.Len(t, c.Sources, 1)
		assert.Equal(t, c.Source.URL, c.Sources[0].URL)
		assert.Equal(t, RegistryAPIModeTS11, c.Sources[0].Mode)
	})
}

func TestConfig_ValidateRegistry_Auth(t *testing.T) {
	base := func() *Config {
		c := defaultConfig()
		c.Registry.RequireAuth = true
		return c
	}

	t.Run("no auth required needs nothing", func(t *testing.T) {
		c := defaultConfig()
		c.JWT.Secret = ""
		require.NoError(t, c.ValidateRegistry())
	})

	t.Run("names every missing field", func(t *testing.T) {
		c := base()
		c.JWT.Secret = ""
		c.JWT.Issuer = ""
		err := c.ValidateRegistry()
		require.Error(t, err)
		for _, f := range []string{"as.external_url", "as.issuer", "jwt.secret"} {
			assert.Contains(t, err.Error(), f)
		}
	})

	t.Run("legacy disabled needs no secret", func(t *testing.T) {
		c := base()
		c.AS.ExternalURL = "https://wallet.example.org"
		c.AS.Legacy.Enabled = false
		c.JWT.Secret = ""
		require.NoError(t, c.ValidateRegistry())
	})

	t.Run("legacy enabled needs a 32 byte secret", func(t *testing.T) {
		c := base()
		c.AS.ExternalURL = "https://wallet.example.org"
		c.AS.Legacy.Enabled = true
		c.JWT.Secret = "short"
		err := c.ValidateRegistry()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "jwt.secret")
		assert.NotContains(t, err.Error(), "as.external_url")
		c.JWT.Secret = strings.Repeat("s", 32)
		require.NoError(t, c.ValidateRegistry())
	})

	t.Run("as.enabled false is fine", func(t *testing.T) {
		c := base()
		c.AS.Enabled = false
		c.AS.ExternalURL = "https://wallet.example.org"
		c.AS.Issuer = "https://wallet.example.org"
		c.AS.Legacy.Enabled = false
		require.NoError(t, c.ValidateRegistry())
	})

	t.Run("registry validation errors propagate", func(t *testing.T) {
		c := defaultConfig()
		c.Registry.Cache.Path = ""
		require.Error(t, c.ValidateRegistry())
	})
}

func TestConfig_ValidateRegistryStandalone(t *testing.T) {
	c := defaultConfig()
	require.NoError(t, c.ValidateRegistryStandalone())

	c = defaultConfig()
	c.Server.RegistryPort = 0 // defaults to 8097
	require.NoError(t, c.ValidateRegistryStandalone())

	c = defaultConfig()
	c.Server.RegistryPort = 70000
	assert.ErrorContains(t, c.ValidateRegistryStandalone(), "registry_port")

	c = defaultConfig()
	c.Server.CORS.AllowedOrigins = []string{}
	require.NoError(t, c.ValidateRegistryStandalone())
	assert.Equal(t, []string{"*"}, c.Server.CORS.AllowedOrigins)

	c = defaultConfig()
	c.Server.CORS.AllowCredentials = true
	c.Server.CORS.AllowedOrigins = []string{"*"}
	assert.ErrorContains(t, c.ValidateRegistryStandalone(), "allow_credentials")

	c = defaultConfig()
	c.Server.TLS.Enabled = true
	assert.ErrorContains(t, c.ValidateRegistryStandalone(), "cert_file")
	c.Server.TLS.CertFile = "c"
	assert.ErrorContains(t, c.ValidateRegistryStandalone(), "key_file")
	c.Server.TLS.KeyFile = "k"
	require.NoError(t, c.ValidateRegistryStandalone())

	c = defaultConfig()
	c.Server.TrustedProxies = []string{"not-a-cidr"}
	assert.Error(t, c.ValidateRegistryStandalone())
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestLoad_RegistrySection(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "config.yaml", `
jwt:
  secret: "0123456789abcdef0123456789abcdef"
registry:
  source:
    url: "https://example.org/api/v1/schemas.json"
    poll_interval: 10m
  cache:
    path: /var/lib/vctm.json
  filter:
    include_patterns: ["^https://example\\.org/"]
  rate_limit:
    unauthenticated_rpm: 7
  require_auth: true
`)
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.Equal(t, "https://example.org/api/v1/schemas.json", cfg.Registry.Source.URL)
	assert.Equal(t, 10*time.Minute, cfg.Registry.Source.PollInterval)
	assert.Equal(t, "/var/lib/vctm.json", cfg.Registry.Cache.Path)
	assert.Equal(t, 7, cfg.Registry.RateLimit.UnauthenticatedRPM)
	assert.Equal(t, 1000, cfg.Registry.RateLimit.AuthenticatedRPM, "unset keys keep defaults")
	assert.True(t, cfg.Registry.RequireAuth)
	assert.True(t, cfg.RegistryExplicit())
}

func TestLoad_RegistryEnv(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "config.yaml", "jwt:\n  secret: \"0123456789abcdef0123456789abcdef\"\n")
	cfg, err := Load(p)
	require.NoError(t, err)
	assert.False(t, cfg.RegistryExplicit())

	t.Setenv("WALLET_REGISTRY_SOURCE_URL", "https://env.example.org/x.json")
	t.Setenv("WALLET_REGISTRY_REQUIRE_AUTH", "true")
	t.Setenv("WALLET_REGISTRY_DYNAMIC_CACHE_ENABLED", "true")
	cfg, err = Load(p)
	require.NoError(t, err)
	assert.Equal(t, "https://env.example.org/x.json", cfg.Registry.Source.URL)
	assert.True(t, cfg.Registry.RequireAuth)
	assert.True(t, cfg.Registry.DynamicCache.Enabled)
	assert.True(t, cfg.RegistryExplicit())
}

func TestLoadRegistryOnly(t *testing.T) {
	dir := t.TempDir()

	t.Run("no backend-only settings required", func(t *testing.T) {
		// No jwt.secret, default storage: Load would reject this, registry-only must not.
		p := writeFile(t, dir, "reg.yaml", "registry:\n  cache:\n    path: /tmp/c.json\n")
		_, err := Load(p)
		require.Error(t, err)
		cfg, err := LoadRegistryOnly(p)
		require.NoError(t, err)
		assert.Equal(t, "/tmp/c.json", cfg.Registry.Cache.Path)
		assert.Equal(t, "0.0.0.0:8097", cfg.Server.RegistryAddress())
	})

	t.Run("missing file uses defaults", func(t *testing.T) {
		cfg, err := LoadRegistryOnly(filepath.Join(dir, "absent.yaml"))
		require.NoError(t, err)
		assert.Equal(t, DefaultRegistryConfig(), cfg.Registry)
	})

	t.Run("invalid server settings rejected", func(t *testing.T) {
		p := writeFile(t, dir, "bad.yaml", "server:\n  registry_port: 99999\n")
		_, err := LoadRegistryOnly(p)
		assert.ErrorContains(t, err, "registry_port")
	})
}

func TestLoad_RetiredRegistryLayoutWarning(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "old.yaml", "source:\n  url: https://x\ncache:\n  path: /x\nrate_limit:\n  enabled: true\n")
	cfg, err := LoadRegistryOnly(p)
	require.NoError(t, err)
	require.Len(t, cfg.Warnings(), 1)
	assert.Contains(t, cfg.Warnings()[0], "source")
	assert.Contains(t, cfg.Warnings()[0], "registry:")
	assert.Equal(t, DefaultRegistryConfig(), cfg.Registry, "top-level keys are not applied")

	p = writeFile(t, dir, "new.yaml", "registry:\n  cache:\n    path: /x\n")
	cfg, err = LoadRegistryOnly(p)
	require.NoError(t, err)
	assert.Empty(t, cfg.Warnings())
}

const legacyRegistryYAML = `
server:
  host: 127.0.0.1
  port: 9100
  cors:
    allowed_origins: ["https://wallet.example.org"]
source:
  url: https://legacy.example.org/api/v1/schemas.json
  poll_interval: 2m
cache:
  path: /legacy/cache.json
dynamic_cache:
  enabled: true
rate_limit:
  unauthenticated_rpm: 5
logging:
  level: debug
  format: text
jwt:
  secret: "0123456789abcdef0123456789abcdef"
  issuer: legacy-issuer
  require_auth: true
`

func TestApplyLegacyRegistryConfig_NoOpWhenAbsent(t *testing.T) {
	c := defaultConfig()
	w, err := c.ApplyLegacyRegistryConfig(filepath.Join(t.TempDir(), "absent.yaml"), true)
	require.NoError(t, err)
	assert.Empty(t, w)
	assert.Equal(t, DefaultRegistryConfig(), c.Registry)

	w, err = c.ApplyLegacyRegistryConfig("", false)
	require.NoError(t, err)
	assert.Empty(t, w)
}

func TestApplyLegacyRegistryConfig_FileMappingStandalone(t *testing.T) {
	p := writeFile(t, t.TempDir(), "registry.yaml", legacyRegistryYAML)
	c := defaultConfig()
	c.AS.ExternalURL = "https://wallet.example.org"
	w, err := c.ApplyLegacyRegistryConfig(p, true)
	require.NoError(t, err)
	require.NotEmpty(t, w)
	assert.Contains(t, w[0], "DEPRECATED")
	assert.Contains(t, w[0], p)
	assert.Contains(t, w[0], "registry:")

	// registry section
	assert.Equal(t, "https://legacy.example.org/api/v1/schemas.json", c.Registry.Source.URL)
	assert.Equal(t, 2*time.Minute, c.Registry.Source.PollInterval)
	assert.Equal(t, "/legacy/cache.json", c.Registry.Cache.Path)
	assert.True(t, c.Registry.DynamicCache.Enabled)
	assert.Equal(t, 5, c.Registry.RateLimit.UnauthenticatedRPM)
	assert.True(t, c.Registry.RequireAuth, "jwt.require_auth -> registry.require_auth")

	// server/logging map onto the shared backend settings (registry-only)
	assert.Equal(t, "127.0.0.1", c.Server.RegistryHost)
	assert.Equal(t, 9100, c.Server.RegistryPort)
	assert.Equal(t, []string{"https://wallet.example.org"}, c.Server.CORS.AllowedOrigins)
	assert.Equal(t, "debug", c.Logging.Level)
	assert.Equal(t, "text", c.Logging.Format)

	// jwt block keeps validating HMAC tokens through the shared stack
	assert.Equal(t, "0123456789abcdef0123456789abcdef", c.JWT.Secret)
	assert.Equal(t, "legacy-issuer", c.JWT.Issuer, "legacy HMAC issuer stays enforced")
	assert.Equal(t, "", c.AS.Issuer)
	assert.Contains(t, strings.Join(w, "\n"), "jwt")
	assert.False(t, c.registryLegacyTolerateNoJWKS)

	require.NoError(t, c.ValidateRegistry())
}

func TestApplyLegacyRegistryConfig_CombinedIgnoresServerAndJWT(t *testing.T) {
	p := writeFile(t, t.TempDir(), "registry.yaml", legacyRegistryYAML)
	c := defaultConfig()
	c.JWT.Secret = "backend-secret-backend-secret-1234"
	c.Server.Port = 8080
	w, err := c.ApplyLegacyRegistryConfig(p, false)
	require.NoError(t, err)
	assert.Equal(t, "https://legacy.example.org/api/v1/schemas.json", c.Registry.Source.URL)
	assert.Equal(t, 8080, c.Server.Port)
	assert.Equal(t, "", c.Server.RegistryHost, "server block is not applied in combined mode")
	assert.Equal(t, "info", c.Logging.Level)
	assert.Equal(t, "backend-secret-backend-secret-1234", c.JWT.Secret)
	assert.Contains(t, strings.Join(w, "\n"), "jwt` block is ignored")
}

func TestApplyLegacyRegistryConfig_RequireAuthWithoutExternalURLIsTolerated(t *testing.T) {
	p := writeFile(t, t.TempDir(), "registry.yaml", legacyRegistryYAML)
	c := defaultConfig()
	w, err := c.ApplyLegacyRegistryConfig(p, true)
	require.NoError(t, err)
	assert.True(t, c.registryLegacyTolerateNoJWKS)
	assert.Contains(t, strings.Join(w, "\n"), "as.external_url")
	require.NoError(t, c.ValidateRegistry(), "old HMAC-only auth deployments keep starting")

	// ...but the new section is strict.
	c2 := defaultConfig()
	c2.Registry.RequireAuth = true
	c2.JWT.Secret = strings.Repeat("s", 32)
	assert.ErrorContains(t, c2.ValidateRegistry(), "as.external_url")
}

func TestApplyLegacyRegistryConfig_SecretPath(t *testing.T) {
	dir := t.TempDir()
	sp := writeFile(t, dir, "secret", "  0123456789abcdef0123456789abcdef\n")
	p := writeFile(t, dir, "registry.yaml", "jwt:\n  secret_path: "+sp+"\n")
	c := defaultConfig()
	_, err := c.ApplyLegacyRegistryConfig(p, true)
	require.NoError(t, err)
	assert.Equal(t, "0123456789abcdef0123456789abcdef", c.JWT.Secret)

	p = writeFile(t, dir, "registry2.yaml", "jwt:\n  secret_path: "+filepath.Join(dir, "missing")+"\n")
	_, err = defaultConfig().ApplyLegacyRegistryConfig(p, true)
	assert.ErrorContains(t, err, "jwt.secret_path")
}

func TestApplyLegacyRegistryConfig_Env(t *testing.T) {
	t.Setenv("REGISTRY_SOURCE_URL", "https://envlegacy.example.org/s.json")
	t.Setenv("REGISTRY_CACHE_PATH", "/env/cache.json")
	t.Setenv("REGISTRY_RATE_LIMIT_UNAUTHENTICATED_RPM", "9")
	t.Setenv("REGISTRY_DYNAMIC_CACHE_ALLOWED_HOSTS", "a,b")
	t.Setenv("REGISTRY_JWT_REQUIRE_AUTH", "true")
	t.Setenv("REGISTRY_SERVER_PORT", "9200")
	c := defaultConfig()
	c.AS.ExternalURL = "https://wallet.example.org"
	w, err := c.ApplyLegacyRegistryConfig(filepath.Join(t.TempDir(), "absent.yaml"), true)
	require.NoError(t, err)
	require.NotEmpty(t, w)
	assert.Contains(t, w[0], "REGISTRY_* environment variables")
	assert.Equal(t, "https://envlegacy.example.org/s.json", c.Registry.Source.URL)
	assert.Equal(t, "/env/cache.json", c.Registry.Cache.Path)
	assert.Equal(t, 9, c.Registry.RateLimit.UnauthenticatedRPM)
	assert.Equal(t, []string{"a", "b"}, c.Registry.DynamicCache.AllowedHosts)
	assert.True(t, c.Registry.RequireAuth)
	assert.Equal(t, 9200, c.Server.RegistryPort)
}

func TestApplyLegacyRegistryConfig_EnvOverridesFileLikeBefore(t *testing.T) {
	p := writeFile(t, t.TempDir(), "registry.yaml", legacyRegistryYAML)
	t.Setenv("REGISTRY_CACHE_PATH", "/env/wins.json")
	c := defaultConfig()
	w, err := c.ApplyLegacyRegistryConfig(p, true)
	require.NoError(t, err)
	assert.Contains(t, w[0], "and REGISTRY_* environment variables")
	assert.Equal(t, "/env/wins.json", c.Registry.Cache.Path)
}

func TestApplyLegacyRegistryConfig_NewSectionWins(t *testing.T) {
	dir := t.TempDir()
	newCfg := writeFile(t, dir, "config.yaml", `
jwt:
  secret: "0123456789abcdef0123456789abcdef"
registry:
  cache:
    path: /new/cache.json
`)
	cfg, err := Load(newCfg)
	require.NoError(t, err)
	require.True(t, cfg.RegistryExplicit())

	p := writeFile(t, dir, "registry.yaml", legacyRegistryYAML)
	w, err := cfg.ApplyLegacyRegistryConfig(p, false)
	require.NoError(t, err)
	require.NotEmpty(t, w)
	assert.Contains(t, w[0], "DEPRECATED")
	assert.Contains(t, w[1], "registry.cache.path")
	assert.Contains(t, w[1], "take precedence")
	assert.Equal(t, "/new/cache.json", cfg.Registry.Cache.Path, "customised new key wins")
	assert.Equal(t, "https://legacy.example.org/api/v1/schemas.json", cfg.Registry.Source.URL, "untouched key filled from legacy")
}

// The helper image always loads configs/config.registry.yaml, which contains a
// registry: block; legacy REGISTRY_* variables must still apply for the keys
// that block leaves at their defaults.
func TestApplyLegacyRegistryConfig_HelperImageBundledConfig(t *testing.T) {
	bundled, err := os.ReadFile(filepath.Join("..", "..", "configs", "config.registry.yaml"))
	require.NoError(t, err)
	p := writeFile(t, t.TempDir(), "config.registry.yaml", string(bundled))
	cfg, err := LoadRegistryOnly(p)
	require.NoError(t, err)
	require.True(t, cfg.RegistryExplicit())

	t.Setenv("REGISTRY_SOURCE_URL", "https://env.example.org/s.json")
	t.Setenv("REGISTRY_RATE_LIMIT_UNAUTHENTICATED_RPM", "11")
	w, err := cfg.ApplyLegacyRegistryConfig("", true)
	require.NoError(t, err)
	assert.Equal(t, "https://env.example.org/s.json", cfg.Registry.Source.URL)
	assert.Equal(t, 11, cfg.Registry.RateLimit.UnauthenticatedRPM)
	require.Len(t, w, 1, "no conflict: only the deprecation warning")
	assert.Contains(t, w[0], "DEPRECATED")
}

func TestApplyLegacyRegistryConfig_NewEnvSectionWins(t *testing.T) {
	dir := t.TempDir()
	newCfg := writeFile(t, dir, "config.yaml", "jwt:\n  secret: \"0123456789abcdef0123456789abcdef\"\n")
	t.Setenv("WALLET_REGISTRY_CACHE_PATH", "/newenv/c.json")
	cfg, err := Load(newCfg)
	require.NoError(t, err)
	p := writeFile(t, dir, "registry.yaml", legacyRegistryYAML)
	w, err := cfg.ApplyLegacyRegistryConfig(p, true)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(w, "\n"), "take precedence")
	assert.Equal(t, "/newenv/c.json", cfg.Registry.Cache.Path)
}

func TestApplyLegacyRegistryConfig_Errors(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "bad.yaml", "source: [unclosed")
	_, err := defaultConfig().ApplyLegacyRegistryConfig(p, true)
	assert.ErrorContains(t, err, "failed to parse registry config file")

	// a directory is not a readable file
	_, err = defaultConfig().ApplyLegacyRegistryConfig(dir, true)
	assert.ErrorContains(t, err, "failed to read registry config file")

	t.Setenv("REGISTRY_SERVER_PORT", "not-a-number")
	_, err = defaultConfig().ApplyLegacyRegistryConfig("", true)
	assert.ErrorContains(t, err, "REGISTRY_* environment variables")
}

func TestFilterConfig_Compile(t *testing.T) {
	tests := []struct {
		name        string
		include     []string
		exclude     []string
		expectError bool
	}{
		{
			name:        "empty patterns",
			include:     []string{},
			exclude:     []string{},
			expectError: false,
		},
		{
			name:        "valid include patterns",
			include:     []string{"^https://", "example\\.com"},
			exclude:     []string{},
			expectError: false,
		},
		{
			name:        "valid exclude patterns",
			include:     []string{},
			exclude:     []string{"-dev$", "^test"},
			expectError: false,
		},
		{
			name:        "invalid include pattern",
			include:     []string{"[invalid"},
			exclude:     []string{},
			expectError: true,
		},
		{
			name:        "invalid exclude pattern",
			include:     []string{},
			exclude:     []string{"(unclosed"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &RegistryFilterConfig{
				IncludePatterns: tt.include,
				ExcludePatterns: tt.exclude,
			}

			err := filter.Compile()

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, filter.includeRegexps, len(tt.include))
				assert.Len(t, filter.excludeRegexps, len(tt.exclude))
			}
		})
	}
}

func TestFilterConfig_Matches(t *testing.T) {
	tests := []struct {
		name    string
		include []string
		exclude []string
		vctID   string
		matches bool
	}{
		{
			name:    "no patterns - matches all",
			include: []string{},
			exclude: []string{},
			vctID:   "https://example.com/credential",
			matches: true,
		},
		{
			name:    "include pattern matches",
			include: []string{"^https://example\\.com/"},
			exclude: []string{},
			vctID:   "https://example.com/credential",
			matches: true,
		},
		{
			name:    "include pattern does not match",
			include: []string{"^https://other\\.com/"},
			exclude: []string{},
			vctID:   "https://example.com/credential",
			matches: false,
		},
		{
			name:    "exclude pattern matches - excluded",
			include: []string{},
			exclude: []string{"-dev$"},
			vctID:   "https://example.com/credential-dev",
			matches: false,
		},
		{
			name:    "exclude pattern does not match - included",
			include: []string{},
			exclude: []string{"-dev$"},
			vctID:   "https://example.com/credential-prod",
			matches: true,
		},
		{
			name:    "include matches but exclude also matches - excluded",
			include: []string{"^https://"},
			exclude: []string{"-test$"},
			vctID:   "https://example.com/credential-test",
			matches: false,
		},
		{
			name:    "include matches and exclude does not - included",
			include: []string{"^https://"},
			exclude: []string{"-test$"},
			vctID:   "https://example.com/credential-prod",
			matches: true,
		},
		{
			name:    "multiple include patterns - first matches",
			include: []string{"^https://example\\.com/", "^https://other\\.com/"},
			exclude: []string{},
			vctID:   "https://example.com/credential",
			matches: true,
		},
		{
			name:    "multiple include patterns - second matches",
			include: []string{"^https://example\\.com/", "^https://other\\.com/"},
			exclude: []string{},
			vctID:   "https://other.com/credential",
			matches: true,
		},
		{
			name:    "multiple include patterns - none match",
			include: []string{"^https://example\\.com/", "^https://other\\.com/"},
			exclude: []string{},
			vctID:   "https://third.com/credential",
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &RegistryFilterConfig{
				IncludePatterns: tt.include,
				ExcludePatterns: tt.exclude,
			}
			err := filter.Compile()
			require.NoError(t, err)

			result := filter.Matches(tt.vctID)
			assert.Equal(t, tt.matches, result)
		})
	}
}

func TestApplyLegacyRegistryConfig_ExplicitDefaultsWin(t *testing.T) {
	dir := t.TempDir()
	newCfg := writeFile(t, dir, "config.yaml", `
jwt:
  secret: "0123456789abcdef0123456789abcdef"
registry:
  dynamic_cache:
    enabled: false
  require_auth: false
`)
	old := writeFile(t, dir, "registry.yaml", "dynamic_cache:\n  enabled: true\njwt:\n  require_auth: true\n")

	cfg, err := Load(newCfg)
	require.NoError(t, err)
	w, err := cfg.ApplyLegacyRegistryConfig(old, false)
	require.NoError(t, err)
	assert.False(t, cfg.Registry.DynamicCache.Enabled, "explicit registry.dynamic_cache.enabled=false beats the old config")
	assert.False(t, cfg.Registry.RequireAuth, "explicit registry.require_auth=false beats jwt.require_auth=true")
	assert.Contains(t, strings.Join(w, "\n"), "registry.dynamic_cache.enabled")

	// same through the environment
	t.Setenv("WALLET_REGISTRY_DYNAMIC_CACHE_ENABLED", "false")
	t.Setenv("WALLET_REGISTRY_REQUIRE_AUTH", "false")
	plain := writeFile(t, dir, "plain.yaml", "jwt:\n  secret: \"0123456789abcdef0123456789abcdef\"\n")
	cfg, err = Load(plain)
	require.NoError(t, err)
	_, err = cfg.ApplyLegacyRegistryConfig(old, false)
	require.NoError(t, err)
	assert.False(t, cfg.Registry.DynamicCache.Enabled)
	assert.False(t, cfg.Registry.RequireAuth)
}

func TestValidateRegistry_ShortSecretAndTolerance(t *testing.T) {
	c := defaultConfig()
	c.AS.Legacy.Enabled = true
	c.JWT.Secret = "short"
	assert.ErrorContains(t, c.ValidateRegistry(), "at least 32 bytes")
	c.AS.Legacy.Enabled = false
	require.NoError(t, c.ValidateRegistry(), "legacy off: secret unused")
	c.AS.Legacy.Enabled = true
	c.JWT.Secret = ""
	require.NoError(t, c.ValidateRegistry(), "no secret: legacy validator not built")

	// the no-JWKS tolerance only applies while legacy validation stays enabled
	c = defaultConfig()
	c.Registry.RequireAuth = true
	c.registryLegacyTolerateNoJWKS = true
	c.JWT.Secret = strings.Repeat("s", 32)
	require.NoError(t, c.ValidateRegistry())
	c.AS.Legacy.Enabled = false
	assert.ErrorContains(t, c.ValidateRegistry(), "as.external_url")
}

func TestLoadRegistryOnly_IgnoresBackendOnlySecretFiles(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	p := writeFile(t, dir, "c.yaml", "server:\n  admin_token_path: "+missing+"\n"+
		"storage:\n  mongodb:\n    password_path: "+missing+"\n"+
		"wallet_provider:\n  pkcs11:\n    pin_path: "+missing+"\n"+
		"jwt:\n  secret_path: "+missing+"\n"+
		"as:\n  legacy:\n    enabled: false\n")
	_, err := Load(p)
	require.Error(t, err, "the full backend load needs those files")
	cfg, err := LoadRegistryOnly(p)
	require.NoError(t, err, "registry-only does not read backend secrets nor jwt.secret_path with legacy off")
	assert.Empty(t, cfg.JWT.Secret)

	// legacy on: jwt.secret_path is read (and required)
	p = writeFile(t, dir, "c2.yaml", "jwt:\n  secret_path: "+missing+"\n")
	_, err = LoadRegistryOnly(p)
	assert.ErrorContains(t, err, "jwt.secret_path")
	sp := writeFile(t, dir, "secret", "0123456789abcdef0123456789abcdef\n")
	p = writeFile(t, dir, "c3.yaml", "jwt:\n  secret_path: "+sp+"\nserver:\n  admin_token_path: "+missing+"\n")
	cfg, err = LoadRegistryOnly(p)
	require.NoError(t, err)
	assert.Equal(t, "0123456789abcdef0123456789abcdef", cfg.JWT.Secret)
}

func TestApplyLegacyRegistryConfig_CombinedDoesNotReadOldSecretFile(t *testing.T) {
	dir := t.TempDir()
	old := writeFile(t, dir, "registry.yaml", "jwt:\n  secret_path: "+filepath.Join(dir, "gone")+"\n")
	c := defaultConfig()
	_, err := c.ApplyLegacyRegistryConfig(old, false)
	require.NoError(t, err, "combined mode uses the backend jwt settings")
	_, err = defaultConfig().ApplyLegacyRegistryConfig(old, true)
	assert.ErrorContains(t, err, "jwt.secret_path", "standalone still needs it")
}
