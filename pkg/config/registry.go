package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/embed"
)

// RegistryConfig holds the settings of the VCTM registry role
// (--mode=registry). It lives under the `registry:` key of the backend
// configuration. Server address, logging, CORS and outbound HTTP client
// settings are shared with the backend (server, logging, http_client), and
// request authentication uses the shared as.* / jwt.* configuration.
type RegistryConfig struct {
	// Source is the legacy single-registry source configuration.
	// Use Sources for multi-registry support. If Sources is empty, Source is used.
	Source RegistrySourceConfig `yaml:"source" envconfig:"SOURCE"`

	// Sources is an ordered list of remote registry URLs to fetch from.
	// Schemas fetched from later sources in the list overwrite earlier ones,
	// allowing a registry to extend or override another.
	// When non-empty, the Source.URL field is ignored for remote fetching
	// (Source.PollInterval and Source.LocalOverrides remain global settings).
	Sources []RegistryRemoteSourceConfig `yaml:"sources"`

	// Cache configuration
	Cache RegistryCacheConfig `yaml:"cache" envconfig:"CACHE"`

	// DynamicCache configuration for on-demand URL fetching
	DynamicCache RegistryDynamicCacheConfig `yaml:"dynamic_cache" envconfig:"DYNAMIC_CACHE"`

	// ImageEmbed configuration for embedding images as data URIs
	ImageEmbed embed.Config `yaml:"image_embed" envconfig:"IMAGE_EMBED"`

	// Filter configuration for include/exclude patterns
	Filter RegistryFilterConfig `yaml:"filter" envconfig:"FILTER"`

	// RateLimit configuration
	RateLimit RegistryRateLimitConfig `yaml:"rate_limit" envconfig:"RATE_LIMIT"`

	// RequireAuth requires a valid access token on all registry requests.
	// If false (default), unauthenticated access is allowed (with the lower
	// unauthenticated rate limit); valid tokens are still recognised.
	// Tokens are validated with the same go-tokenauth validator as the other
	// roles; see ValidateRegistry for the as.* fields this needs when the
	// registry runs without the auth role.
	RequireAuth bool `yaml:"require_auth" envconfig:"REQUIRE_AUTH"`
}

// RegistryAPIMode determines which registry API format to use when fetching.
type RegistryAPIMode string

const (
	// RegistryAPIModeTS11 uses the TS11 /api/v1/schemas.json endpoint which returns only
	// fully TS11-compliant credentials with schemaURIs for VCTM fetching.
	RegistryAPIModeTS11 RegistryAPIMode = "ts11"

	// RegistryAPIModeRegistry uses the /api/v1/registry.json endpoint which returns ALL
	// credentials (including non-TS11) with minimal metadata. Individual VCTMs
	// are fetched separately via their schemaURIs when available, or via the
	// /api/v1/schemas/{id}.json detail endpoint.
	RegistryAPIModeRegistry RegistryAPIMode = "registry"
)

// RegistryRemoteSourceConfig contains the minimal configuration needed to fetch schemas
// from a single remote registry URL. It is used by Config.Sources to specify
// multiple registries. Unlike RegistrySourceConfig it intentionally omits the global
// settings (LocalOverrides, PollInterval) that are not meaningful per source.
type RegistryRemoteSourceConfig struct {
	// URL is the base URL of the registry (e.g. "https://registry.siros.org").
	// The actual endpoint path is determined by the Mode setting.
	// For backward compatibility, if a full path to a specific endpoint is given
	// (e.g. ending in schemas.json or registry.json), it is used as-is regardless of Mode.
	URL string `yaml:"url"`

	// Mode selects which API endpoint to use: "ts11" (default) for only TS11-compliant
	// credentials, or "registry" for all credentials including non-TS11.
	Mode RegistryAPIMode `yaml:"mode"`

	// Timeout for HTTP requests to this source. Zero means no per-source timeout
	// (the shared http.Client timeout applies).
	Timeout time.Duration `yaml:"timeout"`
}

// RegistrySourceConfig contains upstream registry source configuration
type RegistrySourceConfig struct {
	// URL of the upstream registry.
	// The actual endpoint is determined by the Mode setting.
	URL string `yaml:"url"`

	// Mode selects which API endpoint to use: "ts11" (default) or "registry" (all credentials).
	Mode RegistryAPIMode `yaml:"mode"`

	// LocalOverrides is a list of local file or directory paths containing VCTM JSON files.
	// These are loaded at startup and take priority over entries fetched from the remote registry.
	// Directories are scanned for *.json files. Entries are keyed by their "vct" field.
	LocalOverrides []string `yaml:"local_overrides" envconfig:"LOCAL_OVERRIDES"`

	// PollInterval is how often to poll the upstream registry for updates
	PollInterval time.Duration `yaml:"poll_interval" envconfig:"POLL_INTERVAL"`

	// Timeout for HTTP requests to the upstream registry
	Timeout time.Duration `yaml:"timeout"`
}

// RegistryCacheConfig contains disk cache configuration
type RegistryCacheConfig struct {
	// Path to the cache file (JSON format)
	Path string `yaml:"path"`

	// MaxAge is the maximum age of cached data before forcing a refresh
	MaxAge time.Duration `yaml:"max_age" envconfig:"MAX_AGE"`
}

// RegistryDynamicCacheConfig contains configuration for on-demand URL fetching
type RegistryDynamicCacheConfig struct {
	// Enabled controls whether dynamic URL fetching is active
	Enabled bool `yaml:"enabled"`

	// DefaultTTL is the default cache TTL for dynamically fetched VCTMs
	// when no HTTP cache headers are present
	DefaultTTL time.Duration `yaml:"default_ttl" envconfig:"DEFAULT_TTL"`

	// MaxTTL is the maximum cache TTL to respect from HTTP headers
	// Values larger than this will be capped
	MaxTTL time.Duration `yaml:"max_ttl" envconfig:"MAX_TTL"`

	// MinTTL is the minimum cache TTL; shorter values from HTTP headers
	// will be bumped up to this value
	MinTTL time.Duration `yaml:"min_ttl" envconfig:"MIN_TTL"`

	// Timeout for HTTP requests when fetching VCTMs dynamically
	Timeout time.Duration `yaml:"timeout"`

	// AllowedHosts is an optional list of host patterns (regexps) that are
	// allowed for dynamic fetching. If empty, all HTTPS hosts are allowed.
	AllowedHosts []string `yaml:"allowed_hosts" envconfig:"ALLOWED_HOSTS"`

	// compiled host patterns
	allowedHostRegexps []*regexp.Regexp
}

// Compile compiles the allowed host patterns into regular expressions
func (d *RegistryDynamicCacheConfig) Compile() error {
	d.allowedHostRegexps = make([]*regexp.Regexp, 0, len(d.AllowedHosts))
	for _, pattern := range d.AllowedHosts {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid allowed host pattern %q: %w", pattern, err)
		}
		d.allowedHostRegexps = append(d.allowedHostRegexps, re)
	}
	return nil
}

// IsHostAllowed checks if a host is allowed for dynamic fetching
func (d *RegistryDynamicCacheConfig) IsHostAllowed(host string) bool {
	if !d.Enabled {
		return false
	}
	// If no patterns specified, allow all
	if len(d.allowedHostRegexps) == 0 {
		return true
	}
	for _, re := range d.allowedHostRegexps {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// RegistryFilterConfig contains VCT ID filtering configuration
type RegistryFilterConfig struct {
	// IncludePatterns are regexps that VCT IDs must match to be included
	// If empty, all VCT IDs are included (unless excluded)
	IncludePatterns []string `yaml:"include_patterns" envconfig:"INCLUDE_PATTERNS"`

	// ExcludePatterns are regexps that cause VCT IDs to be excluded
	ExcludePatterns []string `yaml:"exclude_patterns" envconfig:"EXCLUDE_PATTERNS"`

	// Compiled patterns (set by Compile())
	includeRegexps []*regexp.Regexp
	excludeRegexps []*regexp.Regexp
}

// Compile compiles the filter patterns into regular expressions
func (f *RegistryFilterConfig) Compile() error {
	f.includeRegexps = make([]*regexp.Regexp, 0, len(f.IncludePatterns))
	for _, pattern := range f.IncludePatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid include pattern %q: %w", pattern, err)
		}
		f.includeRegexps = append(f.includeRegexps, re)
	}

	f.excludeRegexps = make([]*regexp.Regexp, 0, len(f.ExcludePatterns))
	for _, pattern := range f.ExcludePatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid exclude pattern %q: %w", pattern, err)
		}
		f.excludeRegexps = append(f.excludeRegexps, re)
	}

	return nil
}

// Matches returns true if the VCT ID passes the filter
func (f *RegistryFilterConfig) Matches(vctID string) bool {
	// Check exclude patterns first
	for _, re := range f.excludeRegexps {
		if re.MatchString(vctID) {
			return false
		}
	}

	// If no include patterns, include by default
	if len(f.includeRegexps) == 0 {
		return true
	}

	// Check include patterns
	for _, re := range f.includeRegexps {
		if re.MatchString(vctID) {
			return true
		}
	}

	return false
}

// RegistryRateLimitConfig contains rate limiting configuration
type RegistryRateLimitConfig struct {
	// Enabled controls whether rate limiting is active
	Enabled bool `yaml:"enabled"`

	// AuthenticatedRPM is requests per minute for authenticated clients
	AuthenticatedRPM int `yaml:"authenticated_rpm" envconfig:"AUTHENTICATED_RPM"`

	// UnauthenticatedRPM is requests per minute for unauthenticated clients
	UnauthenticatedRPM int `yaml:"unauthenticated_rpm" envconfig:"UNAUTHENTICATED_RPM"`

	// BurstMultiplier allows bursts of this multiple of the rate limit
	BurstMultiplier int `yaml:"burst_multiplier" envconfig:"BURST_MULTIPLIER"`
}

// DefaultRegistryConfig returns a RegistryConfig with sensible default values.
func DefaultRegistryConfig() RegistryConfig {
	return RegistryConfig{
		Source: RegistrySourceConfig{
			URL:          "https://registry.siros.org/api/v1/schemas.json",
			PollInterval: 5 * time.Minute,
			Timeout:      30 * time.Second,
		},
		Cache: RegistryCacheConfig{
			Path:   "data/vctm-cache.json",
			MaxAge: 24 * time.Hour,
		},
		DynamicCache: RegistryDynamicCacheConfig{
			Enabled:      false, // Disabled by default to prevent SSRF
			DefaultTTL:   1 * time.Hour,
			MaxTTL:       24 * time.Hour,
			MinTTL:       5 * time.Minute,
			Timeout:      30 * time.Second,
			AllowedHosts: []string{},
		},
		Filter: RegistryFilterConfig{
			IncludePatterns: []string{},
			ExcludePatterns: []string{},
		},
		RateLimit: RegistryRateLimitConfig{
			Enabled:            true,
			AuthenticatedRPM:   1000,
			UnauthenticatedRPM: 100,
			BurstMultiplier:    3,
		},
	}
}

// Validate validates the registry section on its own (sources, cache,
// filter, dynamic cache, rate limit). It also normalizes Sources and
// compiles the filter / allowed-host patterns. Authentication requirements
// that depend on other config sections are checked by Config.ValidateRegistry.
func (c *RegistryConfig) Validate() error {
	if c.Source.URL == "" && len(c.Sources) == 0 {
		return fmt.Errorf("registry.source.url is required")
	}

	// Normalize: if Sources is empty, populate from the legacy Source field
	if len(c.Sources) == 0 {
		c.Sources = []RegistryRemoteSourceConfig{{URL: c.Source.URL, Mode: c.Source.Mode, Timeout: c.Source.Timeout}}
	}

	// Validate each Sources entry and default Mode to ts11
	for i := range c.Sources {
		if c.Sources[i].URL == "" {
			return fmt.Errorf("registry.sources[%d].url is required", i)
		}
		if c.Sources[i].Mode == "" {
			c.Sources[i].Mode = RegistryAPIModeTS11
		}
		if c.Sources[i].Mode != RegistryAPIModeTS11 && c.Sources[i].Mode != RegistryAPIModeRegistry {
			return fmt.Errorf("registry.sources[%d].mode must be %q or %q, got %q", i, RegistryAPIModeTS11, RegistryAPIModeRegistry, c.Sources[i].Mode)
		}
	}
	if c.Source.PollInterval < time.Second {
		return fmt.Errorf("registry.source.poll_interval must be at least 1 second")
	}

	if c.Cache.Path == "" {
		return fmt.Errorf("registry.cache.path is required")
	}

	if err := c.Filter.Compile(); err != nil {
		return fmt.Errorf("invalid registry.filter configuration: %w", err)
	}

	if c.DynamicCache.Enabled {
		if err := c.DynamicCache.Compile(); err != nil {
			return fmt.Errorf("invalid registry.dynamic_cache configuration: %w", err)
		}
		if c.DynamicCache.DefaultTTL < time.Second {
			return fmt.Errorf("registry.dynamic_cache.default_ttl must be at least 1 second")
		}
		if c.DynamicCache.MinTTL > c.DynamicCache.MaxTTL {
			return fmt.Errorf("registry.dynamic_cache.min_ttl cannot be greater than max_ttl")
		}
	}

	if c.RateLimit.Enabled {
		if c.RateLimit.AuthenticatedRPM < 1 {
			return fmt.Errorf("registry.rate_limit.authenticated_rpm must be positive")
		}
		if c.RateLimit.UnauthenticatedRPM < 1 {
			return fmt.Errorf("registry.rate_limit.unauthenticated_rpm must be positive")
		}
	}
	return nil
}

// RegistryAudience is the audience new-style (asymmetric) access tokens must
// carry to be accepted by the registry role.
const RegistryAudience = "wallet-registry"

// ValidateRegistry validates everything the registry role needs from the
// backend configuration: the registry section itself and, when
// registry.require_auth is true, the as.* / jwt.* fields used to build the
// shared go-tokenauth validator. It is meaningful whether or not the auth
// role runs in the same process (as.enabled may be false: the registry then
// only validates tokens issued by a remote authorization server).
func (c *Config) ValidateRegistry() error {
	if err := c.Registry.Validate(); err != nil {
		return err
	}
	if !c.Registry.RequireAuth {
		return nil
	}

	var missing []string
	if c.AS.ExternalURL == "" && !c.registryLegacyTolerateNoJWKS {
		missing = append(missing, "as.external_url (public base URL of the authorization server; JWKS is fetched from <as.external_url>/auth/.well-known/jwks.json)")
	}
	if c.AS.Issuer == "" && c.JWT.Issuer == "" {
		missing = append(missing, "as.issuer (or jwt.issuer) (expected \"iss\" claim)")
	}
	if c.AS.Legacy.Enabled && len(c.JWT.Secret) < 32 {
		missing = append(missing, "jwt.secret or jwt.secret_path (>= 32 bytes, needed to validate legacy HMAC tokens while as.legacy.enabled is true; or set as.legacy.enabled=false)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("registry.require_auth is true but the token validator is not fully configured; set: %s", strings.Join(missing, "; "))
	}
	return nil
}

// ValidateRegistryStandalone validates the server-level settings used when
// the registry role runs alone (no backend roles): listen address, TLS and
// CORS. In this mode the process listens on server.registry_host /
// server.registry_port (default host:8097), the same default as the retired
// standalone registry binary.
func (c *Config) ValidateRegistryStandalone() error {
	port := c.Server.RegistryPort
	if port == 0 {
		port = 8097
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid server.registry_port: %d", port)
	}
	c.Server.CORS.SetDefaults()
	if c.Server.CORS.AllowCredentials {
		for _, origin := range c.Server.CORS.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("CORS: allow_credentials cannot be true when allowed_origins contains '*'")
			}
		}
	}
	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" {
			return fmt.Errorf("server.tls.cert_file is required when TLS is enabled")
		}
		if c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("server.tls.key_file is required when TLS is enabled")
		}
	}
	if err := c.Server.validateTrustedProxies(); err != nil {
		return err
	}
	return nil
}
