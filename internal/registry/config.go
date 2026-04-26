// Package registry provides a VCTM (Verifiable Credential Type Metadata) registry server.
// It fetches VCTMs from registry.siros.org and serves them via HTTP with rate limiting.
package registry

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/internal/embed"
	pkgconfig "github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Config holds the registry server configuration
type Config struct {
	// Server configuration
	Server ServerConfig `yaml:"server"`

	// Source is the legacy single-registry source configuration.
	// Use Sources for multi-registry support. If Sources is empty, Source is used.
	Source SourceConfig `yaml:"source"`

	// Sources is a list of registry sources to fetch from.
	// Schemas fetched from later sources in the list overwrite earlier ones,
	// allowing a registry to extend or override another.
	// When non-empty, the Source field is ignored for URL fetching (but
	// Source.PollInterval and Source.LocalOverrides are still used).
	Sources []SourceConfig `yaml:"sources"`

	// Cache configuration
	Cache CacheConfig `yaml:"cache"`

	// DynamicCache configuration for on-demand URL fetching
	DynamicCache DynamicCacheConfig `yaml:"dynamic_cache" envconfig:"DYNAMIC_CACHE"`

	// ImageEmbed configuration for embedding images as data URIs
	ImageEmbed embed.Config `yaml:"image_embed" envconfig:"IMAGE_EMBED"`

	// Filter configuration for include/exclude patterns
	Filter FilterConfig `yaml:"filter"`

	// Rate limiting configuration
	RateLimit RateLimitConfig `yaml:"rate_limit" envconfig:"RATE_LIMIT"`

	// JWT configuration for authentication
	JWT JWTConfig `yaml:"jwt"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging"`

	// HTTPClient configuration for outbound requests (proxy, TLS settings)
	HTTPClient pkgconfig.HTTPClientConfig `yaml:"http_client" envconfig:"HTTP_CLIENT"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host           string              `yaml:"host"`
	Port           int                 `yaml:"port"`
	ServedByHeader *string             `yaml:"served_by_header"`
	TLS            pkgconfig.TLSConfig `yaml:"tls"`
}

// Address returns the server address in host:port format
func (c ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// ResolvedServedBy returns the resolved X-Served-By header value.
func (c ServerConfig) ResolvedServedBy() string {
	if c.ServedByHeader == nil {
		h, err := os.Hostname()
		if err != nil {
			return "unknown"
		}
		return h
	}
	return *c.ServedByHeader
}

// SourceConfig contains upstream registry source configuration
type SourceConfig struct {
	// URL of the upstream registry index.
	// Supports both the legacy vctm-registry.json format and the TS11-compliant
	// /api/v1/schemas.json endpoint – the format is auto-detected from the response.
	URL string `yaml:"url"`

	// LocalOverrides is a list of local file or directory paths containing VCTM JSON files.
	// These are loaded at startup and take priority over entries fetched from the remote registry.
	// Directories are scanned for *.json files. Entries are keyed by their "vct" field.
	LocalOverrides []string `yaml:"local_overrides" envconfig:"LOCAL_OVERRIDES"`

	// PollInterval is how often to poll the upstream registry for updates
	PollInterval time.Duration `yaml:"poll_interval" envconfig:"POLL_INTERVAL"`

	// Timeout for HTTP requests to the upstream registry
	Timeout time.Duration `yaml:"timeout"`
}

// CacheConfig contains disk cache configuration
type CacheConfig struct {
	// Path to the cache file (JSON format)
	Path string `yaml:"path"`

	// MaxAge is the maximum age of cached data before forcing a refresh
	MaxAge time.Duration `yaml:"max_age" envconfig:"MAX_AGE"`
}

// DynamicCacheConfig contains configuration for on-demand URL fetching
type DynamicCacheConfig struct {
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
func (d *DynamicCacheConfig) Compile() error {
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
func (d *DynamicCacheConfig) IsHostAllowed(host string) bool {
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

// FilterConfig contains VCT ID filtering configuration
type FilterConfig struct {
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
func (f *FilterConfig) Compile() error {
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
func (f *FilterConfig) Matches(vctID string) bool {
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

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	// Enabled controls whether rate limiting is active
	Enabled bool `yaml:"enabled"`

	// AuthenticatedRPM is requests per minute for authenticated clients
	AuthenticatedRPM int `yaml:"authenticated_rpm" envconfig:"AUTHENTICATED_RPM"`

	// UnauthenticatedRPM is requests per minute for unauthenticated clients
	UnauthenticatedRPM int `yaml:"unauthenticated_rpm" envconfig:"UNAUTHENTICATED_RPM"`

	// BurstMultiplier allows bursts of this multiple of the rate limit
	BurstMultiplier int `yaml:"burst_multiplier" envconfig:"BURST_MULTIPLIER"`
}

// JWTConfig contains JWT validation configuration
type JWTConfig struct {
	// Secret is the shared secret for validating JWT signatures (HMAC)
	Secret string `yaml:"secret"`

	// Issuer is the expected issuer claim in the JWT
	Issuer string `yaml:"issuer"`

	// RequireAuth requires authentication for all requests (if false, unauthenticated access is allowed)
	RequireAuth bool `yaml:"require_auth" envconfig:"REQUIRE_AUTH"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
}

// DefaultConfig returns a Config with sensible default values
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8097,
		},
		Source: SourceConfig{
			URL:          "https://registry.siros.org/api/v1/schemas.json",
			PollInterval: 5 * time.Minute,
			Timeout:      30 * time.Second,
		},
		Cache: CacheConfig{
			Path:   "data/vctm-cache.json",
			MaxAge: 24 * time.Hour,
		},
		DynamicCache: DynamicCacheConfig{
			Enabled:      false, // Disabled by default to prevent SSRF
			DefaultTTL:   1 * time.Hour,
			MaxTTL:       24 * time.Hour,
			MinTTL:       5 * time.Minute,
			Timeout:      30 * time.Second,
			AllowedHosts: []string{},
		},
		Filter: FilterConfig{
			IncludePatterns: []string{},
			ExcludePatterns: []string{},
		},
		RateLimit: RateLimitConfig{
			Enabled:            true,
			AuthenticatedRPM:   1000,
			UnauthenticatedRPM: 100,
			BurstMultiplier:    3,
		},
		JWT: JWTConfig{
			Issuer:      "wallet-backend",
			RequireAuth: false,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	// Validate TLS configuration
	if c.Server.TLS.Enabled {
		if c.Server.TLS.CertFile == "" {
			return fmt.Errorf("server.tls.cert_file is required when TLS is enabled")
		}
		if c.Server.TLS.KeyFile == "" {
			return fmt.Errorf("server.tls.key_file is required when TLS is enabled")
		}
	}

	if c.Source.URL == "" && len(c.Sources) == 0 {
		return fmt.Errorf("source URL is required")
	}

	// Normalize: if Sources is empty, populate from the legacy Source field
	if len(c.Sources) == 0 {
		c.Sources = []SourceConfig{c.Source}
	}

	for i, source := range c.Sources {
		if source.URL == "" {
			return fmt.Errorf("sources[%d].url is required", i)
		}
	}
	if c.Source.PollInterval < time.Second {
		return fmt.Errorf("poll interval must be at least 1 second")
	}

	if c.Cache.Path == "" {
		return fmt.Errorf("cache path is required")
	}

	// Compile filter patterns
	if err := c.Filter.Compile(); err != nil {
		return fmt.Errorf("invalid filter configuration: %w", err)
	}

	// Compile dynamic cache patterns and validate
	if c.DynamicCache.Enabled {
		if err := c.DynamicCache.Compile(); err != nil {
			return fmt.Errorf("invalid dynamic cache configuration: %w", err)
		}
		if c.DynamicCache.DefaultTTL < time.Second {
			return fmt.Errorf("dynamic cache default TTL must be at least 1 second")
		}
		if c.DynamicCache.MinTTL > c.DynamicCache.MaxTTL {
			return fmt.Errorf("dynamic cache min TTL cannot be greater than max TTL")
		}
	}

	if c.RateLimit.Enabled {
		if c.RateLimit.AuthenticatedRPM < 1 {
			return fmt.Errorf("authenticated rate limit must be positive")
		}
		if c.RateLimit.UnauthenticatedRPM < 1 {
			return fmt.Errorf("unauthenticated rate limit must be positive")
		}
	}

	// JWT secret is only required if RequireAuth is true
	if c.JWT.RequireAuth && c.JWT.Secret == "" {
		return fmt.Errorf("JWT secret is required when authentication is required")
	}

	return nil
}
