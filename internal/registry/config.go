// Package registry provides a VCTM (Verifiable Credential Type Metadata) registry server.
// It fetches VCTMs from registry.siros.org and serves them via HTTP with rate limiting.
package registry

import (
	"fmt"
	"regexp"
	"time"
)

// Config holds the registry server configuration
type Config struct {
	// Server configuration
	Server ServerConfig `yaml:"server" envconfig:"SERVER"`

	// Registry source configuration
	Source SourceConfig `yaml:"source" envconfig:"SOURCE"`

	// Cache configuration
	Cache CacheConfig `yaml:"cache" envconfig:"CACHE"`

	// DynamicCache configuration for on-demand URL fetching
	DynamicCache DynamicCacheConfig `yaml:"dynamic_cache" envconfig:"DYNAMIC_CACHE"`

	// Filter configuration for include/exclude patterns
	Filter FilterConfig `yaml:"filter" envconfig:"FILTER"`

	// Rate limiting configuration
	RateLimit RateLimitConfig `yaml:"rate_limit" envconfig:"RATE_LIMIT"`

	// JWT configuration for authentication
	JWT JWTConfig `yaml:"jwt" envconfig:"JWT"`

	// Logging configuration
	Logging LoggingConfig `yaml:"logging" envconfig:"LOGGING"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host string `yaml:"host" envconfig:"HOST"`
	Port int    `yaml:"port" envconfig:"PORT"`
}

// Address returns the server address in host:port format
func (c ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// SourceConfig contains upstream registry source configuration
type SourceConfig struct {
	// URL of the upstream registry index (e.g., https://registry.siros.org/.well-known/vctm-registry.json)
	URL string `yaml:"url" envconfig:"URL"`

	// PollInterval is how often to poll the upstream registry for updates
	PollInterval time.Duration `yaml:"poll_interval" envconfig:"POLL_INTERVAL"`

	// Timeout for HTTP requests to the upstream registry
	Timeout time.Duration `yaml:"timeout" envconfig:"TIMEOUT"`
}

// CacheConfig contains disk cache configuration
type CacheConfig struct {
	// Path to the cache file (JSON format)
	Path string `yaml:"path" envconfig:"PATH"`

	// MaxAge is the maximum age of cached data before forcing a refresh
	MaxAge time.Duration `yaml:"max_age" envconfig:"MAX_AGE"`
}

// DynamicCacheConfig contains configuration for on-demand URL fetching
type DynamicCacheConfig struct {
	// Enabled controls whether dynamic URL fetching is active
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

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
	Timeout time.Duration `yaml:"timeout" envconfig:"TIMEOUT"`

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
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

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
	Secret string `yaml:"secret" envconfig:"SECRET"`

	// Issuer is the expected issuer claim in the JWT
	Issuer string `yaml:"issuer" envconfig:"ISSUER"`

	// RequireAuth requires authentication for all requests (if false, unauthenticated access is allowed)
	RequireAuth bool `yaml:"require_auth" envconfig:"REQUIRE_AUTH"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level" envconfig:"LEVEL"`   // debug, info, warn, error
	Format string `yaml:"format" envconfig:"FORMAT"` // json, text
}

// DefaultConfig returns a Config with sensible default values
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8097,
		},
		Source: SourceConfig{
			URL:          "https://registry.siros.org/.well-known/vctm-registry.json",
			PollInterval: 5 * time.Minute,
			Timeout:      30 * time.Second,
		},
		Cache: CacheConfig{
			Path:   "data/vctm-cache.json",
			MaxAge: 24 * time.Hour,
		},
		DynamicCache: DynamicCacheConfig{
			Enabled:      true,
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

	if c.Source.URL == "" {
		return fmt.Errorf("source URL is required")
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
