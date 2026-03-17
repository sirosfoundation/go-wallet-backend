package registry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, "0.0.0.0", config.Server.Host)
	assert.Equal(t, 8097, config.Server.Port)
	assert.Equal(t, "https://registry.siros.org/.well-known/vctm-registry.json", config.Source.URL)
	assert.Equal(t, 5*time.Minute, config.Source.PollInterval)
	assert.Equal(t, 30*time.Second, config.Source.Timeout)
	assert.Equal(t, "data/vctm-cache.json", config.Cache.Path)
	assert.Equal(t, 24*time.Hour, config.Cache.MaxAge)
	assert.True(t, config.RateLimit.Enabled)
	assert.Equal(t, 1000, config.RateLimit.AuthenticatedRPM)
	assert.Equal(t, 100, config.RateLimit.UnauthenticatedRPM)
	assert.Equal(t, 3, config.RateLimit.BurstMultiplier)
	assert.Equal(t, "wallet-backend", config.JWT.Issuer)
	assert.False(t, config.JWT.RequireAuth)
	assert.Equal(t, "info", config.Logging.Level)
	assert.Equal(t, "json", config.Logging.Format)
}

func TestServerConfig_Address(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		port     int
		expected string
	}{
		{
			name:     "default",
			host:     "0.0.0.0",
			port:     8097,
			expected: "0.0.0.0:8097",
		},
		{
			name:     "localhost",
			host:     "127.0.0.1",
			port:     9000,
			expected: "127.0.0.1:9000",
		},
		{
			name:     "empty host",
			host:     "",
			port:     8080,
			expected: ":8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ServerConfig{Host: tt.host, Port: tt.port}
			assert.Equal(t, tt.expected, config.Address())
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*Config)
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid default config",
			modify:      func(c *Config) {},
			expectError: false,
		},
		{
			name: "invalid port - zero",
			modify: func(c *Config) {
				c.Server.Port = 0
			},
			expectError: true,
			errorMsg:    "invalid server port",
		},
		{
			name: "invalid port - too high",
			modify: func(c *Config) {
				c.Server.Port = 70000
			},
			expectError: true,
			errorMsg:    "invalid server port",
		},
		{
			name: "empty source URL",
			modify: func(c *Config) {
				c.Source.URL = ""
			},
			expectError: true,
			errorMsg:    "source URL is required",
		},
		{
			name: "poll interval too short",
			modify: func(c *Config) {
				c.Source.PollInterval = 500 * time.Millisecond
			},
			expectError: true,
			errorMsg:    "poll interval must be at least 1 second",
		},
		{
			name: "empty cache path",
			modify: func(c *Config) {
				c.Cache.Path = ""
			},
			expectError: true,
			errorMsg:    "cache path is required",
		},
		{
			name: "invalid include pattern",
			modify: func(c *Config) {
				c.Filter.IncludePatterns = []string{"[invalid"}
			},
			expectError: true,
			errorMsg:    "invalid include pattern",
		},
		{
			name: "invalid exclude pattern",
			modify: func(c *Config) {
				c.Filter.ExcludePatterns = []string{"(unclosed"}
			},
			expectError: true,
			errorMsg:    "invalid exclude pattern",
		},
		{
			name: "invalid authenticated rate limit",
			modify: func(c *Config) {
				c.RateLimit.AuthenticatedRPM = 0
			},
			expectError: true,
			errorMsg:    "authenticated rate limit must be positive",
		},
		{
			name: "invalid unauthenticated rate limit",
			modify: func(c *Config) {
				c.RateLimit.UnauthenticatedRPM = -1
			},
			expectError: true,
			errorMsg:    "unauthenticated rate limit must be positive",
		},
		{
			name: "require auth without secret",
			modify: func(c *Config) {
				c.JWT.RequireAuth = true
				c.JWT.Secret = ""
			},
			expectError: true,
			errorMsg:    "JWT secret is required when authentication is required",
		},
		{
			name: "require auth with secret",
			modify: func(c *Config) {
				c.JWT.RequireAuth = true
				c.JWT.Secret = "my-secret"
			},
			expectError: false,
		},
		{
			name: "rate limit disabled - zero values ok",
			modify: func(c *Config) {
				c.RateLimit.Enabled = false
				c.RateLimit.AuthenticatedRPM = 0
				c.RateLimit.UnauthenticatedRPM = 0
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			tt.modify(config)

			err := config.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
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
			filter := &FilterConfig{
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
			filter := &FilterConfig{
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
