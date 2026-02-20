package config

import (
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Mode is the application mode: "production" or "development"
	// In development mode, security checks (proxy filtering, etc.) are relaxed.
	Mode           string               `yaml:"mode" envconfig:"MODE"`
	Server         ServerConfig         `yaml:"server" envconfig:"SERVER"`
	Storage        StorageConfig        `yaml:"storage" envconfig:"STORAGE"`
	Logging        LoggingConfig        `yaml:"logging" envconfig:"LOGGING"`
	JWT            JWTConfig            `yaml:"jwt" envconfig:"JWT"`
	WalletProvider WalletProviderConfig `yaml:"wallet_provider" envconfig:"WALLET_PROVIDER"`
	Trust          TrustConfig          `yaml:"trust" envconfig:"TRUST"`
	Proxy          ProxyConfig          `yaml:"proxy" envconfig:"PROXY"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit" envconfig:"RATE_LIMIT"`
	OHTTP          OHTTPConfig          `yaml:"ohttp" envconfig:"OHTTP"`
}

// IsDevelopment returns true if running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.Mode == "development" || c.Mode == "dev"
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host       string `yaml:"host" envconfig:"HOST"`
	Port       int    `yaml:"port" envconfig:"PORT"`
	AdminPort  int    `yaml:"admin_port" envconfig:"ADMIN_PORT"`   // Internal admin API port (0 to disable)
	AdminToken string `yaml:"admin_token" envconfig:"ADMIN_TOKEN"` // Bearer token for admin API (auto-generated if empty)
	RPID       string `yaml:"rp_id" envconfig:"RP_ID"`
	RPOrigin   string `yaml:"rp_origin" envconfig:"RP_ORIGIN"`
	RPName     string `yaml:"rp_name" envconfig:"RP_NAME"`
	BaseURL    string `yaml:"base_url" envconfig:"BASE_URL"`
}

// StorageConfig contains storage configuration
type StorageConfig struct {
	Type    string        `yaml:"type" envconfig:"TYPE"` // memory, sqlite, mongodb
	SQLite  SQLiteConfig  `yaml:"sqlite" envconfig:"SQLITE"`
	MongoDB MongoDBConfig `yaml:"mongodb" envconfig:"MONGODB"`
}

// SQLiteConfig contains SQLite-specific configuration
type SQLiteConfig struct {
	Path string `yaml:"path" envconfig:"DB_PATH"`
}

// MongoDBConfig contains MongoDB-specific configuration
type MongoDBConfig struct {
	URI      string `yaml:"uri" envconfig:"URI"`
	Database string `yaml:"database" envconfig:"DATABASE"`
	Timeout  int    `yaml:"timeout" envconfig:"TIMEOUT"` // seconds
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level" envconfig:"LEVEL"`   // debug, info, warn, error
	Format string `yaml:"format" envconfig:"FORMAT"` // json, text
}

// JWTConfig contains JWT configuration
type JWTConfig struct {
	Secret      string `yaml:"secret" envconfig:"SECRET"`
	ExpiryHours int    `yaml:"expiry_hours" envconfig:"EXPIRY_HOURS"`
	RefreshDays int    `yaml:"refresh_days" envconfig:"REFRESH_DAYS"`
	Issuer      string `yaml:"issuer" envconfig:"ISSUER"`
}

// WalletProviderConfig contains wallet provider key attestation configuration
type WalletProviderConfig struct {
	PrivateKeyPath  string `yaml:"private_key_path" envconfig:"PRIVATE_KEY_PATH"`
	CertificatePath string `yaml:"certificate_path" envconfig:"CERTIFICATE_PATH"`
	CACertPath      string `yaml:"ca_cert_path" envconfig:"CA_CERT_PATH"`
}

// TrustConfig contains trust evaluation configuration (ADR 010)
type TrustConfig struct {
	// Type is the trust evaluator type: "none", "x509", "authzen", or "composite"
	Type string `yaml:"type" envconfig:"TYPE"`
	// X509 configuration for the X.509 certificate evaluator
	X509 X509TrustConfig `yaml:"x509" envconfig:"X509"`
	// AuthZEN configuration for the AuthZEN PDP evaluator
	AuthZEN AuthZENConfig `yaml:"authzen" envconfig:"AUTHZEN"`
}

// X509TrustConfig contains X.509 certificate trust configuration
type X509TrustConfig struct {
	// RootCertPaths are paths to root CA certificate files (PEM format)
	RootCertPaths []string `yaml:"root_cert_paths" envconfig:"ROOT_CERT_PATHS"`
	// IntermediateCertPaths are paths to intermediate CA certificate files
	IntermediateCertPaths []string `yaml:"intermediate_cert_paths" envconfig:"INTERMEDIATE_CERT_PATHS"`
}

// AuthZENConfig contains AuthZEN PDP configuration
type AuthZENConfig struct {
	// BaseURL is the base URL of the AuthZEN PDP service (e.g., "https://pdp.example.com")
	BaseURL string `yaml:"base_url" envconfig:"BASE_URL"`
	// Timeout is the HTTP request timeout in seconds (default 30)
	Timeout int `yaml:"timeout" envconfig:"TIMEOUT"`
	// UseDiscovery enables .well-known/authzen-configuration discovery
	UseDiscovery bool `yaml:"use_discovery" envconfig:"USE_DISCOVERY"`
}

// ProxyConfig contains HTTP proxy security configuration.
//
// Security model (all individually configurable):
//   - RequireHTTPS is the PRIMARY defense against SSRF. Cloud metadata endpoints
//     and internal services don't have valid TLS certificates.
//   - BlockLoopback prevents access to localhost services.
//   - BlockLinkLocal blocks cloud metadata at 169.254.169.254.
//   - BlockRFC1918 is defense-in-depth (can be bypassed via DNS rebinding).
//
// In development mode, set all Block* options to false to allow local testing.
type ProxyConfig struct {
	// Enabled turns proxy filtering on/off (default: true)
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
	// RequireHTTPS requires all proxied URLs to use HTTPS (PRIMARY SSRF defense)
	RequireHTTPS bool `yaml:"require_https" envconfig:"REQUIRE_HTTPS"`
	// BlockLoopback blocks localhost and 127.0.0.0/8
	BlockLoopback bool `yaml:"block_loopback" envconfig:"BLOCK_LOOPBACK"`
	// BlockLinkLocal blocks link-local addresses (169.254.0.0/16) including cloud metadata
	BlockLinkLocal bool `yaml:"block_link_local" envconfig:"BLOCK_LINK_LOCAL"`
	// BlockRFC1918 blocks RFC 1918 private addresses (defense-in-depth)
	BlockRFC1918 bool `yaml:"block_rfc1918" envconfig:"BLOCK_RFC1918"`
	// BlockedHosts is a list of blocked hostnames
	BlockedHosts []string `yaml:"blocked_hosts" envconfig:"BLOCKED_HOSTS"`
	// Timeout is the proxy request timeout in seconds
	Timeout int `yaml:"timeout" envconfig:"TIMEOUT"`
	// SeenHostsTTL is how long to remember contacted hosts (seconds, 0 = forever)
	SeenHostsTTL int `yaml:"seen_hosts_ttl" envconfig:"SEEN_HOSTS_TTL"`
	// MaxSeenHosts limits the seen hosts cache size
	MaxSeenHosts int `yaml:"max_seen_hosts" envconfig:"MAX_SEEN_HOSTS"`
}

// RateLimitConfig contains rate limiting configuration
type RateLimitConfig struct {
	// Enabled turns rate limiting on/off
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`
	// RequestsPerMinute is the max requests per minute per user/IP
	RequestsPerMinute int `yaml:"requests_per_minute" envconfig:"REQUESTS_PER_MINUTE"`
	// BurstSize allows temporary bursts above the limit
	BurstSize int `yaml:"burst_size" envconfig:"BURST_SIZE"`
	// ProxyRequestsPerMinute is a stricter limit for proxy requests
	ProxyRequestsPerMinute int `yaml:"proxy_requests_per_minute" envconfig:"PROXY_REQUESTS_PER_MINUTE"`
	// ProxyBurstSize is the burst size for proxy requests
	ProxyBurstSize int `yaml:"proxy_burst_size" envconfig:"PROXY_BURST_SIZE"`
}

// OHTTPConfig contains Oblivious HTTP (RFC 9458) configuration.
//
// OHTTP provides IP unlinkability between wallet users and target servers
// (issuers, verifiers). Two modes are supported:
//
//  1. Integrated relay: Backend acts as both relay and gateway. The wallet's IP
//     is hidden from target servers, but the backend sees both.
//
//  2. External relay: An external relay forwards to the backend gateway. This
//     provides full privacy separation (relay sees wallet IP, gateway sees
//     target URL, neither sees both).
type OHTTPConfig struct {
	// Enabled turns OHTTP on/off (default: false, opt-in)
	Enabled bool `yaml:"enabled" envconfig:"ENABLED"`

	// KeyID identifies the gateway key (1-255, for key rotation)
	KeyID uint8 `yaml:"key_id" envconfig:"KEY_ID"`

	// PrivateKeyFile is the path to the gateway's private key file.
	// If empty, a new ephemeral key is generated on each startup (not recommended for production).
	// If the file doesn't exist and CreateKey is true, a new key will be generated and saved.
	PrivateKeyFile string `yaml:"private_key_file" envconfig:"PRIVATE_KEY_FILE"`

	// CreateKey creates and saves a new private key if the file doesn't exist.
	CreateKey bool `yaml:"create_key" envconfig:"CREATE_KEY"`

	// IntegratedRelay enables the /api/relay endpoint for frontend use.
	// When true, the frontend can send OHTTP requests directly to the backend.
	// When false, an external relay must be used.
	IntegratedRelay bool `yaml:"integrated_relay" envconfig:"INTEGRATED_RELAY"`

	// MaxRequestSize limits the size of OHTTP requests in bytes (default: 1MB)
	MaxRequestSize int64 `yaml:"max_request_size" envconfig:"MAX_REQUEST_SIZE"`
}

// Load loads configuration from file and environment variables
func Load(configFile string) (*Config, error) {
	// Start with defaults
	cfg := defaultConfig()

	// Load from YAML file if provided (overrides defaults)
	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
			// File doesn't exist, that's ok - we'll use defaults and env vars
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables (highest priority)
	// Since we removed `default:` tags, this only applies actual env vars
	if err := envconfig.Process("WALLET", cfg); err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Set BaseURL if not provided
	if cfg.Server.BaseURL == "" {
		cfg.Server.BaseURL = fmt.Sprintf("http://%s:%d", cfg.Server.Host, cfg.Server.Port)
	}

	// Apply development mode overrides if configured
	if cfg.IsDevelopment() {
		applyDevelopmentDefaults(cfg)
	}

	return cfg, nil
}

// applyDevelopmentDefaults relaxes security settings for local development.
func applyDevelopmentDefaults(cfg *Config) {
	// Relax proxy security for local testing
	cfg.Proxy.RequireHTTPS = false
	cfg.Proxy.BlockLoopback = false
	cfg.Proxy.BlockLinkLocal = false
	cfg.Proxy.BlockRFC1918 = false
	cfg.Proxy.BlockedHosts = nil

	// Optionally disable rate limiting in dev
	// cfg.RateLimit.Enabled = false
}

// defaultConfig returns a Config with sensible default values
func defaultConfig() *Config {
	return &Config{
		Mode: "production", // Default to production (secure)
		Server: ServerConfig{
			Host:      "0.0.0.0",
			Port:      8080,
			AdminPort: 8081, // Internal admin API port
			RPID:      "localhost",
			RPOrigin:  "http://localhost:8080",
			RPName:    "Wallet Backend",
		},
		Storage: StorageConfig{
			Type: "memory",
			SQLite: SQLiteConfig{
				Path: "wallet.db",
			},
			MongoDB: MongoDBConfig{
				URI:      "mongodb://localhost:27017",
				Database: "wallet",
				Timeout:  10,
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		JWT: JWTConfig{
			ExpiryHours: 24,
			RefreshDays: 7,
			Issuer:      "wallet-backend",
		},
		Trust: TrustConfig{
			Type: "none",
			AuthZEN: AuthZENConfig{
				Timeout: 30,
			},
		},
		Proxy: ProxyConfig{
			Enabled:        true,
			RequireHTTPS:   true,  // Primary SSRF defense
			BlockLoopback:  true,  // Block localhost access
			BlockLinkLocal: true,  // Block cloud metadata (169.254.169.254)
			BlockRFC1918:   true,  // Defense-in-depth
			BlockedHosts: []string{
				"metadata.google.internal",
			},
			Timeout:      30,
			SeenHostsTTL: 3600, // 1 hour
			MaxSeenHosts: 100,
		},
		RateLimit: RateLimitConfig{
			Enabled:                true,
			RequestsPerMinute:      120,
			BurstSize:              20,
			ProxyRequestsPerMinute: 30, // Stricter for proxy
			ProxyBurstSize:         5,
		},
		OHTTP: OHTTPConfig{
			Enabled:         false, // Opt-in feature
			KeyID:           1,
			IntegratedRelay: true,              // Default to integrated mode
			MaxRequestSize:  1 << 20,           // 1 MB
			CreateKey:       true,              // Auto-generate if missing
		},
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", c.Server.Port)
	}

	if c.Server.RPID == "" {
		return fmt.Errorf("rp_id is required")
	}

	if c.Server.RPOrigin == "" {
		return fmt.Errorf("rp_origin is required")
	}

	if c.Storage.Type != "memory" && c.Storage.Type != "sqlite" && c.Storage.Type != "mongodb" {
		return fmt.Errorf("invalid storage type: %s (must be memory, sqlite, or mongodb)", c.Storage.Type)
	}

	if c.Storage.Type == "mongodb" && c.Storage.MongoDB.URI == "" {
		return fmt.Errorf("mongodb uri is required when using mongodb storage")
	}

	if c.JWT.Secret == "" {
		return fmt.Errorf("jwt secret is required")
	}

	return nil
}

// Address returns the server address
func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// AdminAddress returns the admin server address
func (c *ServerConfig) AdminAddress() string {
	return fmt.Sprintf("%s:%d", c.Host, c.AdminPort)
}
