package config

import (
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	Server         ServerConfig         `yaml:"server" envconfig:"SERVER"`
	Storage        StorageConfig        `yaml:"storage" envconfig:"STORAGE"`
	Logging        LoggingConfig        `yaml:"logging" envconfig:"LOGGING"`
	JWT            JWTConfig            `yaml:"jwt" envconfig:"JWT"`
	WalletProvider WalletProviderConfig `yaml:"wallet_provider" envconfig:"WALLET_PROVIDER"`
	Trust          TrustConfig          `yaml:"trust" envconfig:"TRUST"`
	SessionStore   SessionStoreConfig   `yaml:"session_store" envconfig:"SESSION_STORE"`
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host         string `yaml:"host" envconfig:"HOST"`
	Port         int    `yaml:"port" envconfig:"PORT"`
	AdminHost    string `yaml:"admin_host" envconfig:"ADMIN_HOST"`       // Admin API bind address (defaults to Host)
	AdminPort    int    `yaml:"admin_port" envconfig:"ADMIN_PORT"`       // Internal admin API port (0 to disable)
	EngineHost   string `yaml:"engine_host" envconfig:"ENGINE_HOST"`     // WebSocket engine bind address (defaults to Host)
	EnginePort   int    `yaml:"engine_port" envconfig:"ENGINE_PORT"`     // WebSocket engine port (defaults to Port if 0)
	RegistryHost string `yaml:"registry_host" envconfig:"REGISTRY_HOST"` // Registry bind address (defaults to Host)
	RegistryPort int    `yaml:"registry_port" envconfig:"REGISTRY_PORT"` // VCTM registry port (defaults to 8097)
	AdminToken   string `yaml:"admin_token" envconfig:"ADMIN_TOKEN"`     // Bearer token for admin API (auto-generated if empty)
	RPID         string `yaml:"rp_id" envconfig:"RP_ID"`
	RPOrigin     string `yaml:"rp_origin" envconfig:"RP_ORIGIN"`
	RPName       string `yaml:"rp_name" envconfig:"RP_NAME"`
	BaseURL      string `yaml:"base_url" envconfig:"BASE_URL"`

	// CORS configuration
	CORS CORSConfig `yaml:"cors" envconfig:"CORS"`

	// ExternalURLs for split-mode deployment (when services run separately)
	ExternalURLs ExternalURLsConfig `yaml:"external_urls" envconfig:"EXTERNAL_URLS"`
}

// CORSConfig contains CORS (Cross-Origin Resource Sharing) configuration
type CORSConfig struct {
	// AllowedOrigins is a list of origins that may access the resource.
	// Use "*" to allow all origins (default for development).
	AllowedOrigins []string `yaml:"allowed_origins" envconfig:"ALLOWED_ORIGINS"`

	// AllowedMethods is a list of HTTP methods allowed for cross-origin requests.
	AllowedMethods []string `yaml:"allowed_methods" envconfig:"ALLOWED_METHODS"`

	// AllowedHeaders is a list of request headers allowed in cross-origin requests.
	AllowedHeaders []string `yaml:"allowed_headers" envconfig:"ALLOWED_HEADERS"`

	// ExposedHeaders is a list of headers that browsers are allowed to access.
	ExposedHeaders []string `yaml:"exposed_headers" envconfig:"EXPOSED_HEADERS"`

	// AllowCredentials indicates whether the request can include credentials.
	// Cannot be true when AllowedOrigins is "*".
	AllowCredentials bool `yaml:"allow_credentials" envconfig:"ALLOW_CREDENTIALS"`

	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached.
	MaxAge int `yaml:"max_age" envconfig:"MAX_AGE"`
}

// SetDefaults sets default values for CORS configuration
func (c *CORSConfig) SetDefaults() {
	if len(c.AllowedOrigins) == 0 {
		c.AllowedOrigins = []string{"*"}
	}
	if len(c.AllowedMethods) == 0 {
		c.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	}
	if len(c.AllowedHeaders) == 0 {
		c.AllowedHeaders = []string{
			"Authorization", "Content-Type", "X-Tenant-ID",
			"If-None-Match", "X-Private-Data-If-Match", "X-Private-Data-If-None-Match",
			"Upgrade", "Connection", "Sec-WebSocket-Key",
			"Sec-WebSocket-Version", "Sec-WebSocket-Protocol",
		}
	}
	if len(c.ExposedHeaders) == 0 {
		c.ExposedHeaders = []string{"X-Private-Data-ETag"}
	}
	if c.MaxAge == 0 {
		c.MaxAge = 43200 // 12 hours
	}
}

// ExternalURLsConfig contains URLs for split-mode deployment
// When services run as separate containers/pods, they need external URLs to reference each other.
type ExternalURLsConfig struct {
	// BackendURL is the external URL for the backend service (for engine → backend calls)
	BackendURL string `yaml:"backend_url" envconfig:"BACKEND_URL"`

	// EngineURL is the external URL for the engine service (for WebSocket connections)
	EngineURL string `yaml:"engine_url" envconfig:"ENGINE_URL"`

	// RegistryURL is the external URL for the registry service (for VCTM lookups)
	RegistryURL string `yaml:"registry_url" envconfig:"REGISTRY_URL"`

	// AdminURL is the external URL for the admin API (for inter-service admin calls)
	AdminURL string `yaml:"admin_url" envconfig:"ADMIN_URL"`
}

// GetBackendURL returns the backend URL, with fallback to localhost
func (e *ExternalURLsConfig) GetBackendURL(host string, port int) string {
	if e.BackendURL != "" {
		return e.BackendURL
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// GetEngineURL returns the engine URL, with fallback to localhost
func (e *ExternalURLsConfig) GetEngineURL(host string, port int) string {
	if e.EngineURL != "" {
		return e.EngineURL
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// GetRegistryURL returns the registry URL, with fallback to localhost
func (e *ExternalURLsConfig) GetRegistryURL(host string, port int) string {
	if e.RegistryURL != "" {
		return e.RegistryURL
	}
	return fmt.Sprintf("http://%s:%d", host, port)
}

// GetAdminURL returns the admin URL, with fallback to localhost
func (e *ExternalURLsConfig) GetAdminURL(host string, port int) string {
	if e.AdminURL != "" {
		return e.AdminURL
	}
	return fmt.Sprintf("http://%s:%d", host, port)
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

// TrustConfig contains trust evaluation configuration
type TrustConfig struct {
	// DefaultEndpoint is the go-trust PDP endpoint for trust evaluation.
	// Tenants can override this with their own endpoint.
	DefaultEndpoint string `yaml:"default_endpoint" envconfig:"DEFAULT_ENDPOINT"`
	// RegistryURL is the URL for the VCTM registry service.
	RegistryURL string `yaml:"registry_url" envconfig:"REGISTRY_URL"`
	// Timeout is the HTTP timeout for trust evaluation requests (seconds).
	Timeout int `yaml:"timeout" envconfig:"TIMEOUT"`
}

// SessionStoreConfig contains WebSocket session store configuration
type SessionStoreConfig struct {
	// Type is the session store type: "memory" or "redis"
	Type string `yaml:"type" envconfig:"TYPE"`
	// Redis contains Redis-specific configuration
	Redis RedisConfig `yaml:"redis" envconfig:"REDIS"`
	// DefaultTTL is the default session TTL in hours
	DefaultTTLHours int `yaml:"default_ttl_hours" envconfig:"DEFAULT_TTL_HOURS"`
}

// RedisConfig contains Redis connection configuration
type RedisConfig struct {
	Address   string `yaml:"address" envconfig:"ADDRESS"`
	Password  string `yaml:"password" envconfig:"PASSWORD"`
	DB        int    `yaml:"db" envconfig:"DB"`
	KeyPrefix string `yaml:"key_prefix" envconfig:"KEY_PREFIX"`
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

	// Ensure CORS has defaults
	cfg.Server.CORS.SetDefaults()

	return cfg, nil
}

// defaultConfig returns a Config with sensible default values
func defaultConfig() *Config {
	corsConfig := CORSConfig{}
	corsConfig.SetDefaults()

	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			AdminPort:    8081, // Internal admin API port
			EnginePort:   8082, // WebSocket engine port
			RegistryPort: 8097, // VCTM registry port
			RPID:         "localhost",
			RPOrigin:     "http://localhost:8080",
			RPName:       "Wallet Backend",
			CORS:         corsConfig,
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
			Timeout: 30, // seconds
		},
		SessionStore: SessionStoreConfig{
			Type:            "memory",
			DefaultTTLHours: 24,
			Redis: RedisConfig{
				Address:   "localhost:6379",
				KeyPrefix: "ws:session:",
			},
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

	// Validate CORS: AllowCredentials cannot be true with wildcard origins
	if c.Server.CORS.AllowCredentials {
		for _, origin := range c.Server.CORS.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("CORS: allow_credentials cannot be true when allowed_origins contains '*'")
			}
		}
	}

	return nil
}

// Address returns the server address
func (c *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// AdminAddress returns the admin server address
func (c *ServerConfig) AdminAddress() string {
	host := c.AdminHost
	if host == "" {
		host = c.Host
	}
	return fmt.Sprintf("%s:%d", host, c.AdminPort)
}

// EngineAddress returns the engine server address
func (c *ServerConfig) EngineAddress() string {
	host := c.EngineHost
	if host == "" {
		host = c.Host
	}
	port := c.EnginePort
	if port == 0 {
		port = c.Port // fallback to main port for backward compatibility
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// RegistryAddress returns the registry server address
func (c *ServerConfig) RegistryAddress() string {
	host := c.RegistryHost
	if host == "" {
		host = c.Host
	}
	port := c.RegistryPort
	if port == 0 {
		port = 8097 // default registry port
	}
	return fmt.Sprintf("%s:%d", host, port)
}
