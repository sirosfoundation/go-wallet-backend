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

	return cfg, nil
}

// defaultConfig returns a Config with sensible default values
func defaultConfig() *Config {
	return &Config{
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
