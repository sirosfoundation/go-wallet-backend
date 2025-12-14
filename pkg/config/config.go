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
}

// ServerConfig contains HTTP server configuration
type ServerConfig struct {
	Host     string `yaml:"host" envconfig:"HOST" default:"0.0.0.0"`
	Port     int    `yaml:"port" envconfig:"PORT" default:"8080"`
	RPID     string `yaml:"rp_id" envconfig:"RP_ID" default:"localhost"`
	RPOrigin string `yaml:"rp_origin" envconfig:"RP_ORIGIN" default:"http://localhost:8080"`
	RPName   string `yaml:"rp_name" envconfig:"RP_NAME" default:"Wallet Backend"`
	BaseURL  string `yaml:"base_url" envconfig:"BASE_URL"`
}

// StorageConfig contains storage configuration
type StorageConfig struct {
	Type    string        `yaml:"type" envconfig:"TYPE" default:"memory"` // memory, sqlite, mongodb
	SQLite  SQLiteConfig  `yaml:"sqlite" envconfig:"SQLITE"`
	MongoDB MongoDBConfig `yaml:"mongodb" envconfig:"MONGODB"`
}

// SQLiteConfig contains SQLite-specific configuration
type SQLiteConfig struct {
	Path string `yaml:"path" envconfig:"PATH" default:"wallet.db"`
}

// MongoDBConfig contains MongoDB-specific configuration
type MongoDBConfig struct {
	URI      string `yaml:"uri" envconfig:"URI" default:"mongodb://localhost:27017"`
	Database string `yaml:"database" envconfig:"DATABASE" default:"wallet"`
	Timeout  int    `yaml:"timeout" envconfig:"TIMEOUT" default:"10"` // seconds
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level" envconfig:"LEVEL" default:"info"`   // debug, info, warn, error
	Format string `yaml:"format" envconfig:"FORMAT" default:"json"` // json, text
}

// JWTConfig contains JWT configuration
type JWTConfig struct {
	Secret      string `yaml:"secret" envconfig:"SECRET"`
	ExpiryHours int    `yaml:"expiry_hours" envconfig:"EXPIRY_HOURS" default:"24"`
	RefreshDays int    `yaml:"refresh_days" envconfig:"REFRESH_DAYS" default:"7"`
	Issuer      string `yaml:"issuer" envconfig:"ISSUER" default:"wallet-backend"`
}

// WalletProviderConfig contains wallet provider key attestation configuration
type WalletProviderConfig struct {
	PrivateKeyPath  string `yaml:"private_key_path" envconfig:"PRIVATE_KEY_PATH"`
	CertificatePath string `yaml:"certificate_path" envconfig:"CERTIFICATE_PATH"`
	CACertPath      string `yaml:"ca_cert_path" envconfig:"CA_CERT_PATH"`
}

// Load loads configuration from file and environment variables
func Load(configFile string) (*Config, error) {
	cfg := &Config{}

	// Load from YAML file if provided
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

	// Override with environment variables
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
