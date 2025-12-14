package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		Storage: StorageConfig{Type: "memory"},
		JWT:     JWTConfig{Secret: "test"},
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

func TestConfig_Validate_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"port too low", 0},
		{"port negative", -1},
		{"port too high", 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{
					Host:     "localhost",
					Port:     tt.port,
					RPID:     "localhost",
					RPOrigin: "http://localhost:8080",
				},
				Storage: StorageConfig{Type: "memory"},
				JWT:     JWTConfig{Secret: "test"},
			}

			err := cfg.Validate()
			if err == nil {
				t.Error("Expected validation error for invalid port")
			}
		})
	}
}

func TestConfig_Validate_MissingRPID(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "",
			RPOrigin: "http://localhost:8080",
		},
		Storage: StorageConfig{Type: "memory"},
		JWT:     JWTConfig{Secret: "test"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing RPID")
	}
}

func TestConfig_Validate_MissingRPOrigin(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "",
		},
		Storage: StorageConfig{Type: "memory"},
		JWT:     JWTConfig{Secret: "test"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing RPOrigin")
	}
}

func TestConfig_Validate_InvalidStorageType(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		Storage: StorageConfig{Type: "invalid"},
		JWT:     JWTConfig{Secret: "test"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for invalid storage type")
	}
}

func TestConfig_Validate_MongoDBWithoutURI(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		Storage: StorageConfig{
			Type:    "mongodb",
			MongoDB: MongoDBConfig{URI: ""},
		},
		JWT: JWTConfig{Secret: "test"},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for mongodb without URI")
	}
}

func TestConfig_Validate_MissingJWTSecret(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		Storage: StorageConfig{Type: "memory"},
		JWT:     JWTConfig{Secret: ""},
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing JWT secret")
	}
}

func TestConfig_Validate_SQLiteStorage(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		Storage: StorageConfig{Type: "sqlite"},
		JWT:     JWTConfig{Secret: "test"},
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

func TestConfig_Validate_MongoDBStorageWithURI(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
		},
		Storage: StorageConfig{
			Type:    "mongodb",
			MongoDB: MongoDBConfig{URI: "mongodb://localhost:27017"},
		},
		JWT: JWTConfig{Secret: "test"},
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v", err)
	}
}

func TestServerConfig_Address(t *testing.T) {
	cfg := ServerConfig{Host: "localhost", Port: 8080}
	expected := "localhost:8080"

	if cfg.Address() != expected {
		t.Errorf("Address() = %q, want %q", cfg.Address(), expected)
	}
}

func TestServerConfig_Address_DifferentValues(t *testing.T) {
	tests := []struct {
		host     string
		port     int
		expected string
	}{
		{"0.0.0.0", 80, "0.0.0.0:80"},
		{"127.0.0.1", 3000, "127.0.0.1:3000"},
		{"example.com", 443, "example.com:443"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			cfg := ServerConfig{Host: tt.host, Port: tt.port}
			if cfg.Address() != tt.expected {
				t.Errorf("Address() = %q, want %q", cfg.Address(), tt.expected)
			}
		})
	}
}

func TestLoad_NonExistentFile(t *testing.T) {
	// Test loading with a non-existent file - should use defaults
	cfg, err := Load("nonexistent.yaml")
	// This will fail validation because defaults don't include JWT secret
	if err == nil {
		t.Error("Expected error for missing JWT secret")
	}
	// cfg should be nil when there's a validation error
	if cfg != nil && err != nil {
		t.Error("Expected nil config on error")
	}
}

func TestLoad_ValidYAMLFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	content := `
server:
  host: localhost
  port: 8080
  rp_id: localhost
  rp_origin: http://localhost:8080
storage:
  type: memory
jwt:
  secret: test-secret
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", cfg.Server.Port)
	}
	if cfg.JWT.Secret != "test-secret" {
		t.Errorf("Expected JWT secret 'test-secret', got %q", cfg.JWT.Secret)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	// Create a temporary config file with invalid YAML
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	content := `
server:
  port: "invalid"  # This will cause unmarshal to fail or use default
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// This should fail due to missing required fields (like jwt.secret)
	_, err := Load(configPath)
	if err == nil {
		t.Error("Expected error for invalid/incomplete configuration")
	}
}

func TestLoad_BaseURLGeneration(t *testing.T) {
	// The envconfig defaults override YAML values, so we use default host/port
	// Create a temporary config file without base_url
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	content := `
server:
  rp_id: myhost
  rp_origin: http://myhost:8080
storage:
  type: memory
jwt:
  secret: test-secret
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// BaseURL should be generated from default host/port (0.0.0.0:8080)
	expected := "http://0.0.0.0:8080"
	if cfg.Server.BaseURL != expected {
		t.Errorf("Expected BaseURL %q, got %q", expected, cfg.Server.BaseURL)
	}
}
