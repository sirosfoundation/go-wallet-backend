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
	if err == nil {
		t.Error("Validate() expected error for deprecated sqlite storage, got nil")
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

func TestLoad_YAMLValuesNotOverwrittenByDefaults(t *testing.T) {
	// This test ensures that YAML values are preserved and not overwritten
	// by default values. This was a bug where envconfig's `default:` tags
	// would overwrite values that were already set from YAML.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Use non-default port 8081 to verify it's preserved
	content := `
server:
  host: 127.0.0.1
  port: 8081
  rp_id: example.com
  rp_origin: http://example.com:8081
storage:
  type: memory
jwt:
  secret: test-secret
  expiry_hours: 48
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify YAML values are preserved, not overwritten by defaults
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1', got %q", cfg.Server.Host)
	}
	if cfg.Server.Port != 8081 {
		t.Errorf("Expected port 8081, got %d (default 8080 was applied)", cfg.Server.Port)
	}
	if cfg.Storage.Type != "memory" {
		t.Errorf("Expected storage type 'memory', got %q", cfg.Storage.Type)
	}
	if cfg.JWT.ExpiryHours != 48 {
		t.Errorf("Expected JWT expiry hours 48, got %d", cfg.JWT.ExpiryHours)
	}
}
func TestTrustConfig_GetPDPURL(t *testing.T) {
	tests := []struct {
		name     string
		cfg      TrustConfig
		expected string
	}{
		{
			name:     "PDPURL takes precedence",
			cfg:      TrustConfig{PDPURL: "https://new.example.com", DefaultEndpoint: "https://old.example.com"},
			expected: "https://new.example.com",
		},
		{
			name:     "fallback to DefaultEndpoint for backward compatibility",
			cfg:      TrustConfig{DefaultEndpoint: "https://old.example.com"},
			expected: "https://old.example.com",
		},
		{
			name:     "empty when both empty (allow all mode)",
			cfg:      TrustConfig{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.GetPDPURL()
			if got != tt.expected {
				t.Errorf("GetPDPURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestFlowTrustConfig_IsExplicitlyDisabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      FlowTrustConfig
		expected bool
	}{
		{"empty means not disabled", FlowTrustConfig{}, false},
		{"url means not disabled", FlowTrustConfig{PDPURL: "https://pdp.example.com"}, false},
		{"none means disabled", FlowTrustConfig{PDPURL: "none"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsExplicitlyDisabled(); got != tt.expected {
				t.Errorf("IsExplicitlyDisabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTrustConfig_GetIssuerPDPURL(t *testing.T) {
	tests := []struct {
		name     string
		cfg      TrustConfig
		expected string
	}{
		{
			name:     "issuer explicitly disabled returns empty",
			cfg:      TrustConfig{PDPURL: "https://global.example.com", Issuer: FlowTrustConfig{PDPURL: "none"}},
			expected: "",
		},
		{
			name:     "issuer flow-specific URL takes precedence",
			cfg:      TrustConfig{PDPURL: "https://global.example.com", Issuer: FlowTrustConfig{PDPURL: "https://issuer.example.com"}},
			expected: "https://issuer.example.com",
		},
		{
			name:     "falls back to global PDPURL",
			cfg:      TrustConfig{PDPURL: "https://global.example.com"},
			expected: "https://global.example.com",
		},
		{
			name:     "falls back to deprecated DefaultEndpoint",
			cfg:      TrustConfig{DefaultEndpoint: "https://old.example.com"},
			expected: "https://old.example.com",
		},
		{
			name:     "empty when nothing configured",
			cfg:      TrustConfig{},
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetIssuerPDPURL(); got != tt.expected {
				t.Errorf("GetIssuerPDPURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTrustConfig_GetVerifierPDPURL(t *testing.T) {
	tests := []struct {
		name     string
		cfg      TrustConfig
		expected string
	}{
		{
			name:     "verifier explicitly disabled returns empty",
			cfg:      TrustConfig{PDPURL: "https://global.example.com", Verifier: FlowTrustConfig{PDPURL: "none"}},
			expected: "",
		},
		{
			name:     "verifier flow-specific URL takes precedence",
			cfg:      TrustConfig{PDPURL: "https://global.example.com", Verifier: FlowTrustConfig{PDPURL: "https://verifier.example.com"}},
			expected: "https://verifier.example.com",
		},
		{
			name:     "falls back to global PDPURL",
			cfg:      TrustConfig{PDPURL: "https://global.example.com"},
			expected: "https://global.example.com",
		},
		{
			name:     "empty when nothing configured",
			cfg:      TrustConfig{},
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetVerifierPDPURL(); got != tt.expected {
				t.Errorf("GetVerifierPDPURL() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTrustConfig_IsIssuerTrustEnabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      TrustConfig
		expected bool
	}{
		{"enabled via global PDPURL", TrustConfig{PDPURL: "https://pdp.example.com"}, true},
		{"enabled via issuer flow URL", TrustConfig{Issuer: FlowTrustConfig{PDPURL: "https://issuer-pdp.example.com"}}, true},
		{"disabled when nothing configured", TrustConfig{}, false},
		{"disabled via explicit none", TrustConfig{PDPURL: "https://global.example.com", Issuer: FlowTrustConfig{PDPURL: "none"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsIssuerTrustEnabled(); got != tt.expected {
				t.Errorf("IsIssuerTrustEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTrustConfig_IsVerifierTrustEnabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      TrustConfig
		expected bool
	}{
		{"enabled via global PDPURL", TrustConfig{PDPURL: "https://pdp.example.com"}, true},
		{"enabled via verifier flow URL", TrustConfig{Verifier: FlowTrustConfig{PDPURL: "https://verifier-pdp.example.com"}}, true},
		{"disabled when nothing configured", TrustConfig{}, false},
		{"disabled via explicit none", TrustConfig{PDPURL: "https://global.example.com", Verifier: FlowTrustConfig{PDPURL: "none"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsVerifierTrustEnabled(); got != tt.expected {
				t.Errorf("IsVerifierTrustEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTrustConfig_IndependentFlowConfig(t *testing.T) {
	// Issuer uses a specific PDP, verifier trust is disabled
	cfg := TrustConfig{
		PDPURL:   "https://global.example.com",
		Issuer:   FlowTrustConfig{PDPURL: "https://issuer-pdp.example.com"},
		Verifier: FlowTrustConfig{PDPURL: "none"},
	}

	if !cfg.IsIssuerTrustEnabled() {
		t.Error("Expected issuer trust to be enabled")
	}
	if cfg.IsVerifierTrustEnabled() {
		t.Error("Expected verifier trust to be disabled")
	}
	if got := cfg.GetIssuerPDPURL(); got != "https://issuer-pdp.example.com" {
		t.Errorf("GetIssuerPDPURL() = %v, want https://issuer-pdp.example.com", got)
	}
	if got := cfg.GetVerifierPDPURL(); got != "" {
		t.Errorf("GetVerifierPDPURL() = %v, want empty", got)
	}
}

func TestServerConfig_ResolvedServedBy(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	t.Run("nil defaults to hostname", func(t *testing.T) {
		cfg := ServerConfig{ServedByHeader: nil}
		got := cfg.ResolvedServedBy()
		// Should return something non-empty (hostname or "unknown")
		if got == "" {
			t.Error("ResolvedServedBy() should return hostname when nil, got empty")
		}
	})

	t.Run("custom value", func(t *testing.T) {
		cfg := ServerConfig{ServedByHeader: strPtr("custom-node")}
		if got := cfg.ResolvedServedBy(); got != "custom-node" {
			t.Errorf("ResolvedServedBy() = %q, want %q", got, "custom-node")
		}
	})

	t.Run("empty string disables header", func(t *testing.T) {
		cfg := ServerConfig{ServedByHeader: strPtr("")}
		if got := cfg.ResolvedServedBy(); got != "" {
			t.Errorf("ResolvedServedBy() = %q, want %q", got, "")
		}
	})
}