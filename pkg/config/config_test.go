package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestTLSConfig_TLSMinVersion(t *testing.T) {
	tests := []struct {
		name       string
		minVersion string
		expected   uint16
	}{
		{"default empty returns TLS 1.2", "", 0x0303}, // tls.VersionTLS12
		{"tls12 returns TLS 1.2", "tls12", 0x0303},
		{"TLS12 uppercase returns TLS 1.2", "TLS12", 0x0303},
		{"1.2 returns TLS 1.2", "1.2", 0x0303},
		{"tls13 returns TLS 1.3", "tls13", 0x0304}, // tls.VersionTLS13
		{"TLS13 uppercase returns TLS 1.3", "TLS13", 0x0304},
		{"1.3 returns TLS 1.3", "1.3", 0x0304},
		{"unknown falls back to TLS 1.2", "invalid", 0x0303},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TLSConfig{MinVersion: tt.minVersion}
			if got := cfg.TLSMinVersion(); got != tt.expected {
				t.Errorf("TLSMinVersion() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_Validate_TLSEnabled_RequiresCertAndKey(t *testing.T) {
	tests := []struct {
		name      string
		certFile  string
		keyFile   string
		wantError bool
	}{
		{"valid TLS config", "/path/to/cert.pem", "/path/to/key.pem", false},
		{"missing cert_file", "", "/path/to/key.pem", true},
		{"missing key_file", "/path/to/cert.pem", "", true},
		{"missing both", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{
					Host:     "localhost",
					Port:     8080,
					RPID:     "localhost",
					RPOrigin: "http://localhost:8080",
					TLS: TLSConfig{
						Enabled:  true,
						CertFile: tt.certFile,
						KeyFile:  tt.keyFile,
					},
				},
				Storage: StorageConfig{Type: "memory"},
				JWT:     JWTConfig{Secret: "test"},
			}

			err := cfg.Validate()
			if tt.wantError && err == nil {
				t.Error("Expected validation error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

func TestConfig_Validate_TLSDisabled_NoRequirements(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Host:     "localhost",
			Port:     8080,
			RPID:     "localhost",
			RPOrigin: "http://localhost:8080",
			TLS: TLSConfig{
				Enabled:  false,
				CertFile: "", // empty is fine when disabled
				KeyFile:  "", // empty is fine when disabled
			},
		},
		Storage: StorageConfig{Type: "memory"},
		JWT:     JWTConfig{Secret: "test"},
	}

	err := cfg.Validate()
	if err != nil {
		t.Errorf("Validate() error = %v, expected nil when TLS disabled", err)
	}
}

func TestConfig_Validate_AdminTLS(t *testing.T) {
	base := func() *Config {
		return &Config{
			Server: ServerConfig{
				Host:     "localhost",
				Port:     8080,
				RPID:     "localhost",
				RPOrigin: "http://localhost:8080",
			},
			Storage: StorageConfig{Type: "memory"},
			JWT:     JWTConfig{Secret: "test"},
		}
	}

	t.Run("nil admin_tls is valid", func(t *testing.T) {
		cfg := base()
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("admin_tls disabled is valid without cert/key", func(t *testing.T) {
		cfg := base()
		cfg.Server.AdminTLS = &TLSConfig{Enabled: false}
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("admin_tls enabled requires cert_file", func(t *testing.T) {
		cfg := base()
		cfg.Server.AdminTLS = &TLSConfig{Enabled: true, KeyFile: "/key.pem"}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing cert_file")
		}
	})

	t.Run("admin_tls enabled requires key_file", func(t *testing.T) {
		cfg := base()
		cfg.Server.AdminTLS = &TLSConfig{Enabled: true, CertFile: "/cert.pem"}
		if err := cfg.Validate(); err == nil {
			t.Error("expected error for missing key_file")
		}
	})

	t.Run("admin_tls enabled with both files is valid", func(t *testing.T) {
		cfg := base()
		cfg.Server.AdminTLS = &TLSConfig{Enabled: true, CertFile: "/cert.pem", KeyFile: "/key.pem"}
		if err := cfg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestLoad_AdminTLS_FromYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	configYAML := []byte(`
server:
  host: localhost
  port: 8080
  rp_id: localhost
  rp_origin: http://localhost:8080
  admin_tls:
    enabled: true
    cert_file: /yaml/cert.pem
    key_file: /yaml/key.pem
storage:
  type: memory
jwt:
  secret: test
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.AdminTLS == nil {
		t.Fatal("Load() left Server.AdminTLS nil for YAML admin_tls configuration")
	}
	if !cfg.Server.AdminTLS.Enabled {
		t.Errorf("Server.AdminTLS.Enabled = %v, want true", cfg.Server.AdminTLS.Enabled)
	}
	if cfg.Server.AdminTLS.CertFile != "/yaml/cert.pem" {
		t.Errorf("Server.AdminTLS.CertFile = %q, want %q", cfg.Server.AdminTLS.CertFile, "/yaml/cert.pem")
	}
	if cfg.Server.AdminTLS.KeyFile != "/yaml/key.pem" {
		t.Errorf("Server.AdminTLS.KeyFile = %q, want %q", cfg.Server.AdminTLS.KeyFile, "/yaml/key.pem")
	}
}

func TestLoad_AdminTLS_FromEnv(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	configYAML := []byte(`
server:
  host: localhost
  port: 8080
  rp_id: localhost
  rp_origin: http://localhost:8080
storage:
  type: memory
jwt:
  secret: test
`)
	if err := os.WriteFile(configPath, configYAML, 0o600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	t.Setenv("WALLET_SERVER_ADMIN_TLS_ENABLED", "true")
	t.Setenv("WALLET_SERVER_ADMIN_TLS_CERT_FILE", "/env/cert.pem")
	t.Setenv("WALLET_SERVER_ADMIN_TLS_KEY_FILE", "/env/key.pem")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.AdminTLS == nil {
		t.Fatal("Load() left Server.AdminTLS nil when admin TLS env vars were set")
	}
	if !cfg.Server.AdminTLS.Enabled {
		t.Errorf("Server.AdminTLS.Enabled = %v, want true", cfg.Server.AdminTLS.Enabled)
	}
	if cfg.Server.AdminTLS.CertFile != "/env/cert.pem" {
		t.Errorf("Server.AdminTLS.CertFile = %q, want %q", cfg.Server.AdminTLS.CertFile, "/env/cert.pem")
	}
	if cfg.Server.AdminTLS.KeyFile != "/env/key.pem" {
		t.Errorf("Server.AdminTLS.KeyFile = %q, want %q", cfg.Server.AdminTLS.KeyFile, "/env/key.pem")
	}
}

// =============================================================================
// ExternalURLsConfig tests
// =============================================================================

func TestExternalURLsConfig_GetBackendURL(t *testing.T) {
	tests := []struct {
		name     string
		config   ExternalURLsConfig
		host     string
		port     int
		expected string
	}{
		{
			name:     "configured URL used",
			config:   ExternalURLsConfig{BackendURL: "https://api.example.com"},
			host:     "localhost",
			port:     8080,
			expected: "https://api.example.com",
		},
		{
			name:     "fallback to host:port",
			config:   ExternalURLsConfig{BackendURL: ""},
			host:     "localhost",
			port:     8080,
			expected: "http://localhost:8080",
		},
		{
			name:     "fallback with custom port",
			config:   ExternalURLsConfig{},
			host:     "0.0.0.0",
			port:     9000,
			expected: "http://0.0.0.0:9000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetBackendURL(tt.host, tt.port)
			if got != tt.expected {
				t.Errorf("GetBackendURL() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExternalURLsConfig_GetEngineURL(t *testing.T) {
	tests := []struct {
		name     string
		config   ExternalURLsConfig
		host     string
		port     int
		expected string
	}{
		{
			name:     "configured URL used",
			config:   ExternalURLsConfig{EngineURL: "wss://engine.example.com"},
			host:     "localhost",
			port:     8081,
			expected: "wss://engine.example.com",
		},
		{
			name:     "fallback to host:port",
			config:   ExternalURLsConfig{},
			host:     "localhost",
			port:     8081,
			expected: "http://localhost:8081",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetEngineURL(tt.host, tt.port)
			if got != tt.expected {
				t.Errorf("GetEngineURL() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExternalURLsConfig_GetRegistryURL(t *testing.T) {
	tests := []struct {
		name     string
		config   ExternalURLsConfig
		host     string
		port     int
		expected string
	}{
		{
			name:     "configured URL used",
			config:   ExternalURLsConfig{RegistryURL: "https://registry.example.com"},
			host:     "localhost",
			port:     8082,
			expected: "https://registry.example.com",
		},
		{
			name:     "fallback to host:port",
			config:   ExternalURLsConfig{},
			host:     "0.0.0.0",
			port:     8082,
			expected: "http://0.0.0.0:8082",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetRegistryURL(tt.host, tt.port)
			if got != tt.expected {
				t.Errorf("GetRegistryURL() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExternalURLsConfig_GetAdminURL(t *testing.T) {
	tests := []struct {
		name     string
		config   ExternalURLsConfig
		host     string
		port     int
		expected string
	}{
		{
			name:     "configured URL used",
			config:   ExternalURLsConfig{AdminURL: "https://admin.example.com"},
			host:     "localhost",
			port:     9090,
			expected: "https://admin.example.com",
		},
		{
			name:     "fallback to host:port",
			config:   ExternalURLsConfig{},
			host:     "localhost",
			port:     9090,
			expected: "http://localhost:9090",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetAdminURL(tt.host, tt.port)
			if got != tt.expected {
				t.Errorf("GetAdminURL() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// ServerConfig address tests
// =============================================================================

func TestServerConfig_AdminAddress(t *testing.T) {
	tests := []struct {
		name     string
		config   ServerConfig
		expected string
	}{
		{
			name: "default port",
			config: ServerConfig{
				Host:      "localhost",
				AdminPort: 9090,
			},
			expected: "localhost:9090",
		},
		{
			name: "all interfaces",
			config: ServerConfig{
				Host:      "0.0.0.0",
				AdminPort: 8090,
			},
			expected: "0.0.0.0:8090",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.AdminAddress()
			if got != tt.expected {
				t.Errorf("AdminAddress() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestServerConfig_EngineAddress(t *testing.T) {
	tests := []struct {
		name     string
		config   ServerConfig
		expected string
	}{
		{
			name: "separate engine port",
			config: ServerConfig{
				Host:       "localhost",
				Port:       8080,
				EnginePort: 8081,
			},
			expected: "localhost:8081",
		},
		{
			name: "fallback to main port",
			config: ServerConfig{
				Host:       "localhost",
				Port:       8080,
				EnginePort: 0, // Not set
			},
			expected: "localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.EngineAddress()
			if got != tt.expected {
				t.Errorf("EngineAddress() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestServerConfig_RegistryAddress(t *testing.T) {
	tests := []struct {
		name     string
		config   ServerConfig
		expected string
	}{
		{
			name: "separate registry port",
			config: ServerConfig{
				Host:         "localhost",
				Port:         8080,
				RegistryPort: 8082,
			},
			expected: "localhost:8082",
		},
		{
			name: "default port when not set",
			config: ServerConfig{
				Host:         "0.0.0.0",
				Port:         8080,
				RegistryPort: 0,
			},
			expected: "0.0.0.0:8097", // default registry port
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.RegistryAddress()
			if got != tt.expected {
				t.Errorf("RegistryAddress() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// HTTPClientConfig tests
// =============================================================================

func TestHTTPClientConfig_NewHTTPClient_NoProxy(t *testing.T) {
	cfg := HTTPClientConfig{
		ProxyURL: "",
		Timeout:  10,
	}

	client := cfg.NewHTTPClient(0)
	if client == nil {
		t.Fatal("NewHTTPClient() returned nil")
	}
}

func TestHTTPClientConfig_NewHTTPClient_WithProxy(t *testing.T) {
	cfg := HTTPClientConfig{
		ProxyURL: "http://proxy.example.com:8080",
		Timeout:  30,
	}

	client := cfg.NewHTTPClient(0)
	if client == nil {
		t.Fatal("NewHTTPClient() returned nil")
	}
}

func TestHTTPClientConfig_NewHTTPClient_TimeoutOverride(t *testing.T) {
	cfg := HTTPClientConfig{
		ProxyURL: "",
		Timeout:  10,
	}

	client := cfg.NewHTTPClient(60 * time.Second)
	if client == nil {
		t.Fatal("NewHTTPClient() returned nil")
	}
	// Can't easily check internal timeout, but validates it doesn't panic
}

// =============================================================================
// SetDefaults tests
// =============================================================================

func TestCORSConfig_SetDefaults(t *testing.T) {
	cfg := CORSConfig{}
	cfg.SetDefaults()

	if len(cfg.AllowedOrigins) == 0 {
		t.Error("AllowedOrigins should have default value")
	}
	if cfg.AllowedOrigins[0] != "*" {
		t.Errorf("AllowedOrigins[0] = %q, want '*'", cfg.AllowedOrigins[0])
	}
	if len(cfg.AllowedMethods) == 0 {
		t.Error("AllowedMethods should have default value")
	}
	if len(cfg.AllowedHeaders) == 0 {
		t.Error("AllowedHeaders should have default value")
	}
}
