package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/server"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/logging"
)

var (
	configFile         = flag.String("config", "configs/config.yaml", "Path to backend configuration file")
	registryConfigFile = flag.String("registry-config", "configs/registry.yaml", "Path to registry configuration file")
	modeFlag           = flag.String("mode", "backend", "Operating roles: backend, registry, engine (comma-separated or 'all')")
	version            = "dev"
	buildTime          = "unknown"
)

func main() {
	flag.Parse()

	// Parse roles (supports comma-separated list or "all")
	roles, err := modes.ParseRoles(*modeFlag)
	if err != nil {
		log.Fatalf("Invalid mode: %v", err)
	}
	roleStrings := roles.Strings()

	// Load backend configuration (needed for backend, engine, and admin roles)
	var backendCfg *config.Config
	if roles.Has(modes.RoleBackend) || roles.Has(modes.RoleEngine) || roles.Has(modes.RoleAdmin) {
		backendCfg, err = config.Load(*configFile)
		if err != nil {
			log.Fatalf("Failed to load backend configuration: %v", err)
		}
	}

	// Load registry configuration (needed for registry role)
	var registryCfg *registry.Config
	if roles.Has(modes.RoleRegistry) {
		registryCfg, err = loadRegistryConfig(*registryConfigFile)
		if err != nil {
			log.Fatalf("Failed to load registry configuration: %v", err)
		}
		if err := registryCfg.Validate(); err != nil {
			log.Fatalf("Invalid registry configuration: %v", err)
		}
	}

	// Initialize logger (use backend config if available, otherwise registry)
	var logger *zap.Logger
	if backendCfg != nil {
		logger, err = logging.NewLogger(logging.Config{
			Level:  backendCfg.Logging.Level,
			Format: backendCfg.Logging.Format,
		})
	} else if registryCfg != nil {
		logger, err = logging.NewLogger(logging.Config{
			Level:  registryCfg.Logging.Level,
			Format: registryCfg.Logging.Format,
		})
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("Starting Wallet Backend",
		zap.String("version", version),
		zap.String("build_time", buildTime),
		zap.Strings("roles", roleStrings),
	)

	// Security configuration validation for production environments
	// Checks for potentially dangerous configurations and logs warnings
	isProduction := os.Getenv("ENVIRONMENT") == "production" ||
		os.Getenv("GO_ENV") == "production" ||
		os.Getenv("APP_ENV") == "production"

	if backendCfg != nil {
		// Issue #70: Warn when trust evaluation is disabled (allows any issuer/verifier)
		// Cache the results to avoid repeated calls
		issuerEnabled := backendCfg.Trust.IsIssuerTrustEnabled()
		verifierEnabled := backendCfg.Trust.IsVerifierTrustEnabled()

		if !issuerEnabled || !verifierEnabled {
			// Use Error level in production to ensure visibility in alerting pipelines
			level := zap.WarnLevel
			if isProduction {
				level = zap.ErrorLevel
			}

			if !issuerEnabled && !verifierEnabled {
				logger.Log(level, "Trust evaluation is disabled - all issuers and verifiers will be accepted without verification",
					zap.Bool("issuer_trust_enabled", false),
					zap.Bool("verifier_trust_enabled", false),
					zap.Bool("production", isProduction))
			} else if !issuerEnabled {
				logger.Log(level, "Issuer trust evaluation is disabled - all issuers will be accepted without verification",
					zap.Bool("issuer_trust_enabled", false),
					zap.Bool("production", isProduction))
			} else {
				logger.Log(level, "Verifier trust evaluation is disabled - all verifiers will be accepted without verification",
					zap.Bool("verifier_trust_enabled", false),
					zap.Bool("production", isProduction))
			}
		}

		// Issue #71: Warn when CORS allows wildcard origin
		for _, origin := range backendCfg.Server.CORS.AllowedOrigins {
			if origin == "*" {
				level := zap.WarnLevel
				if isProduction {
					level = zap.ErrorLevel
				}
				logger.Log(level, "CORS wildcard (*) configured - this allows any origin to make requests",
					zap.Strings("allowed_origins", backendCfg.Server.CORS.AllowedOrigins),
					zap.Bool("allow_credentials", backendCfg.Server.CORS.AllowCredentials),
					zap.Strings("allowed_headers", backendCfg.Server.CORS.AllowedHeaders),
					zap.Strings("allowed_methods", backendCfg.Server.CORS.AllowedMethods),
					zap.Bool("production", isProduction))
				break
			}
		}
	}

	// Build server configuration
	serverCfg := server.DefaultServerConfig()
	serverCfg.Roles = roleStrings

	if backendCfg != nil {
		serverCfg.HTTPAddress = backendCfg.Server.Host
		serverCfg.HTTPPort = backendCfg.Server.Port
		serverCfg.WSAddress = backendCfg.Server.Host
		serverCfg.WSPort = backendCfg.Server.EnginePort
		serverCfg.AdminPort = backendCfg.Server.AdminPort
		serverCfg.AdminToken = backendCfg.Server.AdminToken
		serverCfg.CORS = backendCfg.Server.CORS
		serverCfg.LoggingLevel = backendCfg.Logging.Level
		serverCfg.TLS = backendCfg.Server.TLS
		serverCfg.AdminTLS = backendCfg.Server.AdminTLS
	} else if registryCfg != nil {
		// Registry-only mode - use registry server config
		serverCfg.HTTPAddress = registryCfg.Server.Host
		serverCfg.HTTPPort = registryCfg.Server.Port
		serverCfg.LoggingLevel = registryCfg.Logging.Level
	}

	serverCfg.IsProduction = isProduction

	// Create unified server manager
	mgr := server.NewManager(serverCfg, logger)

	// Track closeable resources
	type closeable interface{ Close() error }
	var resources []closeable

	// Add providers based on roles
	var backendProvider *server.BackendProvider
	if roles.Has(modes.RoleBackend) {
		var err error
		backendProvider, err = server.NewBackendProvider(backendCfg, logger, roleStrings)
		if err != nil {
			logger.Fatal("Failed to create backend provider", zap.Error(err))
		}
		mgr.AddProvider(backendProvider)
		resources = append(resources, backendProvider)
	}

	if roles.Has(modes.RoleRegistry) {
		provider, err := server.NewRegistryProvider(registryCfg, logger)
		if err != nil {
			logger.Fatal("Failed to create registry provider", zap.Error(err))
		}
		mgr.AddProvider(provider)
		resources = append(resources, provider)
	}

	if roles.Has(modes.RoleEngine) {
		// Wire verifier store from backend if available (for trust caching)
		var verifierStore storage.VerifierStore
		if backendProvider != nil {
			verifierStore = backendProvider.Store().Verifiers()
		}
		provider, err := server.NewEngineProvider(backendCfg, logger, verifierStore)
		if err != nil {
			logger.Fatal("Failed to create engine provider", zap.Error(err))
		}
		mgr.AddProvider(provider)
	}

	// Admin-only mode: standalone admin API without backend auth/storage routes.
	// Skipped when RoleBackend is active, since BackendProvider already registers admin routes.
	if roles.Has(modes.RoleAdmin) && !roles.Has(modes.RoleBackend) {
		provider, err := server.NewAdminProvider(backendCfg, logger)
		if err != nil {
			logger.Fatal("Failed to create admin provider", zap.Error(err))
		}
		mgr.AddProvider(provider)
		resources = append(resources, provider)
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start all servers
	if err := mgr.Start(ctx); err != nil {
		logger.Fatal("Failed to start servers", zap.Error(err))
	}

	// Wait for shutdown signal
	<-quit
	logger.Info("Received shutdown signal")
	cancel()

	// Graceful shutdown
	logger.Info("Shutting down...", zap.Strings("roles", roleStrings))
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := mgr.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}

	// Cleanup resources
	for _, r := range resources {
		if err := r.Close(); err != nil {
			logger.Error("Resource cleanup error", zap.Error(err))
		}
	}

	logger.Info("Server exited")
}

// loadRegistryConfig loads registry configuration from file and environment
func loadRegistryConfig(path string) (*registry.Config, error) {
	cfg := registry.DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read registry config file: %w", err)
	}
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse registry config file: %w", err)
		}
	}

	if err := envconfig.Process("REGISTRY", cfg); err != nil {
		return nil, fmt.Errorf("failed to process registry environment variables: %w", err)
	}

	return cfg, nil
}
