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
	modebackend "github.com/sirosfoundation/go-wallet-backend/internal/modes/backend"
	modeengine "github.com/sirosfoundation/go-wallet-backend/internal/modes/engine"
	moderegistry "github.com/sirosfoundation/go-wallet-backend/internal/modes/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/logging"
)

// Ensure mode packages are registered
var (
	_ = modebackend.Config{}
	_ = modeengine.Config{}
	_ = moderegistry.Config{}
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

	// Load backend configuration (needed for backend and engine roles)
	var backendCfg *config.Config
	if roles.Has(modes.RoleBackend) || roles.Has(modes.RoleEngine) {
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

	// Create runners for each active role
	var runners []modes.Runner

	if roles.Has(modes.RoleBackend) {
		runner, err := modebackend.New(&modebackend.Config{
			Config: backendCfg,
			Logger: logger.Named("backend"),
			Roles:  roleStrings,
		})
		if err != nil {
			logger.Fatal("Failed to create backend runner", zap.Error(err))
		}
		runners = append(runners, runner)
	}

	if roles.Has(modes.RoleRegistry) {
		runner, err := moderegistry.New(&moderegistry.Config{
			Config: registryCfg,
			Logger: logger.Named("registry"),
		})
		if err != nil {
			logger.Fatal("Failed to create registry runner", zap.Error(err))
		}
		runners = append(runners, runner)
	}

	if roles.Has(modes.RoleEngine) {
		runner, err := modeengine.New(&modeengine.Config{
			Config: backendCfg,
			Logger: logger.Named("engine"),
			Roles:  roleStrings,
		})
		if err != nil {
			logger.Fatal("Failed to create engine runner", zap.Error(err))
		}
		runners = append(runners, runner)
	}

	if len(runners) == 0 {
		logger.Fatal("No runners configured")
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start all runners in goroutines
	errCh := make(chan error, len(runners))
	for _, runner := range runners {
		r := runner // capture for goroutine
		go func() {
			logger.Info("Starting role", zap.String("role", string(r.Role())))
			if err := r.Run(ctx); err != nil {
				errCh <- fmt.Errorf("%s error: %w", r.Role(), err)
			}
		}()
	}

	// Wait for signal or error
	select {
	case <-quit:
		logger.Info("Received shutdown signal")
	case err := <-errCh:
		if err != nil {
			logger.Error("Runner error", zap.Error(err))
		}
	}

	// Graceful shutdown
	cancel()
	logger.Info("Shutting down...", zap.Strings("roles", roleStrings))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Shutdown all runners
	for _, runner := range runners {
		if err := runner.Shutdown(shutdownCtx); err != nil {
			logger.Error("Shutdown error",
				zap.String("role", string(runner.Role())),
				zap.Error(err))
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
