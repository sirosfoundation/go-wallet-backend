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
	modeall "github.com/sirosfoundation/go-wallet-backend/internal/modes/all"
	modebackend "github.com/sirosfoundation/go-wallet-backend/internal/modes/backend"
	modeengine "github.com/sirosfoundation/go-wallet-backend/internal/modes/engine"
	moderegistry "github.com/sirosfoundation/go-wallet-backend/internal/modes/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Ensure mode packages are registered
var (
	_ = modeall.Config{}
	_ = modebackend.Config{}
	_ = modeengine.Config{}
	_ = moderegistry.Config{}
)

var (
	configFile         = flag.String("config", "configs/config.yaml", "Path to backend configuration file")
	registryConfigFile = flag.String("registry-config", "configs/registry.yaml", "Path to registry configuration file")
	modeFlag           = flag.String("mode", "backend", "Operating mode: all, backend, registry, engine")
	version            = "dev"
	buildTime          = "unknown"
)

func main() {
	flag.Parse()

	// Parse mode
	mode, err := modes.ParseMode(*modeFlag)
	if err != nil {
		log.Fatalf("Invalid mode: %v", err)
	}

	// Load backend configuration (needed for most modes)
	var backendCfg *config.Config
	if mode == modes.ModeBackend || mode == modes.ModeAll || mode == modes.ModeEngine {
		backendCfg, err = config.Load(*configFile)
		if err != nil {
			log.Fatalf("Failed to load backend configuration: %v", err)
		}
	}

	// Load registry configuration (needed for registry or all modes)
	var registryCfg *registry.Config
	if mode == modes.ModeRegistry || mode == modes.ModeAll {
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
		logger, err = initLogger(backendCfg.Logging)
	} else if registryCfg != nil {
		logger, err = initLoggerFromRegistry(registryCfg.Logging)
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
		zap.String("mode", string(mode)),
	)

	// Create mode-specific runner configuration
	var runnerCfg interface{}
	switch mode {
	case modes.ModeBackend:
		runnerCfg = &modebackend.Config{
			Config: backendCfg,
			Logger: logger,
		}
	case modes.ModeRegistry:
		runnerCfg = &moderegistry.Config{
			Config: registryCfg,
			Logger: logger,
		}
	case modes.ModeEngine:
		runnerCfg = &modeengine.Config{
			Config: backendCfg,
			Logger: logger,
		}
	case modes.ModeAll:
		runnerCfg = &modeall.Config{
			BackendConfig:  backendCfg,
			RegistryConfig: registryCfg,
			Logger:         logger,
		}
	}

	// Create runner for the mode
	runner, err := modes.NewRunner(mode, runnerCfg)
	if err != nil {
		logger.Fatal("Failed to create runner", zap.Error(err))
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start runner in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- runner.Run(ctx)
	}()

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
	logger.Info("Shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := runner.Shutdown(shutdownCtx); err != nil {
		logger.Error("Shutdown error", zap.Error(err))
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

func initLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	var zapCfg zap.Config

	if cfg.Format == "json" {
		zapCfg = zap.NewProductionConfig()
	} else {
		zapCfg = zap.NewDevelopmentConfig()
	}

	switch cfg.Level {
	case "debug":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	return zapCfg.Build()
}

func initLoggerFromRegistry(cfg registry.LoggingConfig) (*zap.Logger, error) {
	var zapCfg zap.Config

	if cfg.Format == "json" {
		zapCfg = zap.NewProductionConfig()
	} else {
		zapCfg = zap.NewDevelopmentConfig()
	}

	switch cfg.Level {
	case "debug":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapCfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		zapCfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	return zapCfg.Build()
}
