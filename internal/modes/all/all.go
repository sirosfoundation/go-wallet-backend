// Package all provides the all mode runner that runs all services.
package all

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	modebackend "github.com/sirosfoundation/go-wallet-backend/internal/modes/backend"
	moderegistry "github.com/sirosfoundation/go-wallet-backend/internal/modes/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func init() {
	modes.Register(modes.ModeAll, func(cfg interface{}) (modes.Runner, error) {
		c, ok := cfg.(*Config)
		if !ok {
			return nil, fmt.Errorf("invalid config type for all mode")
		}
		return New(c)
	})
}

// Config holds configuration for the all mode
type Config struct {
	BackendConfig  *config.Config
	RegistryConfig *registry.Config
	Logger         *zap.Logger
}

// Runner implements the all mode (runs all services)
type Runner struct {
	cfg             *Config
	backendRunner   *modebackend.Runner
	registryRunner  *moderegistry.Runner
}

// New creates a new all-mode runner
func New(cfg *Config) (*Runner, error) {
	// Create backend runner
	backendRunner, err := modebackend.New(&modebackend.Config{
		Config: cfg.BackendConfig,
		Logger: cfg.Logger.Named("backend"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create backend runner: %w", err)
	}

	// Create registry runner (if config provided)
	var registryRunner *moderegistry.Runner
	if cfg.RegistryConfig != nil {
		rr, err := moderegistry.New(&moderegistry.Config{
			Config: cfg.RegistryConfig,
			Logger: cfg.Logger.Named("registry"),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create registry runner: %w", err)
		}
		registryRunner = rr
	}

	return &Runner{
		cfg:            cfg,
		backendRunner:  backendRunner,
		registryRunner: registryRunner,
	}, nil
}

// Name returns the mode name
func (r *Runner) Name() modes.Mode {
	return modes.ModeAll
}

// Run starts all services
func (r *Runner) Run(ctx context.Context) error {
	logger := r.cfg.Logger

	errCh := make(chan error, 2)

	// Start backend
	go func() {
		logger.Info("Starting backend service")
		if err := r.backendRunner.Run(ctx); err != nil {
			errCh <- fmt.Errorf("backend error: %w", err)
		}
	}()

	// Start registry if configured
	if r.registryRunner != nil {
		go func() {
			logger.Info("Starting registry service")
			if err := r.registryRunner.Run(ctx); err != nil {
				errCh <- fmt.Errorf("registry error: %w", err)
			}
		}()
	}

	// Wait for context cancellation or error
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

// Shutdown gracefully shuts down all services
func (r *Runner) Shutdown(ctx context.Context) error {
	logger := r.cfg.Logger
	var lastErr error

	// Shutdown backend
	if r.backendRunner != nil {
		logger.Info("Shutting down backend service")
		if err := r.backendRunner.Shutdown(ctx); err != nil {
			logger.Error("Backend shutdown error", zap.Error(err))
			lastErr = err
		}
	}

	// Shutdown registry
	if r.registryRunner != nil {
		logger.Info("Shutting down registry service")
		if err := r.registryRunner.Shutdown(ctx); err != nil {
			logger.Error("Registry shutdown error", zap.Error(err))
			lastErr = err
		}
	}

	return lastErr
}
