// Package engine provides the WebSocket engine mode runner.
// The engine handles stateless WebSocket coordination for OID4VP flows.
package engine

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func init() {
	modes.Register(modes.ModeEngine, func(cfg interface{}) (modes.Runner, error) {
		c, ok := cfg.(*Config)
		if !ok {
			return nil, fmt.Errorf("invalid config type for engine mode")
		}
		return New(c)
	})
}

// Config holds configuration for the engine mode
type Config struct {
	Config *config.Config
	Logger *zap.Logger
}

// Runner implements the engine mode
type Runner struct {
	cfg *Config
}

// New creates a new engine runner
func New(cfg *Config) (*Runner, error) {
	return &Runner{cfg: cfg}, nil
}

// Name returns the mode name
func (r *Runner) Name() modes.Mode {
	return modes.ModeEngine
}

// Run starts the engine services
func (r *Runner) Run(ctx context.Context) error {
	logger := r.cfg.Logger
	logger.Info("Engine mode not yet implemented")
	
	// TODO: Implement WebSocket engine
	// See docs/websocket-protocol-spec.md for protocol details
	// Key features:
	// - Stateless WebSocket coordination for OID4VP
	// - Client-side credential matching
	// - Ephemeral encryption for presentation payloads
	
	// Block until context is cancelled
	<-ctx.Done()
	return nil
}

// Shutdown gracefully shuts down the engine services
func (r *Runner) Shutdown(ctx context.Context) error {
	// Nothing to shutdown yet
	return nil
}
