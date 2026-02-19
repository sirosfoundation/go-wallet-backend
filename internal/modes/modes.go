// Package modes provides the mode dispatcher for the hybrid binary.
// The wallet-backend binary can run in different modes:
// - all: runs all services (backend + registry) - default
// - backend: runs only the wallet backend API server
// - registry: runs only the VCTM registry server
// - engine: runs only the WebSocket engine (future)
package modes

import (
	"context"
	"fmt"
)

// Mode represents an operating mode for the hybrid binary
type Mode string

const (
	ModeAll      Mode = "all"
	ModeBackend  Mode = "backend"
	ModeRegistry Mode = "registry"
	ModeEngine   Mode = "engine"
)

// ValidModes lists all valid operating modes
var ValidModes = []Mode{ModeAll, ModeBackend, ModeRegistry, ModeEngine}

// IsValid checks if a mode string is valid
func (m Mode) IsValid() bool {
	for _, valid := range ValidModes {
		if m == valid {
			return true
		}
	}
	return false
}

// ParseMode parses a mode string into a Mode, returning an error if invalid
func ParseMode(s string) (Mode, error) {
	mode := Mode(s)
	if !mode.IsValid() {
		return "", fmt.Errorf("invalid mode %q, valid modes: %v", s, ValidModes)
	}
	return mode, nil
}

// Runner is the interface for mode-specific runners
type Runner interface {
	// Name returns the mode name
	Name() Mode

	// Run starts the mode's services and blocks until shutdown
	Run(ctx context.Context) error

	// Shutdown gracefully shuts down the mode's services
	Shutdown(ctx context.Context) error
}

// RunnerFactory creates a Runner for the given mode
type RunnerFactory func(cfg interface{}) (Runner, error)

// registry of runner factories
var runners = make(map[Mode]RunnerFactory)

// Register registers a runner factory for a mode
func Register(mode Mode, factory RunnerFactory) {
	runners[mode] = factory
}

// NewRunner creates a runner for the given mode
func NewRunner(mode Mode, cfg interface{}) (Runner, error) {
	factory, ok := runners[mode]
	if !ok {
		return nil, fmt.Errorf("no runner registered for mode %q", mode)
	}
	return factory(cfg)
}

// ListRegistered returns the list of registered modes
func ListRegistered() []Mode {
	var modes []Mode
	for m := range runners {
		modes = append(modes, m)
	}
	return modes
}
