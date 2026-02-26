// Package logging provides a unified logging configuration and initialization
// for all modes of the wallet-backend application.
package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config contains logging configuration.
// This is designed to be embedded or reused across different config structures.
type Config struct {
	// Level is the minimum log level: debug, info, warn, error
	Level string `yaml:"level" envconfig:"LEVEL"`
	// Format is the output format: json or text
	Format string `yaml:"format" envconfig:"FORMAT"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Level:  "info",
		Format: "json",
	}
}

// NewLogger creates a new zap logger based on the configuration
func NewLogger(cfg Config) (*zap.Logger, error) {
	var zapCfg zap.Config

	if cfg.Format == "json" {
		zapCfg = zap.NewProductionConfig()
	} else {
		zapCfg = zap.NewDevelopmentConfig()
	}

	// Set log level
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

// ParseLevel converts a string level to zapcore.Level
func ParseLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zap.DebugLevel
	case "info":
		return zap.InfoLevel
	case "warn":
		return zap.WarnLevel
	case "error":
		return zap.ErrorLevel
	default:
		return zap.InfoLevel
	}
}

// LevelString converts a zapcore.Level to its string representation
func LevelString(level zapcore.Level) string {
	switch level {
	case zap.DebugLevel:
		return "debug"
	case zap.InfoLevel:
		return "info"
	case zap.WarnLevel:
		return "warn"
	case zap.ErrorLevel:
		return "error"
	default:
		return "info"
	}
}
