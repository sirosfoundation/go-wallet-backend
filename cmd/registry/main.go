package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
)

func main() {
	// Parse command line flags
	configFile := flag.String("config", "configs/registry.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger, err := initLogger(config.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("starting registry server",
		zap.String("address", config.Server.Address()),
		zap.String("source_url", config.Source.URL))

	// Create store and load cache
	store := registry.NewStore(config.Cache.Path)
	if err := store.Load(); err != nil {
		logger.Warn("failed to load cache, starting fresh", zap.Error(err))
	} else {
		logger.Info("loaded cache",
			zap.Int("entries", store.Count()),
			zap.Time("last_updated", store.LastUpdated()))
	}

	// Create fetcher and start polling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fetcher := registry.NewFetcher(config, store, logger)
	if err := fetcher.Start(ctx); err != nil {
		logger.Error("failed to start fetcher", zap.Error(err))
	}

	// Set up Gin
	if config.Logging.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Add recovery middleware
	router.Use(gin.Recovery())

	// Add request logging middleware
	router.Use(requestLogger(logger))

	// Add JWT middleware (sets authenticated flag)
	router.Use(registry.OptionalJWTMiddleware(config.JWT, logger))

	// Add rate limiting middleware (uses authenticated flag)
	rateLimiter := registry.NewRateLimiter(config.RateLimit)
	router.Use(registry.RateLimitMiddleware(rateLimiter))

	// Register handlers
	handler := registry.NewHandler(store, &config.DynamicCache, logger)
	handler.RegisterRoutes(router)

	// Create HTTP server
	srv := &http.Server{
		Addr:         config.Server.Address(),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("server listening", zap.String("address", config.Server.Address()))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	// Stop fetcher
	fetcher.Stop()

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server forced to shutdown", zap.Error(err))
	}

	// Save cache
	if err := store.Save(); err != nil {
		logger.Error("failed to save cache on shutdown", zap.Error(err))
	}

	logger.Info("server stopped")
}

// loadConfig loads configuration from file and environment variables
func loadConfig(path string) (*registry.Config, error) {
	// Start with defaults
	config := registry.DefaultConfig()

	// Try to load from file
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	if err == nil {
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Override with environment variables
	if err := envconfig.Process("REGISTRY", config); err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}

	return config, nil
}

// initLogger initializes the zap logger
func initLogger(config registry.LoggingConfig) (*zap.Logger, error) {
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(config.Level)); err != nil {
		level = zapcore.InfoLevel
	}

	var zapConfig zap.Config
	if config.Format == "json" {
		zapConfig = zap.NewProductionConfig()
	} else {
		zapConfig = zap.NewDevelopmentConfig()
	}
	zapConfig.Level = zap.NewAtomicLevelAt(level)

	return zapConfig.Build()
}

// requestLogger returns a Gin middleware for logging requests
func requestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		logger.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.Int("status", status),
			zap.Duration("latency", latency),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}
