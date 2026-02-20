// Package registry provides the registry mode runner.
package registry

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
)

func init() {
	modes.Register(modes.ModeRegistry, func(cfg interface{}) (modes.Runner, error) {
		c, ok := cfg.(*Config)
		if !ok {
			return nil, fmt.Errorf("invalid config type for registry mode")
		}
		return New(c)
	})
}

// Config holds configuration for the registry mode
type Config struct {
	Config *registry.Config
	Logger *zap.Logger
}

// Runner implements the registry mode
type Runner struct {
	cfg     *Config
	store   *registry.Store
	fetcher *registry.Fetcher
	srv     *http.Server
	cancel  context.CancelFunc
}

// New creates a new registry runner
func New(cfg *Config) (*Runner, error) {
	return &Runner{cfg: cfg}, nil
}

// Role returns the role this runner implements
func (r *Runner) Role() modes.Role {
	return modes.RoleRegistry
}

// Name returns the mode name (deprecated, use Role())
func (r *Runner) Name() modes.Mode {
	return modes.ModeRegistry
}

// Run starts the registry services
func (r *Runner) Run(ctx context.Context) error {
	cfg := r.cfg.Config
	logger := r.cfg.Logger

	logger.Info("Starting registry server",
		zap.String("address", cfg.Server.Address()),
		zap.String("source_url", cfg.Source.URL))

	// Create store and load cache
	r.store = registry.NewStore(cfg.Cache.Path)
	if err := r.store.Load(); err != nil {
		logger.Warn("Failed to load cache, starting fresh", zap.Error(err))
	} else {
		logger.Info("Loaded cache",
			zap.Int("entries", r.store.Count()),
			zap.Time("last_updated", r.store.LastUpdated()))
	}

	// Create fetcher and start polling
	fetchCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel

	r.fetcher = registry.NewFetcher(cfg, r.store, logger)
	if err := r.fetcher.Start(fetchCtx); err != nil {
		logger.Error("Failed to start fetcher", zap.Error(err))
	}

	// Set up Gin
	if cfg.Logging.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger(logger))

	// Add JWT middleware
	if cfg.JWT.RequireAuth {
		router.Use(registry.JWTMiddleware(cfg.JWT, logger))
	} else {
		router.Use(registry.OptionalJWTMiddleware(cfg.JWT, logger))
	}

	// Add rate limiting
	rateLimiter := registry.NewRateLimiter(cfg.RateLimit)
	router.Use(registry.RateLimitMiddleware(rateLimiter))

	// Register handlers
	handler := registry.NewHandler(r.store, &cfg.DynamicCache, &cfg.ImageEmbed, logger)
	handler.RegisterRoutes(router)

	// Create HTTP server
	r.srv = &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		logger.Info("Registry server listening", zap.String("address", cfg.Server.Address()))
		if err := r.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Registry server error", zap.Error(err))
		}
	}()

	// Block until context is cancelled
	<-ctx.Done()
	return nil
}

// Shutdown gracefully shuts down the registry services
func (r *Runner) Shutdown(ctx context.Context) error {
	logger := r.cfg.Logger

	// Stop fetcher
	if r.cancel != nil {
		r.cancel()
	}
	if r.fetcher != nil {
		r.fetcher.Stop()
	}

	// Shutdown server
	if r.srv != nil {
		if err := r.srv.Shutdown(ctx); err != nil {
			logger.Error("Registry server forced to shutdown", zap.Error(err))
		}
	}

	// Save cache
	if r.store != nil {
		if err := r.store.Save(); err != nil {
			logger.Error("Failed to save cache on shutdown", zap.Error(err))
		}
	}

	return nil
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
		)
	}
}
