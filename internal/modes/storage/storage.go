// Package storage provides the storage mode runner.
// This mode handles credential and presentation storage,
// separated from authentication for privacy-preserving deployments.
package storage

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

func init() {
	modes.Register(modes.RoleStorage, func(cfg interface{}) (modes.Runner, error) {
		c, ok := cfg.(*Config)
		if !ok {
			return nil, fmt.Errorf("invalid config type for storage mode")
		}
		return New(c)
	})
}

// Config holds configuration for the storage mode
type Config struct {
	Config *config.Config
	Logger *zap.Logger
	Roles  []string // Active roles (for status endpoint)
}

// Runner implements the storage mode
type Runner struct {
	cfg   *Config
	store backend.Backend
	srv   *http.Server
}

// New creates a new storage runner
func New(cfg *Config) (*Runner, error) {
	return &Runner{cfg: cfg}, nil
}

// Role returns the role this runner implements
func (r *Runner) Role() modes.Role {
	return modes.RoleStorage
}

// Name returns the mode name (deprecated, use Role())
func (r *Runner) Name() modes.Mode {
	return modes.RoleStorage
}

// Run starts the storage services
func (r *Runner) Run(ctx context.Context) error {
	cfg := r.cfg.Config
	logger := r.cfg.Logger

	// Initialize storage backend
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	store, err := backend.New(initCtx, cfg)
	cancel()
	if err != nil {
		return fmt.Errorf("failed to initialize storage backend: %w", err)
	}
	r.store = store

	logger.Info("Storage mode backend initialized", zap.String("type", cfg.Storage.Type))

	// Ping storage to verify connection
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := store.Ping(pingCtx); err != nil {
		return fmt.Errorf("failed to ping storage: %w", err)
	}

	// Initialize services (storage-only subset)
	services := service.NewServices(store, cfg, logger)

	// Determine roles for status endpoint
	roles := r.cfg.Roles
	if len(roles) == 0 {
		roles = []string{"storage"}
	}

	// Initialize HTTP server with storage-only routes
	router := setupStorageRouter(cfg, services, store, logger, roles)

	r.srv = &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		logger.Info("Storage server listening", zap.String("address", cfg.Server.Address()))
		if err := r.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Storage server error", zap.Error(err))
		}
	}()

	// Block until context is cancelled
	<-ctx.Done()
	return nil
}

// Shutdown gracefully shuts down the storage services
func (r *Runner) Shutdown(ctx context.Context) error {
	logger := r.cfg.Logger

	if r.srv != nil {
		if err := r.srv.Shutdown(ctx); err != nil {
			logger.Error("Storage server forced to shutdown", zap.Error(err))
		}
	}

	if r.store != nil {
		if err := r.store.Close(); err != nil {
			logger.Error("Failed to close storage", zap.Error(err))
		}
	}

	return nil
}

func setupStorageRouter(cfg *config.Config, services *service.Services, store backend.Backend, logger *zap.Logger, roles []string) *gin.Engine {
	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Middleware
	router.Use(gin.Recovery())
	router.Use(middleware.Logger(logger))
	router.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.Server.CORS.AllowedOrigins,
		AllowMethods:     cfg.Server.CORS.AllowedMethods,
		AllowHeaders:     cfg.Server.CORS.AllowedHeaders,
		ExposeHeaders:    cfg.Server.CORS.ExposedHeaders,
		AllowCredentials: cfg.Server.CORS.AllowCredentials,
		MaxAge:           time.Duration(cfg.Server.CORS.MaxAge) * time.Second,
	}))

	// Initialize API handlers
	handlers := api.NewHandlers(services, cfg, logger, roles)

	// Root-level health/status endpoints
	router.GET("/status", handlers.Status)
	router.GET("/health", handlers.Status)

	// =========================================================================
	// PROTECTED ROUTES (authenticated)
	// Storage-related: credentials, presentations, private data
	// =========================================================================
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware(cfg, store, logger))
	{
		// Private data storage (encrypted keystore data)
		session := protected.Group("/user/session")
		{
			session.GET("/private-data", handlers.GetPrivateData)
			session.POST("/private-data", handlers.UpdatePrivateData)
		}

		// Credential storage routes
		storageGroup := protected.Group("/storage")
		{
			// Verifiable Credentials
			storageGroup.GET("/vc", handlers.GetAllCredentials)
			storageGroup.POST("/vc", handlers.StoreCredential)
			storageGroup.POST("/vc/update", handlers.UpdateCredential)
			storageGroup.GET("/vc/:credential_identifier", handlers.GetCredentialByIdentifier)
			storageGroup.DELETE("/vc/:credential_identifier", handlers.DeleteCredential)

			// Verifiable Presentations
			storageGroup.GET("/vp", handlers.GetAllPresentations)
			storageGroup.POST("/vp", handlers.StorePresentation)
			storageGroup.GET("/vp/:presentation_identifier", handlers.GetPresentationByIdentifier)
		}

		// Keystore status
		keystoreGroup := protected.Group("/keystore")
		{
			keystoreGroup.GET("/status", handlers.KeystoreStatus)
		}
	}

	return router
}
