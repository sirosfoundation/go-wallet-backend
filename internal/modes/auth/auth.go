// Package auth provides the authentication mode runner.
// This mode handles user authentication, WebAuthn, and session management,
// separated from credential storage for privacy-preserving deployments.
package auth

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
	modes.Register(modes.RoleAuth, func(cfg interface{}) (modes.Runner, error) {
		c, ok := cfg.(*Config)
		if !ok {
			return nil, fmt.Errorf("invalid config type for auth mode")
		}
		return New(c)
	})
}

// Config holds configuration for the auth mode
type Config struct {
	Config *config.Config
	Logger *zap.Logger
	Roles  []string // Active roles (for status endpoint)
}

// Runner implements the auth mode
type Runner struct {
	cfg   *Config
	store backend.Backend
	srv   *http.Server
}

// New creates a new auth runner
func New(cfg *Config) (*Runner, error) {
	return &Runner{cfg: cfg}, nil
}

// Role returns the role this runner implements
func (r *Runner) Role() modes.Role {
	return modes.RoleAuth
}

// Name returns the mode name (deprecated, use Role())
func (r *Runner) Name() modes.Mode {
	return modes.RoleAuth
}

// Run starts the auth services
func (r *Runner) Run(ctx context.Context) error {
	cfg := r.cfg.Config
	logger := r.cfg.Logger

	// Initialize storage backend (needed for user/tenant data)
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	store, err := backend.New(initCtx, cfg)
	cancel()
	if err != nil {
		return fmt.Errorf("failed to initialize storage backend: %w", err)
	}
	r.store = store

	logger.Info("Auth mode storage initialized", zap.String("type", cfg.Storage.Type))

	// Ping storage to verify connection
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := store.Ping(pingCtx); err != nil {
		return fmt.Errorf("failed to ping storage: %w", err)
	}

	// Initialize services (auth-only subset)
	services := service.NewServices(store, cfg, logger)

	// Determine roles for status endpoint
	roles := r.cfg.Roles
	if len(roles) == 0 {
		roles = []string{"auth"}
	}

	// Initialize HTTP server with auth-only routes
	router := setupAuthRouter(cfg, services, store, logger, roles)

	r.srv = &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		logger.Info("Auth server listening", zap.String("address", cfg.Server.Address()))
		if err := r.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Auth server error", zap.Error(err))
		}
	}()

	// Block until context is cancelled
	<-ctx.Done()
	return nil
}

// Shutdown gracefully shuts down the auth services
func (r *Runner) Shutdown(ctx context.Context) error {
	logger := r.cfg.Logger

	if r.srv != nil {
		if err := r.srv.Shutdown(ctx); err != nil {
			logger.Error("Auth server forced to shutdown", zap.Error(err))
		}
	}

	if r.store != nil {
		if err := r.store.Close(); err != nil {
			logger.Error("Failed to close storage", zap.Error(err))
		}
	}

	return nil
}

func setupAuthRouter(cfg *config.Config, services *service.Services, store backend.Backend, logger *zap.Logger, roles []string) *gin.Engine {
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
	// PUBLIC ROUTES (unauthenticated)
	// Auth-related: registration, login, WebAuthn
	// =========================================================================

	// Create rate limiter for auth endpoints
	rateLimiter := middleware.NewAuthRateLimiter(cfg.Security.AuthRateLimit, logger)

	public := router.Group("/")
	{
		// User authentication routes
		user := public.Group("/user")
		user.Use(middleware.TenantHeaderMiddleware(store))
		{
			user.POST("/register", handlers.RegisterUser)
			user.POST("/login", handlers.LoginUser)

			// WebAuthn routes - protected by rate limiting
			webauthn := user.Group("")
			webauthn.Use(middleware.AuthRateLimitMiddleware(rateLimiter))
			{
				webauthn.POST("/register-webauthn-begin", handlers.StartWebAuthnRegistration)
				webauthn.POST("/register-webauthn-finish", handlers.FinishWebAuthnRegistration)
				webauthn.POST("/login-webauthn-begin", handlers.StartWebAuthnLogin)
				webauthn.POST("/login-webauthn-finish", handlers.FinishWebAuthnLogin)
			}

			// Token refresh endpoint (rate limited)
			user.POST("/token/refresh", middleware.AuthRateLimitMiddleware(rateLimiter), handlers.RefreshToken)
		}

		// Auth check helper
		public.GET("/helper/auth-check", handlers.AuthCheck)
		public.POST("/helper/auth-check", handlers.AuthCheck)
	}

	// =========================================================================
	// PROTECTED ROUTES (authenticated)
	// Auth-related: session management, WebAuthn credential management
	// =========================================================================
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware(cfg, store, logger))
	{
		// User session routes (auth-related only)
		session := protected.Group("/user/session")
		{
			session.GET("/account-info", handlers.GetAccountInfo)
			session.POST("/settings", handlers.UpdateSettings)

			// WebAuthn credential management
			session.POST("/webauthn/register-begin", handlers.StartAddWebAuthnCredential)
			session.POST("/webauthn/register-finish", handlers.FinishAddWebAuthnCredential)
			session.POST("/webauthn/credential/:id/rename", handlers.RenameWebAuthnCredential)
			session.POST("/webauthn/credential/:id/delete", handlers.DeleteWebAuthnCredential)
		}
		protected.DELETE("/user/session", handlers.DeleteUser)
		protected.POST("/user/logout", handlers.Logout)
	}

	return router
}
