// Package backend provides the backend mode runner.
package backend

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
	modes.Register(modes.ModeBackend, func(cfg interface{}) (modes.Runner, error) {
		c, ok := cfg.(*Config)
		if !ok {
			return nil, fmt.Errorf("invalid config type for backend mode")
		}
		return New(c)
	})
}

// Config holds configuration for the backend mode
type Config struct {
	Config *config.Config
	Logger *zap.Logger
}

// Runner implements the backend mode
type Runner struct {
	cfg       *Config
	store     backend.Backend
	srv       *http.Server
	adminSrv  *http.Server
}

// New creates a new backend runner
func New(cfg *Config) (*Runner, error) {
	return &Runner{cfg: cfg}, nil
}

// Name returns the mode name
func (r *Runner) Name() modes.Mode {
	return modes.ModeBackend
}

// Run starts the backend services
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

	logger.Info("Storage backend initialized", zap.String("type", cfg.Storage.Type))

	// Ping storage to verify connection
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := store.Ping(pingCtx); err != nil {
		return fmt.Errorf("failed to ping storage: %w", err)
	}

	// Initialize services
	services := service.NewServices(store, cfg, logger)

	// Initialize public HTTP server
	router := setupRouter(cfg, services, store, logger)

	r.srv = &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start public server
	go func() {
		logger.Info("Backend server listening", zap.String("address", cfg.Server.Address()))
		if err := r.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Backend server error", zap.Error(err))
		}
	}()

	// Start admin server on separate port (if configured)
	if cfg.Server.AdminPort > 0 {
		adminToken := cfg.Server.AdminToken
		if adminToken == "" {
			var err error
			adminToken, err = middleware.GenerateAdminToken()
			if err != nil {
				return fmt.Errorf("failed to generate admin token: %w", err)
			}
			logger.Info("Generated admin API token (set WALLET_SERVER_ADMIN_TOKEN to use a fixed token)",
				zap.String("token", adminToken))
		}

		adminRouter := setupAdminRouter(store, adminToken, logger)
		r.adminSrv = &http.Server{
			Addr:         cfg.Server.AdminAddress(),
			Handler:      adminRouter,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		go func() {
			logger.Info("Admin server listening", zap.String("address", cfg.Server.AdminAddress()))
			if err := r.adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("Admin server error", zap.Error(err))
			}
		}()
	}

	// Block until context is cancelled
	<-ctx.Done()
	return nil
}

// Shutdown gracefully shuts down the backend services
func (r *Runner) Shutdown(ctx context.Context) error {
	logger := r.cfg.Logger

	if r.srv != nil {
		if err := r.srv.Shutdown(ctx); err != nil {
			logger.Error("Backend server forced to shutdown", zap.Error(err))
		}
	}

	if r.adminSrv != nil {
		if err := r.adminSrv.Shutdown(ctx); err != nil {
			logger.Error("Admin server forced to shutdown", zap.Error(err))
		}
	}

	if r.store != nil {
		if err := r.store.Close(); err != nil {
			logger.Error("Failed to close storage", zap.Error(err))
		}
	}

	return nil
}

func setupRouter(cfg *config.Config, services *service.Services, store backend.Backend, logger *zap.Logger) *gin.Engine {
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
		AllowOrigins:     []string{"*"}, // TODO: Make configurable
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "If-None-Match", "X-Private-Data-If-Match", "X-Private-Data-If-None-Match", "X-Tenant-ID"},
		ExposeHeaders:    []string{"X-Private-Data-ETag"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Initialize API handlers
	handlers := api.NewHandlers(services, cfg, logger)

	// Root-level health/status endpoints (no tenant required)
	router.GET("/status", handlers.Status)
	router.GET("/health", handlers.Status)

	// =========================================================================
	// PUBLIC ROUTES (unauthenticated)
	// Tenant comes from X-Tenant-ID header (TenantHeaderMiddleware)
	// =========================================================================
	public := router.Group("/")
	{
		// User authentication routes (no auth required)
		user := public.Group("/user")
		user.Use(middleware.TenantHeaderMiddleware(store))
		{
			user.POST("/register", handlers.RegisterUser)
			user.POST("/login", handlers.LoginUser)

			// WebAuthn routes
			user.POST("/register-webauthn-begin", handlers.StartWebAuthnRegistration)
			user.POST("/register-webauthn-finish", handlers.FinishWebAuthnRegistration)
			user.POST("/login-webauthn-begin", handlers.StartWebAuthnLogin)
			user.POST("/login-webauthn-finish", handlers.FinishWebAuthnLogin)
		}

		// Helper routes (some public)
		public.GET("/helper/auth-check", handlers.AuthCheck)
		public.POST("/helper/auth-check", handlers.AuthCheck)

		// WebSocket for client-side keystore
		public.GET("/ws/keystore", handlers.WebSocketKeystore)
	}

	// =========================================================================
	// PROTECTED ROUTES (authenticated)
	// Tenant comes from JWT token (AuthMiddleware sets tenant_id from JWT claim)
	// =========================================================================
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware(cfg, store, logger))
	{
		// User session routes (authenticated)
		session := protected.Group("/user/session")
		{
			session.GET("/account-info", handlers.GetAccountInfo)
			session.POST("/settings", handlers.UpdateSettings)
			session.GET("/private-data", handlers.GetPrivateData)
			session.POST("/private-data", handlers.UpdatePrivateData)
			session.DELETE("/", handlers.DeleteUser)

			// WebAuthn credential management
			session.POST("/webauthn/register-begin", handlers.StartAddWebAuthnCredential)
			session.POST("/webauthn/register-finish", handlers.FinishAddWebAuthnCredential)
			session.POST("/webauthn/credential/:id/rename", handlers.RenameWebAuthnCredential)
			session.POST("/webauthn/credential/:id/delete", handlers.DeleteWebAuthnCredential)
		}
		protected.DELETE("/user/session", handlers.DeleteUser)

		// Storage routes
		storageGroup := protected.Group("/storage")
		{
			storageGroup.GET("/vc", handlers.GetAllCredentials)
			storageGroup.POST("/vc", handlers.StoreCredential)
			storageGroup.POST("/vc/update", handlers.UpdateCredential)
			storageGroup.GET("/vc/:credential_identifier", handlers.GetCredentialByIdentifier)
			storageGroup.DELETE("/vc/:credential_identifier", handlers.DeleteCredential)

			storageGroup.GET("/vp", handlers.GetAllPresentations)
			storageGroup.POST("/vp", handlers.StorePresentation)
			storageGroup.GET("/vp/:presentation_identifier", handlers.GetPresentationByIdentifier)
		}

		// Issuer routes
		issuerGroup := protected.Group("/issuer")
		{
			issuerGroup.GET("/all", handlers.GetAllIssuers)
		}

		// Verifier routes
		verifierGroup := protected.Group("/verifier")
		{
			verifierGroup.GET("/all", handlers.GetAllVerifiers)
		}

		// Proxy routes
		protected.POST("/proxy", handlers.ProxyRequest)

		// Helper routes
		protected.POST("/helper/get-cert", handlers.GetCertificate)

		// Keystore routes
		keystoreGroup := protected.Group("/keystore")
		{
			keystoreGroup.GET("/status", handlers.KeystoreStatus)
		}

		// Wallet provider routes
		walletProvider := protected.Group("/wallet-provider")
		{
			walletProvider.POST("/key-attestation/generate", handlers.GenerateKeyAttestation)
		}
	}

	return router
}

func setupAdminRouter(store backend.Backend, adminToken string, logger *zap.Logger) *gin.Engine {
	router := gin.New()

	router.Use(gin.Recovery())
	router.Use(middleware.Logger(logger))

	adminHandlers := api.NewAdminHandlers(store, logger)

	router.GET("/admin/status", adminHandlers.AdminStatus)

	admin := router.Group("/admin")
	admin.Use(middleware.AdminAuthMiddleware(adminToken, logger))
	{
		tenants := admin.Group("/tenants")
		{
			tenants.GET("", adminHandlers.ListTenants)
			tenants.POST("", adminHandlers.CreateTenant)
			tenants.GET("/:id", adminHandlers.GetTenant)
			tenants.PUT("/:id", adminHandlers.UpdateTenant)
			tenants.DELETE("/:id", adminHandlers.DeleteTenant)

			tenants.GET("/:id/users", adminHandlers.GetTenantUsers)
			tenants.POST("/:id/users", adminHandlers.AddUserToTenant)
			tenants.DELETE("/:id/users/:user_id", adminHandlers.RemoveUserFromTenant)

			tenants.GET("/:id/issuers", adminHandlers.ListIssuers)
			tenants.POST("/:id/issuers", adminHandlers.CreateIssuer)
			tenants.GET("/:id/issuers/:issuer_id", adminHandlers.GetIssuer)
			tenants.PUT("/:id/issuers/:issuer_id", adminHandlers.UpdateIssuer)
			tenants.DELETE("/:id/issuers/:issuer_id", adminHandlers.DeleteIssuer)

			tenants.GET("/:id/verifiers", adminHandlers.ListVerifiers)
			tenants.POST("/:id/verifiers", adminHandlers.CreateVerifier)
			tenants.GET("/:id/verifiers/:verifier_id", adminHandlers.GetVerifier)
			tenants.PUT("/:id/verifiers/:verifier_id", adminHandlers.UpdateVerifier)
			tenants.DELETE("/:id/verifiers/:verifier_id", adminHandlers.DeleteVerifier)
		}
	}

	return router
}
