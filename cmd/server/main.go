package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

var (
	configFile = flag.String("config", "configs/config.yaml", "Path to configuration file")
	version    = "dev"
	buildTime  = "unknown"
)

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger, err := initLogger(cfg.Logging)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("Starting Wallet Backend Server",
		zap.String("version", version),
		zap.String("build_time", buildTime),
	)

	// Initialize storage backend
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	store, err := backend.New(ctx, cfg)
	cancel()
	if err != nil {
		logger.Fatal("Failed to initialize storage backend", zap.Error(err))
	}
	defer func() { _ = store.Close() }()

	logger.Info("Storage backend initialized", zap.String("type", cfg.Storage.Type))

	// Ping storage to verify connection
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Ping(ctx); err != nil {
		logger.Fatal("Failed to ping storage", zap.Error(err))
	}

	// Initialize services
	services := service.NewServices(store, cfg, logger)

	// Initialize public HTTP server
	router := setupRouter(cfg, services, store, logger)

	srv := &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start public server
	go func() {
		logger.Info("Public server listening", zap.String("address", cfg.Server.Address()))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start public server", zap.Error(err))
		}
	}()

	// Start admin server on separate port (if configured)
	var adminSrv *http.Server
	if cfg.Server.AdminPort > 0 {
		// Generate admin token if not provided
		adminToken := cfg.Server.AdminToken
		if adminToken == "" {
			var err error
			adminToken, err = middleware.GenerateAdminToken()
			if err != nil {
				logger.Fatal("Failed to generate admin token", zap.Error(err))
			}
			logger.Info("Generated admin API token (set WALLET_SERVER_ADMIN_TOKEN to use a fixed token)",
				zap.String("token", adminToken))
		}

		adminRouter := setupAdminRouter(store, adminToken, logger)
		adminSrv = &http.Server{
			Addr:         cfg.Server.AdminAddress(),
			Handler:      adminRouter,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		go func() {
			logger.Info("Admin server listening", zap.String("address", cfg.Server.AdminAddress()))
			if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Failed to start admin server", zap.Error(err))
			}
		}()
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Public server forced to shutdown", zap.Error(err))
	}

	// Shutdown admin server if running
	if adminSrv != nil {
		if err := adminSrv.Shutdown(ctx); err != nil {
			logger.Error("Admin server forced to shutdown", zap.Error(err))
		}
	}

	logger.Info("Server exited")
}

func initLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
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

	// Public routes (default tenant for backward compatibility)
	public := router.Group("/")
	{
		public.GET("/status", handlers.Status)

		// User authentication routes (no auth required)
		// TenantHeaderMiddleware validates the X-Tenant-ID header
		// and sets tenant context for registration endpoints
		user := public.Group("/user")
		user.Use(middleware.TenantHeaderMiddleware(store))
		{
			user.POST("/register", handlers.RegisterUser)
			user.POST("/login", handlers.LoginUser)

			// WebAuthn routes (no auth required for initial registration/login)
			user.POST("/register-webauthn-begin", handlers.StartWebAuthnRegistration)
			user.POST("/register-webauthn-finish", handlers.FinishWebAuthnRegistration)
			user.POST("/login-webauthn-begin", handlers.StartWebAuthnLogin)
			user.POST("/login-webauthn-finish", handlers.FinishWebAuthnLogin)
		}

		// Helper routes (some public)
		public.GET("/helper/auth-check", handlers.AuthCheck)
		public.POST("/helper/auth-check", handlers.AuthCheck)

		// WebSocket for client-side keystore
		// Auth is handled via appToken in the WebSocket handshake, not HTTP headers
		public.GET("/ws/keystore", handlers.WebSocketKeystore)
	}

	// Protected routes (require authentication)
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware(cfg, logger))
	{
		// User session routes (authenticated)
		session := protected.Group("/user/session")
		{
			// Account info and settings
			session.GET("/account-info", handlers.GetAccountInfo)
			session.POST("/settings", handlers.UpdateSettings)

			// Private data management
			session.GET("/private-data", handlers.GetPrivateData)
			session.POST("/private-data", handlers.UpdatePrivateData)

			// Account deletion - handle both /user/session and /user/session/
			session.DELETE("/", handlers.DeleteUser)

			// WebAuthn credential management for existing users
			session.POST("/webauthn/register-begin", handlers.StartAddWebAuthnCredential)
			session.POST("/webauthn/register-finish", handlers.FinishAddWebAuthnCredential)
			session.POST("/webauthn/credential/:id/rename", handlers.RenameWebAuthnCredential)
			session.POST("/webauthn/credential/:id/delete", handlers.DeleteWebAuthnCredential)
		}
		// Also register DELETE at /user/session (without trailing slash)
		// This is needed because DELETE requests don't follow redirects
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
			// TODO: Add OpenID4VCI endpoints
		}

		// Verifier routes
		verifierGroup := protected.Group("/verifier")
		{
			verifierGroup.GET("/all", handlers.GetAllVerifiers)
			// TODO: Add OpenID4VP endpoints
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

	// Tenant-scoped routes (with tenant path parameter)
	// These routes require a valid tenant ID in the path
	// Note: Registration uses the global endpoint with tenantId parameter instead
	tenantRoutes := router.Group("/t/:tenantID")
	tenantRoutes.Use(middleware.TenantPathMiddleware(store))
	{
		// Tenant-scoped WebAuthn login (public) - kept for backwards compatibility
		tenantUser := tenantRoutes.Group("/user")
		{
			tenantUser.POST("/login-webauthn-begin", handlers.StartTenantWebAuthnLogin)
			tenantUser.POST("/login-webauthn-finish", handlers.FinishTenantWebAuthnLogin)
		}

		// Tenant-scoped protected routes (require authentication)
		tenantProtected := tenantRoutes.Group("/")
		tenantProtected.Use(middleware.AuthMiddleware(cfg, logger))
		{
			// Tenant-scoped issuer routes
			tenantIssuer := tenantProtected.Group("/issuer")
			{
				tenantIssuer.GET("/all", handlers.GetAllIssuers)
			}

			// Tenant-scoped verifier routes
			tenantVerifier := tenantProtected.Group("/verifier")
			{
				tenantVerifier.GET("/all", handlers.GetAllVerifiers)
			}
		}
	}

	return router
}

// setupAdminRouter creates the admin router for internal management APIs
func setupAdminRouter(store backend.Backend, adminToken string, logger *zap.Logger) *gin.Engine {
	router := gin.New()

	// Middleware
	router.Use(gin.Recovery())
	router.Use(middleware.Logger(logger))

	// Initialize admin handlers
	adminHandlers := api.NewAdminHandlers(store, logger)

	// Public status endpoint (no auth required for health checks)
	router.GET("/admin/status", adminHandlers.AdminStatus)

	// Admin routes - protected with bearer token authentication
	admin := router.Group("/admin")
	admin.Use(middleware.AdminAuthMiddleware(adminToken, logger))
	{
		// Tenant management
		tenants := admin.Group("/tenants")
		{
			tenants.GET("", adminHandlers.ListTenants)
			tenants.POST("", adminHandlers.CreateTenant)
			tenants.GET("/:id", adminHandlers.GetTenant)
			tenants.PUT("/:id", adminHandlers.UpdateTenant)
			tenants.DELETE("/:id", adminHandlers.DeleteTenant)

			// Tenant user management
			tenants.GET("/:id/users", adminHandlers.GetTenantUsers)
			tenants.POST("/:id/users", adminHandlers.AddUserToTenant)
			tenants.DELETE("/:id/users/:user_id", adminHandlers.RemoveUserFromTenant)

			// Tenant issuer management
			tenants.GET("/:id/issuers", adminHandlers.ListIssuers)
			tenants.POST("/:id/issuers", adminHandlers.CreateIssuer)
			tenants.GET("/:id/issuers/:issuer_id", adminHandlers.GetIssuer)
			tenants.PUT("/:id/issuers/:issuer_id", adminHandlers.UpdateIssuer)
			tenants.DELETE("/:id/issuers/:issuer_id", adminHandlers.DeleteIssuer)

			// Tenant verifier management
			tenants.GET("/:id/verifiers", adminHandlers.ListVerifiers)
			tenants.POST("/:id/verifiers", adminHandlers.CreateVerifier)
			tenants.GET("/:id/verifiers/:verifier_id", adminHandlers.GetVerifier)
			tenants.PUT("/:id/verifiers/:verifier_id", adminHandlers.UpdateVerifier)
			tenants.DELETE("/:id/verifiers/:verifier_id", adminHandlers.DeleteVerifier)
		}
	}

	return router
}
