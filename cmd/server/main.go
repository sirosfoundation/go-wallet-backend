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

	// Initialize HTTP server
	router := setupRouter(cfg, services, logger)

	srv := &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		logger.Info("Server listening", zap.String("address", cfg.Server.Address()))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Graceful shutdown
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
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

func setupRouter(cfg *config.Config, services *service.Services, logger *zap.Logger) *gin.Engine {
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
		AllowHeaders:     []string{"Authorization", "Content-Type", "If-None-Match", "X-Private-Data-If-Match", "X-Private-Data-If-None-Match"},
		ExposeHeaders:    []string{"X-Private-Data-ETag"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Initialize API handlers
	handlers := api.NewHandlers(services, cfg, logger)

	// Public routes
	public := router.Group("/")
	{
		public.GET("/status", handlers.Status)

		// User authentication routes (no auth required)
		user := public.Group("/user")
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

			// Account deletion
			session.DELETE("/", handlers.DeleteUser)

			// WebAuthn credential management for existing users
			session.POST("/webauthn/register-begin", handlers.StartAddWebAuthnCredential)
			session.POST("/webauthn/register-finish", handlers.FinishAddWebAuthnCredential)
			session.POST("/webauthn/credential/:id/rename", handlers.RenameWebAuthnCredential)
			session.POST("/webauthn/credential/:id/delete", handlers.DeleteWebAuthnCredential)
		}

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

	return router
}
