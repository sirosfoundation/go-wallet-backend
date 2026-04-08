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
	"github.com/sirosfoundation/go-wallet-backend/pkg/authz"
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
	Roles  []string // Active roles (for status endpoint)
}

// Runner implements the backend mode
type Runner struct {
	cfg      *Config
	store    backend.Backend
	srv      *http.Server
	adminSrv *http.Server
}

// New creates a new backend runner
func New(cfg *Config) (*Runner, error) {
	return &Runner{cfg: cfg}, nil
}

// Role returns the role this runner implements
func (r *Runner) Role() modes.Role {
	return modes.RoleBackend
}

// Name returns the mode name (deprecated, use Role())
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

	// Determine roles for status endpoint
	roles := r.cfg.Roles
	if len(roles) == 0 {
		roles = []string{"backend"}
	}

	// Initialize public HTTP server
	router, err := setupRouter(cfg, services, store, logger, roles)
	if err != nil {
		return fmt.Errorf("failed to setup router: %w", err)
	}

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
		if err := cfg.Server.TLS.ListenAndServe(r.srv); err != nil && err != http.ErrServerClosed {
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
			// Log token at DEBUG level to avoid capture by production log aggregators
			// For production deployments, set WALLET_SERVER_ADMIN_TOKEN or use admin_token_path
			logger.Debug("Generated admin API token",
				zap.String("token", adminToken))
			logger.Warn("Auto-generated admin token (use WALLET_SERVER_ADMIN_TOKEN or admin_token_path for production)")
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
			if err := cfg.Server.TLS.ListenAndServe(r.adminSrv); err != nil && err != http.ErrServerClosed {
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

func setupRouter(cfg *config.Config, services *service.Services, store backend.Backend, logger *zap.Logger, roles []string) (*gin.Engine, error) {
	// Set Gin mode
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// Middleware
	router.Use(gin.Recovery())
	router.Use(middleware.Logger(logger, "/status", "/health"))
	if v := cfg.Server.ResolvedServedBy(); v != "" {
		router.Use(middleware.ServedByMiddleware(v))
	}
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

	// Create HTTP client for outbound requests (AuthZEN proxy, etc.)
	httpClient := cfg.HTTPClient.NewHTTPClient(0)

	// Initialize AuthZEN proxy handler (for frontend trust evaluation)
	var authzenHandler *api.AuthZENProxyHandler
	if cfg.AuthZENProxy.Enabled {
		// Set defaults
		cfg.AuthZENProxy.SetDefaults()

		// Create SPOCP authorizer
		spocpCfg := &authz.SPOCPConfig{
			RulesFile: cfg.AuthZENProxy.RulesFile,
		}
		authorizer, err := authz.NewSPOCPAuthorizer(spocpCfg, logger)
		if err != nil {
			logger.Error("Failed to initialize SPOCP authorizer", zap.Error(err))
			authorizer = nil
		}

		// Fail-closed: if SPOCP initialization failed in production, refuse to start
		var authorizerInterface authz.Authorizer
		if authorizer != nil {
			authorizerInterface = authorizer
		} else {
			// Production guard: NoOpAuthorizer cannot be used in release mode
			if gin.Mode() == gin.ReleaseMode {
				return nil, fmt.Errorf("SPOCP authorizer failed to initialize and NoOpAuthorizer cannot be used in production (GIN_MODE=release). Configure a valid rules file or set GIN_MODE=debug for development")
			}
			logger.Warn("Using NoOpAuthorizer - ALL requests will be authorized. This is only safe for development!")
			authorizerInterface = authz.NoOpAuthorizer{}
		}

		// Get effective PDP URL and set it on the config so the handler uses it
		pdpURL := cfg.AuthZENProxy.GetPDPURL(cfg.Trust.GetPDPURL())
		cfg.AuthZENProxy.PDPURL = pdpURL

		authzenHandler = api.NewAuthZENProxyHandler(
			&cfg.AuthZENProxy,
			authorizerInterface,
			store.Tenants(), // Enable per-tenant PDP configuration lookup
			httpClient,
			logger,
		)

		logger.Info("AuthZEN proxy initialized",
			zap.String("pdp_url", pdpURL),
			zap.String("rules_file", cfg.AuthZENProxy.RulesFile),
		)
	}

	// Root-level health/status endpoints (no tenant required)
	router.GET("/status", handlers.Status)
	router.GET("/health", handlers.Status)

	// =========================================================================
	// PUBLIC API ROUTES (unauthenticated)
	// These endpoints provide public configuration data
	// =========================================================================
	apiV1 := router.Group("/api/v1")
	{
		// Public tenant config - returns OIDC gate settings etc.
		apiV1.GET("/tenants/:id/config", handlers.GetTenantConfig)
	}

	// =========================================================================
	// PUBLIC ROUTES (unauthenticated)
	// Tenant comes from X-Tenant-ID header (TenantHeaderMiddleware)
	// =========================================================================
	public := router.Group("/")

	// Create OIDC validator cache for gate middleware
	validatorCache := middleware.NewValidatorCache(httpClient, logger)

	{
		// Base user group with tenant middleware
		userBase := public.Group("/user")
		userBase.Use(middleware.TenantHeaderMiddleware(store))

		// Registration routes (with OIDC registration gate)
		registration := userBase.Group("")
		registration.Use(middleware.OIDCGateMiddleware(validatorCache, middleware.GateTypeRegistration, logger))
		{
			registration.POST("/register-webauthn-begin", handlers.StartWebAuthnRegistration)
			registration.POST("/register-webauthn-finish", handlers.FinishWebAuthnRegistration)
		}

		// Login routes (with OIDC login gate)
		login := userBase.Group("")
		login.Use(middleware.OIDCGateMiddleware(validatorCache, middleware.GateTypeLogin, logger))
		{
			login.POST("/login-webauthn-begin", handlers.StartWebAuthnLogin)
			login.POST("/login-webauthn-finish", handlers.FinishWebAuthnLogin)
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

		// Proxy routes (can be disabled via features.proxy_enabled)
		if cfg.Features.ProxyEnabled {
			protected.POST("/proxy", handlers.ProxyRequest)
		}

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

		// =========================================================================
		// V1 API ROUTES (authenticated)
		// These endpoints require JWT authentication
		// =========================================================================
		if authzenHandler != nil {
			v1 := protected.Group("/v1")
			{
				// AuthZEN proxy endpoints for frontend trust evaluation
				v1.POST("/evaluate", authzenHandler.Evaluate)
				v1.POST("/resolve", authzenHandler.Resolve)
			}
		}
	}

	return router, nil
}

func setupAdminRouter(store backend.Backend, adminToken string, logger *zap.Logger) *gin.Engine {
	router := gin.New()

	router.Use(gin.Recovery())
	router.Use(middleware.Logger(logger, "/admin/status"))

	adminHandlers := api.NewAdminHandlers(store, logger)

	router.GET("/admin/status", adminHandlers.AdminStatus)

	admin := router.Group("/admin")
	admin.Use(middleware.AdminAuthMiddleware(adminToken, logger))
	adminHandlers.RegisterRoutes(admin)

	return router
}
