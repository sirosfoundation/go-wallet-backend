// Package server contains RouteProvider implementations for different modes.
// Each provider contributes routes to a shared HTTP server managed by server.Manager.
package server

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// =============================================================================
// Auth Provider - handles authentication routes only
// =============================================================================

// AuthProvider provides authentication routes (WebAuthn, login, register)
type AuthProvider struct {
	cfg      *config.Config
	logger   *zap.Logger
	store    backend.Backend
	services *service.Services
	handlers *api.Handlers
	roles    []string
}

// NewAuthProvider creates a new auth route provider
func NewAuthProvider(cfg *config.Config, store backend.Backend, logger *zap.Logger, roles []string) *AuthProvider {
	services := service.NewServices(store, cfg, logger)
	handlers := api.NewHandlers(services, cfg, logger, roles)
	return &AuthProvider{
		cfg:      cfg,
		logger:   logger,
		store:    store,
		services: services,
		handlers: handlers,
		roles:    roles,
	}
}

func (p *AuthProvider) Transport() Transport { return TransportHTTP }
func (p *AuthProvider) Name() string         { return "auth" }

func (p *AuthProvider) RegisterRoutes(router *gin.Engine) {
	// Public auth routes (no authentication required)
	public := router.Group("/")
	{
		user := public.Group("/user")
		user.Use(middleware.TenantHeaderMiddleware(p.store))
		{
			user.POST("/register", p.handlers.RegisterUser)
			user.POST("/login", p.handlers.LoginUser)

			// WebAuthn routes
			user.POST("/register-webauthn-begin", p.handlers.StartWebAuthnRegistration)
			user.POST("/register-webauthn-finish", p.handlers.FinishWebAuthnRegistration)
			user.POST("/login-webauthn-begin", p.handlers.StartWebAuthnLogin)
			user.POST("/login-webauthn-finish", p.handlers.FinishWebAuthnLogin)
		}

		// Auth check helper
		public.GET("/helper/auth-check", p.handlers.AuthCheck)
		public.POST("/helper/auth-check", p.handlers.AuthCheck)
	}

	// Protected auth routes (session management)
	protected := router.Group("/")
	protected.Use(middleware.AuthMiddleware(p.cfg, p.store, p.logger))
	{
		// User session routes (authenticated)
		session := protected.Group("/user/session")
		{
			session.GET("/account-info", p.handlers.GetAccountInfo)
			session.POST("/settings", p.handlers.UpdateSettings)
			session.GET("/private-data", p.handlers.GetPrivateData)
			session.POST("/private-data", p.handlers.UpdatePrivateData)
			session.DELETE("/", p.handlers.DeleteUser)

			// WebAuthn credential management
			session.POST("/webauthn/register-begin", p.handlers.StartAddWebAuthnCredential)
			session.POST("/webauthn/register-finish", p.handlers.FinishAddWebAuthnCredential)
			session.POST("/webauthn/credential/:id/rename", p.handlers.RenameWebAuthnCredential)
			session.POST("/webauthn/credential/:id/delete", p.handlers.DeleteWebAuthnCredential)
		}
		protected.DELETE("/user/session", p.handlers.DeleteUser)

		// Issuer routes
		issuerGroup := protected.Group("/issuer")
		{
			issuerGroup.GET("/all", p.handlers.GetAllIssuers)
		}

		// Verifier routes
		verifierGroup := protected.Group("/verifier")
		{
			verifierGroup.GET("/all", p.handlers.GetAllVerifiers)
		}

		// Helper routes
		protected.POST("/helper/get-cert", p.handlers.GetCertificate)

		// Proxy routes (can be disabled via features.proxy_enabled)
		if p.cfg.Features.ProxyEnabled {
			protected.POST("/proxy", p.handlers.ProxyRequest)
		}

		// Keystore routes
		keystoreGroup := protected.Group("/keystore")
		{
			keystoreGroup.GET("/status", p.handlers.KeystoreStatus)
		}

		// Wallet provider routes
		walletProvider := protected.Group("/wallet-provider")
		{
			walletProvider.POST("/key-attestation/generate", p.handlers.GenerateKeyAttestation)
		}
	}
}

// =============================================================================
// Storage Provider - handles encrypted data storage routes only
// =============================================================================

// StorageProvider provides encrypted storage routes
type StorageProvider struct {
	cfg      *config.Config
	logger   *zap.Logger
	store    backend.Backend
	handlers *api.Handlers
}

// NewStorageProvider creates a new storage route provider
func NewStorageProvider(cfg *config.Config, store backend.Backend, logger *zap.Logger, roles []string) *StorageProvider {
	services := service.NewServices(store, cfg, logger)
	handlers := api.NewHandlers(services, cfg, logger, roles)
	return &StorageProvider{
		cfg:      cfg,
		logger:   logger,
		store:    store,
		handlers: handlers,
	}
}

func (p *StorageProvider) Transport() Transport { return TransportHTTP }
func (p *StorageProvider) Name() string         { return "storage" }

func (p *StorageProvider) RegisterRoutes(router *gin.Engine) {
	// Protected storage routes
	protected := router.Group("/storage")
	protected.Use(middleware.AuthMiddleware(p.cfg, p.store, p.logger))
	{
		// Credential storage
		protected.GET("/vc", p.handlers.GetAllCredentials)
		protected.POST("/vc", p.handlers.StoreCredential)
		protected.POST("/vc/update", p.handlers.UpdateCredential)
		protected.GET("/vc/:credential_identifier", p.handlers.GetCredentialByIdentifier)
		protected.DELETE("/vc/:credential_identifier", p.handlers.DeleteCredential)

		// Presentation storage
		protected.GET("/vp", p.handlers.GetAllPresentations)
		protected.POST("/vp", p.handlers.StorePresentation)
		protected.GET("/vp/:presentation_identifier", p.handlers.GetPresentationByIdentifier)
	}
}

// =============================================================================
// Engine Provider - handles WebSocket flow orchestration
// =============================================================================

// EngineProvider provides WebSocket engine routes
type EngineProvider struct {
	cfg     *config.Config
	logger  *zap.Logger
	manager *wsengine.Manager
}

// NewEngineProvider creates a new WebSocket engine route provider.
// If store is non-nil, the engine will cache verifier trust evaluations.
func NewEngineProvider(cfg *config.Config, logger *zap.Logger, store storage.VerifierStore) (*EngineProvider, error) {
	// Create WebSocket manager
	manager := wsengine.NewManager(cfg, logger)

	// Wire verifier store for trust caching
	if store != nil {
		manager.SetVerifierStore(store)
	}

	// Configure session store based on config
	if cfg.SessionStore.Type == "redis" {
		redisStore, err := wsengine.NewRedisSessionStore(&wsengine.RedisSessionConfig{
			Address:    cfg.SessionStore.Redis.Address,
			Password:   cfg.SessionStore.Redis.Password,
			DB:         cfg.SessionStore.Redis.DB,
			KeyPrefix:  cfg.SessionStore.Redis.KeyPrefix,
			DefaultTTL: time.Duration(cfg.SessionStore.DefaultTTLHours) * time.Hour,
		}, logger)
		if err != nil {
			logger.Warn("Failed to connect to Redis, falling back to memory store", zap.Error(err))
		} else {
			manager.SetSessionStore(redisStore)
			logger.Info("Using Redis session store", zap.String("address", cfg.SessionStore.Redis.Address))
		}
	}

	// Register flow handlers
	manager.RegisterFlowHandler(wsengine.ProtocolOID4VCI, wsengine.NewOID4VCIHandler)
	manager.RegisterFlowHandler(wsengine.ProtocolOID4VP, wsengine.NewOID4VPHandler)
	manager.RegisterFlowHandler(wsengine.ProtocolVCTM, wsengine.NewVCTMHandler)

	return &EngineProvider{
		cfg:     cfg,
		logger:  logger,
		manager: manager,
	}, nil
}

func (p *EngineProvider) Transport() Transport { return TransportWebSocket }
func (p *EngineProvider) Name() string         { return "engine" }

func (p *EngineProvider) RegisterRoutes(router *gin.Engine) {
	// WebSocket v2 endpoint
	router.GET("/api/v2/wallet", func(c *gin.Context) {
		p.manager.HandleConnection(c.Writer, c.Request)
	})
}

// Close shuts down the engine manager
func (p *EngineProvider) Close() {
	if p.manager != nil {
		p.manager.Close()
	}
}

// CheckReady implements health.ReadinessChecker for EngineProvider.
// It verifies the WebSocket engine manager is operational.
func (p *EngineProvider) CheckReady(ctx context.Context) error {
	if p.manager == nil {
		return fmt.Errorf("engine manager not initialized")
	}
	// Check if manager is healthy (not shutting down, accepting connections)
	if !p.manager.IsHealthy() {
		return fmt.Errorf("engine manager not healthy")
	}
	return nil
}

// =============================================================================
// Combined Backend Provider - combines auth + storage (backward compatible)
// =============================================================================

// BackendProvider provides the full backend API (auth + storage combined)
type BackendProvider struct {
	auth    *AuthProvider
	storage *StorageProvider
	store   backend.Backend
	logger  *zap.Logger
}

// NewBackendProvider creates a combined auth+storage provider
func NewBackendProvider(cfg *config.Config, logger *zap.Logger, roles []string) (*BackendProvider, error) {
	// Initialize storage backend
	initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	store, err := backend.New(initCtx, cfg)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage backend: %w", err)
	}

	// Ping storage to verify connection
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Ping(pingCtx); err != nil {
		return nil, fmt.Errorf("failed to ping storage: %w", err)
	}

	logger.Info("Storage backend initialized", zap.String("type", cfg.Storage.Type))

	return &BackendProvider{
		auth:    NewAuthProvider(cfg, store, logger, roles),
		storage: NewStorageProvider(cfg, store, logger, roles),
		store:   store,
		logger:  logger,
	}, nil
}

func (p *BackendProvider) Transport() Transport { return TransportHTTP }
func (p *BackendProvider) Name() string         { return "backend" }

func (p *BackendProvider) RegisterRoutes(router *gin.Engine) {
	// Register both auth and storage routes
	p.auth.RegisterRoutes(router)
	p.storage.RegisterRoutes(router)
}

// Close shuts down the backend provider
func (p *BackendProvider) Close() error {
	if p.store != nil {
		return p.store.Close()
	}
	return nil
}

// CheckReady implements health.ReadinessChecker for BackendProvider.
// It verifies the database connection is healthy.
func (p *BackendProvider) CheckReady(ctx context.Context) error {
	if p.store == nil {
		return fmt.Errorf("storage not initialized")
	}
	// Use a short timeout for readiness checks
	checkCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	return p.store.Ping(checkCtx)
}

// Store returns the underlying storage backend
func (p *BackendProvider) Store() backend.Backend {
	return p.store
}

// RegisterAdminRoutes implements AdminRouteProvider for BackendProvider.
func (p *BackendProvider) RegisterAdminRoutes(adminGroup *gin.RouterGroup) {
	adminHandlers := api.NewAdminHandlers(p.store, p.logger)
	adminHandlers.RegisterRoutes(adminGroup)
}

// =============================================================================
// Admin Provider - standalone admin API (for --mode=admin deployments)
// =============================================================================

// AdminProvider provides only admin routes, without public auth/storage routes.
// Use this when running admin as a standalone mode separate from the backend.
type AdminProvider struct {
	store  backend.Backend
	logger *zap.Logger
}

// NewAdminProvider creates a standalone admin route provider
func NewAdminProvider(cfg *config.Config, logger *zap.Logger) (*AdminProvider, error) {
	initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	store, err := backend.New(initCtx, cfg)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage backend for admin: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.Ping(pingCtx); err != nil {
		return nil, fmt.Errorf("failed to ping storage: %w", err)
	}

	logger.Info("Admin storage backend initialized", zap.String("type", cfg.Storage.Type))

	return &AdminProvider{
		store:  store,
		logger: logger,
	}, nil
}

func (p *AdminProvider) Transport() Transport { return TransportHTTP }
func (p *AdminProvider) Name() string         { return "admin" }

// RegisterRoutes is a no-op — admin has no public routes
func (p *AdminProvider) RegisterRoutes(router *gin.Engine) {}

// Close shuts down the admin provider's storage
func (p *AdminProvider) Close() error {
	if p.store != nil {
		return p.store.Close()
	}
	return nil
}

// CheckReady implements health.ReadinessChecker for AdminProvider.
func (p *AdminProvider) CheckReady(ctx context.Context) error {
	if p.store == nil {
		return fmt.Errorf("storage not initialized")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	return p.store.Ping(checkCtx)
}

// RegisterAdminRoutes implements AdminRouteProvider for AdminProvider.
func (p *AdminProvider) RegisterAdminRoutes(adminGroup *gin.RouterGroup) {
	adminHandlers := api.NewAdminHandlers(p.store, p.logger)
	adminHandlers.RegisterRoutes(adminGroup)
}

// =============================================================================
// Registry Provider - handles VCTM registry routes
// =============================================================================

// RegistryProvider provides VCTM registry routes
type RegistryProvider struct {
	cfg     *registry.Config
	logger  *zap.Logger
	store   *registry.Store
	fetcher *registry.Fetcher
	handler *registry.Handler
	cancel  context.CancelFunc
}

// NewRegistryProvider creates a new registry route provider
func NewRegistryProvider(cfg *registry.Config, logger *zap.Logger) (*RegistryProvider, error) {
	// Create store and load cache
	store := registry.NewStore(cfg.Cache.Path)
	if err := store.Load(); err != nil {
		logger.Warn("Failed to load registry cache, starting fresh", zap.Error(err))
	} else {
		logger.Info("Loaded registry cache",
			zap.Int("entries", store.Count()),
			zap.Time("last_updated", store.LastUpdated()))
	}

	// Create handler
	handler := registry.NewHandler(store, &cfg.DynamicCache, &cfg.ImageEmbed, logger, nil)

	return &RegistryProvider{
		cfg:     cfg,
		logger:  logger,
		store:   store,
		handler: handler,
	}, nil
}

func (p *RegistryProvider) Transport() Transport { return TransportHTTP }
func (p *RegistryProvider) Name() string         { return "registry" }

func (p *RegistryProvider) RegisterRoutes(router *gin.Engine) {
	// Registry routes with its own middleware group
	group := router.Group("/registry")

	// Add registry-specific JWT middleware
	if p.cfg.JWT.RequireAuth {
		group.Use(registry.JWTMiddleware(p.cfg.JWT, p.logger))
	} else {
		group.Use(registry.OptionalJWTMiddleware(p.cfg.JWT, p.logger))
	}

	// Add rate limiting
	rateLimiter := registry.NewRateLimiter(p.cfg.RateLimit)
	group.Use(registry.RateLimitMiddleware(rateLimiter))

	// Register handler routes under /registry prefix
	p.handler.RegisterRoutes(group)
}

// Start starts the registry background fetcher
func (p *RegistryProvider) Start(ctx context.Context) error {
	fetchCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	p.fetcher = registry.NewFetcher(p.cfg, p.store, p.logger, nil)
	if err := p.fetcher.Start(fetchCtx); err != nil {
		return fmt.Errorf("failed to start registry fetcher: %w", err)
	}
	return nil
}

// Close shuts down the registry provider
func (p *RegistryProvider) Close() error {
	// Stop fetcher
	if p.cancel != nil {
		p.cancel()
	}
	if p.fetcher != nil {
		p.fetcher.Stop()
	}

	// Stop handler background goroutines (performs final save)
	if p.handler != nil {
		p.handler.Close()
	}

	// Save cache
	if p.store != nil {
		if err := p.store.Save(); err != nil {
			p.logger.Error("Failed to save registry cache", zap.Error(err))
		}
	}

	return nil
}

// CheckReady implements health.ReadinessChecker for RegistryProvider.
// It verifies the registry store is initialized and operational.
func (p *RegistryProvider) CheckReady(ctx context.Context) error {
	if p.store == nil {
		return fmt.Errorf("registry store not initialized")
	}
	// Store is file-based cache, check it's loaded
	if p.store.Count() == 0 && !p.cfg.DynamicCache.Enabled {
		// If dynamic cache is disabled and store is empty, that may be intentional
		// Allow this state - the store is still functional
		return nil
	}
	return nil
}
