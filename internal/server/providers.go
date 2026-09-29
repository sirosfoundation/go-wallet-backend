// Package server contains RouteProvider implementations for different modes.
// Each provider contributes routes to a shared HTTP server managed by server.Manager.
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	tokenvalidator "github.com/sirosfoundation/go-tokenauth/validator"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/as"
	"github.com/sirosfoundation/go-wallet-backend/internal/backend"
	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/registry"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/audit"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// =============================================================================
// Auth Provider - handles authentication routes only
// =============================================================================

// AuthProvider provides authentication routes (WebAuthn, login, register)
type AuthProvider struct {
	cfg            *config.Config
	logger         *zap.Logger
	store          backend.Backend
	services       *service.Services
	handlers       *api.Handlers
	roles          []string
	tokenValidator *tokenvalidator.Validator
	wiaRateLimiter *middleware.AuthRateLimiter
}

// NewAuthProvider creates a new auth route provider
func NewAuthProvider(cfg *config.Config, store backend.Backend, logger *zap.Logger, roles []string) *AuthProvider {
	services := service.NewServices(store, cfg, logger)
	services.Start()
	handlers := api.NewHandlers(services, cfg, logger, roles)
	return &AuthProvider{
		cfg:            cfg,
		logger:         logger,
		store:          store,
		services:       services,
		handlers:       handlers,
		roles:          roles,
		wiaRateLimiter: middleware.NewAuthRateLimiter(cfg.WalletProvider.WIA.RateLimit, logger.Named("wia")),
	}
}

func (p *AuthProvider) Transport() Transport { return TransportHTTP }
func (p *AuthProvider) Name() string         { return "auth" }

// Services returns the auth provider's service aggregate.
func (p *AuthProvider) Services() *service.Services { return p.services }

// Close stops background workers in the auth provider.
func (p *AuthProvider) Close() error {
	p.services.Stop()
	return nil
}

func (p *AuthProvider) RegisterRoutes(router *gin.Engine) {
	// Create HTTP client and OIDC validator cache for gate middleware
	httpClient := p.cfg.HTTPClient.NewHTTPClient(0)
	validatorCache := middleware.NewValidatorCache(httpClient, p.logger)

	// Public auth routes (no authentication required)
	public := router.Group("/")
	{
		// Base user group with tenant middleware
		userBase := public.Group("/user")
		userBase.Use(middleware.TenantHeaderMiddleware(p.store))

		// Registration routes (with OIDC registration gate)
		registration := userBase.Group("")
		registration.Use(
			middleware.NoCacheMiddleware(),
			middleware.OIDCGateMiddleware(validatorCache, middleware.GateTypeRegistration, p.logger),
		)
		{
			registration.POST("/register-webauthn-begin", p.handlers.StartWebAuthnRegistration)
			registration.POST("/register-webauthn-finish", p.handlers.FinishWebAuthnRegistration)
		}

		// Login routes (with OIDC login gate)
		login := userBase.Group("")
		login.Use(
			middleware.NoCacheMiddleware(),
			middleware.OIDCGateMiddleware(validatorCache, middleware.GateTypeLogin, p.logger),
		)
		{
			login.POST("/login-webauthn-begin", p.handlers.StartWebAuthnLogin)
			login.POST("/login-webauthn-finish", p.handlers.FinishWebAuthnLogin)
		}

		// Refresh route: exchanges a still-valid refresh token for a new
		// access token (and a rotated refresh token). Deliberately NOT behind
		// authMiddleware()/TokenAuthMiddleware - the entire point of a
		// refresh token is to obtain a new access token once the old one has
		// expired, so requiring a currently-valid access token here would be
		// self-defeating. No OIDC gate either: possessing the long-lived
		// refresh token (itself a signed, type-checked JWT - see
		// WebAuthnService.RefreshAccessToken) is the credential. This handler
		// existed since refresh tokens were added but, like Logout before
		// #391, was never actually mounted on any route (#392).
		refresh := userBase.Group("/session")
		refresh.Use(middleware.NoCacheMiddleware())
		{
			refresh.POST("/refresh", p.handlers.RefreshToken)
		}

		// Public tenant configuration (for OIDC gate discovery)
		// Two routes for compatibility: legacy /tenant/:id/config and new /api/v1/tenants/:id/config
		tenant := public.Group("/tenant")
		{
			tenant.GET("/:id/config", p.handlers.GetTenantConfig)
		}
		apiV1 := public.Group("/api/v1")
		{
			apiV1.GET("/tenants/:id/config", p.handlers.GetTenantConfig)
		}

		// Auth check helper
		public.GET("/helper/auth-check", p.handlers.AuthCheck)
		public.POST("/helper/auth-check", p.handlers.AuthCheck)
	}

	// Protected auth routes (session management)
	protected := router.Group("/")
	protected.Use(
		middleware.NoCacheMiddleware(),
		p.authMiddleware(),
	)
	// These are general user-facing routes, not the narrow-purpose calls
	// (trust evaluation, engine transport) an identity-free anonymous token
	// is scoped to - reject a wallet-registry-only token here. Only
	// enforced under go-tokenauth; legacy AuthMiddleware never populates
	// tokenauth_result (see RequireAudience's doc comment).
	if p.tokenValidator != nil {
		protected.Use(middleware.RequireAudience("wallet-backend"))
	}
	{
		// User session routes (authenticated)
		session := protected.Group("/user/session")
		{
			session.GET("/account-info", requireTACIfEnforced(p.tokenValidator, "r"), p.handlers.GetAccountInfo)
			session.POST("/settings", requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.UpdateSettings)
			session.GET("/private-data", requireTACIfEnforced(p.tokenValidator, "r"), p.handlers.GetPrivateData)
			session.POST("/private-data", requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.UpdatePrivateData)
			session.DELETE("/", requireTACIfEnforced(p.tokenValidator, "d"), p.handlers.DeleteUser)
			// Logout: blacklists the caller's own current token (see
			// api.Handlers.Logout / #382). This handler existed since the
			// blacklist itself was added but was never actually registered
			// on any route - the write side of the blacklist was as
			// unreachable as the read side (AuthMiddleware's hardcoded nil)
			// that #382 is about. No TAC restriction ("" - trivially
			// satisfied): revoking your own already-presented token isn't a
			// read/write/list/insert/delete on any object, just proof you
			// hold a valid token at all.
			session.POST("/logout", requireTACIfEnforced(p.tokenValidator, ""), p.handlers.Logout)

			// WebAuthn credential management
			session.POST("/webauthn/register-begin", requireTACIfEnforced(p.tokenValidator, "i"), p.handlers.StartAddWebAuthnCredential)
			session.POST("/webauthn/register-finish", requireTACIfEnforced(p.tokenValidator, "i"), p.handlers.FinishAddWebAuthnCredential)
			session.POST("/webauthn/credential/:id/rename", requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.RenameWebAuthnCredential)
			session.POST("/webauthn/credential/:id/delete", requireTACIfEnforced(p.tokenValidator, "d"), p.handlers.DeleteWebAuthnCredential)
		}
		protected.DELETE("/user/session", requireTACIfEnforced(p.tokenValidator, "d"), p.handlers.DeleteUser)

		// Issuer routes
		issuerGroup := protected.Group("/issuer")
		{
			issuerGroup.GET("/all", requireTACIfEnforced(p.tokenValidator, "l"), p.handlers.GetAllIssuers)
			issuerGroup.GET("/:id/metadata", requireTACIfEnforced(p.tokenValidator, "r"), p.handlers.GetIssuerMetadata)
		}

		// Verifier routes
		verifierGroup := protected.Group("/verifier")
		{
			verifierGroup.GET("/all", requireTACIfEnforced(p.tokenValidator, "l"), p.handlers.GetAllVerifiers)
		}

		// Helper routes
		protected.POST("/helper/get-cert", requireTACIfEnforced(p.tokenValidator, "r"), p.handlers.GetCertificate)

		// Proxy routes (can be disabled via features.proxy_enabled)
		if p.cfg.Features.ProxyEnabled {
			protected.POST("/proxy", requireTACIfEnforced(p.tokenValidator, "r"), p.handlers.ProxyRequest)
		}

		// Keystore routes
		keystoreGroup := protected.Group("/keystore")
		{
			keystoreGroup.GET("/status", requireTACIfEnforced(p.tokenValidator, "r"), p.handlers.KeystoreStatus)
		}

		// Wallet provider routes
		walletProvider := protected.Group("/wallet-provider")
		{
			walletProvider.POST("/key-attestation/generate", requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.GenerateKeyAttestation)
			if p.cfg.WalletProvider.WIA.Enabled && p.services.WIA != nil {
				wiaLimit := middleware.AuthRateLimitMiddlewareWithIdentifier(p.wiaRateLimiter, wiaCallerIdentifier)
				walletProvider.POST("/wia/challenge", wiaLimit, requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.WIAChallenge)
				walletProvider.POST("/wia/generate", wiaLimit, requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.WIAGenerate)
			}
			if p.services.FIDO2Attestation != nil && p.services.FIDO2Attestation.IsEnabled() {
				walletProvider.POST("/fido2-attestation/register", requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.FIDO2AttestationRegister)
			}
		}
	}
}

// wiaCallerIdentifier extracts the authenticated caller's identity (set by the
// auth middleware) to key the WIA per-caller rate limiter. Falls back to the
// tenant, then to the shared anonymous bucket, matching AuthRateLimiter's
// existing privacy-preserving default.
func wiaCallerIdentifier(c *gin.Context) string {
	if userID := c.GetString("user_id"); userID != "" {
		return userID
	}
	if tenantID := c.GetString("tenant_id"); tenantID != "" {
		return tenantID
	}
	return ""
}

// authMiddleware returns the appropriate auth middleware: go-tokenauth when
// a validator is available (AS enabled), legacy HMAC AuthMiddleware otherwise.
func (p *AuthProvider) authMiddleware() gin.HandlerFunc {
	if p.tokenValidator != nil {
		return middleware.TokenAuthMiddleware(p.tokenValidator, p.store.Tenants(), p.services.TokenBlacklist, p.logger)
	}
	// AuthMiddlewareWithBlacklist, not the bare AuthMiddleware wrapper: the
	// latter hardcodes a nil blacklist, which is exactly what left Logout's
	// blacklist writes (see api.Handlers.Logout) never actually checked by
	// anything (#382).
	return middleware.AuthMiddlewareWithBlacklist(p.cfg, p.store, p.services.TokenBlacklist, p.logger)
}

// requireTACIfEnforced returns MustHaveTAC(required) when tv is non-nil (the
// go-tokenauth path is active, so tokenauth_result - and therefore a TAC to
// check - is actually populated). When tv is nil, the legacy HMAC
// AuthMiddleware path is in effect instead, which has no TAC concept at all
// (see AuthMiddleware) - MustHaveTAC would 401 every request there since it
// never finds tokenauth_result, so this no-ops instead of enforcing.
// Mirrors RequireAudience's own identical conditional application, for the
// same reason.
func requireTACIfEnforced(tv *tokenvalidator.Validator, required string) gin.HandlerFunc {
	if tv == nil {
		return func(c *gin.Context) { c.Next() }
	}
	return middleware.MustHaveTAC(required)
}

// =============================================================================
// Storage Provider - handles encrypted data storage routes only
// =============================================================================

// StorageProvider provides encrypted storage routes
type StorageProvider struct {
	cfg            *config.Config
	logger         *zap.Logger
	store          backend.Backend
	services       *service.Services
	handlers       *api.Handlers
	tokenValidator *tokenvalidator.Validator
}

// NewStorageProvider creates a new storage route provider
func NewStorageProvider(cfg *config.Config, store backend.Backend, logger *zap.Logger, roles []string) *StorageProvider {
	services := service.NewServices(store, cfg, logger)
	handlers := api.NewHandlers(services, cfg, logger, roles)
	return &StorageProvider{
		cfg:      cfg,
		logger:   logger,
		store:    store,
		services: services,
		handlers: handlers,
	}
}

func (p *StorageProvider) Transport() Transport { return TransportHTTP }
func (p *StorageProvider) Name() string         { return "storage" }

func (p *StorageProvider) RegisterRoutes(router *gin.Engine) {
	// Protected storage routes
	protected := router.Group("/storage")
	protected.Use(
		middleware.NoCacheMiddleware(),
		p.authMiddleware(),
	)
	// Credential storage is a general user-facing route, not one of the
	// narrow purposes (trust evaluation, engine transport) an anonymous
	// token is scoped to - reject a wallet-registry-only token here.
	if p.tokenValidator != nil {
		protected.Use(middleware.RequireAudience("wallet-backend"))
	}
	{
		// Credential storage (gated)
		if p.cfg.Features.CredentialStorageEnabled {
			protected.GET("/vc", requireTACIfEnforced(p.tokenValidator, "l"), p.handlers.GetAllCredentials)
			protected.POST("/vc", requireTACIfEnforced(p.tokenValidator, "i"), p.handlers.StoreCredential)
			protected.POST("/vc/update", requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.UpdateCredential)
			protected.GET("/vc/:credential_identifier", requireTACIfEnforced(p.tokenValidator, "r"), p.handlers.GetCredentialByIdentifier)
			protected.DELETE("/vc/:credential_identifier", requireTACIfEnforced(p.tokenValidator, "d"), p.handlers.DeleteCredential)
		}
	}
}

// authMiddleware returns the appropriate auth middleware for storage routes.
func (p *StorageProvider) authMiddleware() gin.HandlerFunc {
	if p.tokenValidator != nil {
		return middleware.TokenAuthMiddleware(p.tokenValidator, p.store.Tenants(), p.services.TokenBlacklist, p.logger)
	}
	// See AuthProvider.authMiddleware's comment - same fix (#382). When this
	// provider is combined with an AuthProvider under BackendProvider,
	// p.services.TokenBlacklist is overwritten to share that AuthProvider's
	// instance, so a token blacklisted via Logout/DeleteUser is honored here
	// too, not just on /user/session routes.
	return middleware.AuthMiddlewareWithBlacklist(p.cfg, p.store, p.services.TokenBlacklist, p.logger)
}

// =============================================================================
// Engine Provider - handles WebSocket flow orchestration
// =============================================================================

// EngineProvider provides WebSocket engine routes
type EngineProvider struct {
	cfg    *config.Config
	logger *zap.Logger
	// metadataResolver is the resolver the flow handlers were registered with,
	// kept the way BackendProvider keeps its own: once it is handed to a
	// handler factory it is otherwise unreachable, and the policy it was built
	// with - AllowsPlaintext - is then only assertable by rebuilding it, which
	// is a restatement of the rule rather than a check of it.
	metadataResolver *issuermetadata.Resolver
	manager          *wsengine.Manager
}

// NewEngineProvider creates a new WebSocket engine route provider.
// If store is non-nil, the engine will cache verifier trust evaluations.
// If sharedResolver is non-nil, it is used for issuer metadata resolution so
// the TTL cache is shared with the HTTP /v1/resolve handler; otherwise a new
// resolver is created from the config.
// If issuerLookup is non-nil, the OID4VCI handler will enrich fetchMetadata results
// with the registered-issuer record from backend storage (same data as /v1/resolve).
func NewEngineProvider(cfg *config.Config, logger *zap.Logger, store storage.VerifierStore, sharedResolver *issuermetadata.Resolver, issuerLookup wsengine.CredentialIssuerLookup) (*EngineProvider, error) {
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

	// Use the shared resolver when available so the TTL cache is not duplicated.
	// Fall back to creating a local resolver (e.g. when the engine runs without
	// the backend provider, or when resolution is disabled on the backend).
	metadataResolver := sharedResolver
	if metadataResolver == nil {
		r, err := issuermetadata.New(issuermetadata.Config{
			HTTPClient: cfg.HTTPClient.NewHTTPClient(time.Duration(cfg.HTTPClient.Timeout) * time.Second),
			AllowHTTP:  cfg.HTTPClient.AllowsPlaintext(),
		})
		if err != nil {
			return nil, fmt.Errorf("creating issuer metadata resolver: %w", err)
		}
		metadataResolver = r
	}

	// Register flow handlers
	manager.RegisterFlowHandler(wsengine.ProtocolOID4VCI, wsengine.NewOID4VCIHandlerFactory(metadataResolver, issuerLookup))
	manager.RegisterFlowHandler(wsengine.ProtocolOID4VP, wsengine.NewOID4VPHandler)
	manager.RegisterFlowHandler(wsengine.ProtocolVCTM, wsengine.NewVCTMHandler)

	return &EngineProvider{
		cfg:              cfg,
		logger:           logger,
		metadataResolver: metadataResolver,
		manager:          manager,
	}, nil
}

func (p *EngineProvider) Transport() Transport { return TransportWebSocket }
func (p *EngineProvider) Name() string         { return "engine" }

// SessionStore returns the engine's session store for cross-provider wiring.
func (p *EngineProvider) SessionStore() wsengine.SessionStore {
	return p.manager.SessionStore()
}

// SetTokenValidator passes the go-tokenauth validator to the WebSocket engine
// so it can validate both new-style and legacy tokens during the handshake.
func (p *EngineProvider) SetTokenValidator(v *tokenvalidator.Validator) {
	p.manager.SetTokenValidator(v)
}

// SetTokenBlacklist passes a token blacklist to the WebSocket engine so its
// handshake honors revocation (both per-jti and per-user) the same way the
// HTTP auth middlewares do - see wsengine.TokenBlacklistChecker's doc
// comment for exactly what this covers versus what a shared
// *tokenvalidator.Validator (see SetTokenValidator) already checks on its
// own (#391 review, round 2: the engine's own token validation was found to
// bypass revocation entirely on the legacy path, and user-level revocation
// even on the go-tokenauth path).
func (p *EngineProvider) SetTokenBlacklist(b wsengine.TokenBlacklistChecker) {
	p.manager.SetTokenBlacklist(b)
}

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

// blacklistRevocationChecker adapts *service.TokenBlacklist to
// go-tokenauth's revocation.Checker interface (IsRevoked vs. the service
// package's own IsBlacklisted method name), so a token revoked via
// Logout/DeleteUser (#382/#383) is honored for AS-issued (and legacy)
// tokens validated through go-tokenauth's Validator - the path taken
// whenever AS is enabled - not only for tokens validated through the
// standalone legacy path (middleware.AuthMiddlewareWithBlacklist).
type blacklistRevocationChecker struct {
	blacklist *service.TokenBlacklist
}

// IsRevoked implements revocation.Checker.
func (c blacklistRevocationChecker) IsRevoked(ctx context.Context, jti string) bool {
	return c.blacklist.IsBlacklisted(ctx, jti)
}

// =============================================================================
// Combined Backend Provider - combines auth + storage (backward compatible)
// =============================================================================

// BackendProvider provides the full backend API (auth + storage combined)
type BackendProvider struct {
	auth             *AuthProvider
	storage          *StorageProvider
	store            backend.Backend
	cfg              *config.Config
	authzenHandler   *api.AuthZENProxyHandler
	metadataResolver *issuermetadata.Resolver
	asModule         *as.ASModule
	tokenValidator   *tokenvalidator.Validator
	auditor          *audit.Emitter
	logger           *zap.Logger
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

	// Initialize AuthZEN proxy handler (for frontend trust evaluation)
	httpClient := cfg.HTTPClient.NewHTTPClient(0)

	// Create issuer metadata resolver for local URL subject resolution.
	// Only instantiated when AuthZEN proxy is enabled and resolution is allowed,
	// so that a startup failure here does not affect deployments that don't use it.
	var metadataResolver *issuermetadata.Resolver
	if cfg.AuthZENProxy.Enabled && cfg.AuthZENProxy.AllowResolution {
		r, err := issuermetadata.New(issuermetadata.Config{
			HTTPClient: cfg.HTTPClient.NewHTTPClient(time.Duration(cfg.HTTPClient.Timeout) * time.Second),
			AllowHTTP:  cfg.HTTPClient.AllowsPlaintext(),
		})
		if err != nil {
			if closeErr := store.Close(); closeErr != nil {
				logger.Error("Failed to close store after metadata resolver creation failure", zap.Error(closeErr))
			}
			return nil, fmt.Errorf("failed to create issuer metadata resolver: %w", err)
		}
		metadataResolver = r
	}

	authzenHandler, err := api.NewAuthZENProxyHandlerFromConfig(cfg, store.Tenants(), store.Issuers(), metadataResolver, httpClient, logger)
	if err != nil {
		if closeErr := store.Close(); closeErr != nil {
			logger.Error("Failed to close store after AuthZEN proxy initialization failure", zap.Error(closeErr))
		}
		return nil, fmt.Errorf("failed to initialize AuthZEN proxy: %w", err)
	}

	// Auth provider is constructed before the AS module and storage provider
	// below so its Services.TokenBlacklist (created, and Start()-ed, right
	// here) can be handed to both of them instead of each building its own,
	// unshared instance - see #382/#383: a token blacklisted via Logout or
	// DeleteUser (both served by authProvider.handlers) must be honored by
	// every request path in this process, not only the one that happened to
	// construct the blacklist it was written to.
	authProvider := NewAuthProvider(cfg, store, logger, roles)

	// Initialize AS module when enabled.
	var asModule *as.ASModule
	var tv *tokenvalidator.Validator
	if cfg.AS.Enabled {
		services := service.NewServices(store, cfg, logger)
		services.TokenBlacklist = authProvider.services.TokenBlacklist
		asModule, err = as.NewASModule(
			context.Background(),
			&cfg.AS,
			&cfg.JWT,
			services.WebAuthn,
			store,
			services.TokenBlacklist,
			cfg.HTTPClient.NewHTTPClient(0),
			logger,
		)
		if err != nil {
			if closeErr := authProvider.Close(); closeErr != nil {
				logger.Error("Failed to close auth provider after AS module initialization failure", zap.Error(closeErr))
			}
			if closeErr := store.Close(); closeErr != nil {
				logger.Error("Failed to close store after AS module initialization failure", zap.Error(closeErr))
			}
			return nil, fmt.Errorf("failed to initialize AS module: %w", err)
		}

		// Create go-tokenauth validator for protecting resource endpoints.
		issuer := cfg.AS.Issuer
		if issuer == "" {
			issuer = cfg.JWT.Issuer
		}
		jwksURL := cfg.AS.ExternalURL + "/auth/.well-known/jwks.json"
		tv = tokenvalidator.New(tokenvalidator.Config{
			JWKSURL:   jwksURL,
			Issuer:    issuer,
			Audiences: cfg.AS.Audiences,
			Legacy: tokenvalidator.LegacyConfig{
				Enabled:    cfg.AS.Legacy.Enabled,
				HMACSecret: []byte(cfg.JWT.Secret),
			},
			// Same blacklist as everything else in this process (#382/#383) -
			// without this, AS-issued/legacy tokens validated through
			// go-tokenauth (the path taken whenever AS is enabled, i.e. the
			// common case) would never consult the blacklist at all, since
			// go-tokenauth's Validator has its own independent validation
			// path that AuthMiddlewareWithBlacklist's check is never reached
			// by.
			Revocation: blacklistRevocationChecker{blacklist: authProvider.services.TokenBlacklist},
		})
		tv.Start(context.Background())
		logger.Info("Authorization Server module initialized",
			zap.String("jwks_url", jwksURL),
			zap.Strings("audiences", cfg.AS.Audiences),
		)
	}

	authProvider.tokenValidator = tv
	storageProvider := NewStorageProvider(cfg, store, logger, roles)
	storageProvider.tokenValidator = tv
	// Share the auth provider's blacklist instance (see the comment above
	// authProvider's construction) rather than storageProvider's own,
	// never-Start()-ed one.
	storageProvider.services.TokenBlacklist = authProvider.services.TokenBlacklist

	return &BackendProvider{
		auth:             authProvider,
		storage:          storageProvider,
		store:            store,
		cfg:              cfg,
		authzenHandler:   authzenHandler,
		metadataResolver: metadataResolver,
		asModule:         asModule,
		tokenValidator:   tv,
		auditor:          newAuditEmitter(cfg, logger),
		logger:           logger,
	}, nil
}

func (p *BackendProvider) Transport() Transport { return TransportHTTP }
func (p *BackendProvider) Name() string         { return "backend" }

// Services returns the backend's service aggregate (via the auth provider).
func (p *BackendProvider) Services() *service.Services { return p.auth.Services() }

func (p *BackendProvider) RegisterRoutes(router *gin.Engine) {
	// Register both auth and storage routes
	p.auth.RegisterRoutes(router)
	p.storage.RegisterRoutes(router)

	// Register AS routes when enabled
	if p.asModule != nil {
		authGroup := router.Group("/auth")
		authGroup.Use(middleware.NoCacheMiddleware())
		p.asModule.RegisterRoutes(authGroup)
	}

	// Register the wallet provider's own JWKS (distinct from the AS's),
	// for relying parties resolving trust via an iss-based WIA. No-ops if
	// WIA/the wallet provider signing key isn't configured.
	service.RegisterWalletProviderJWKSRoute(router, p.Services().WalletProvider)

	// Register the always-VALID Token Status List that every WIA's
	// client_status and every KA's key_storage_status references — see
	// RegisterWalletProviderStatusListRoute's doc comment for why no bit in
	// it is ever set.
	service.RegisterWalletProviderStatusListRoute(router, p.Services().WalletProvider)

	// Register AuthZEN proxy routes if enabled
	if p.authzenHandler != nil {
		protected := router.Group("/")
		protected.Use(p.authMiddleware())
		// Trust-evaluation calls are identity-free by design (see
		// handleAnonymousTokenRequest) and only need a wallet-registry or
		// wallet-backend audience - never require a broader one. Only
		// enforced under go-tokenauth (tokenValidator != nil); the legacy
		// AuthMiddleware path never populates tokenauth_result, so
		// RequireAudience would 401 every legacy token if applied there.
		if p.tokenValidator != nil {
			protected.Use(middleware.RequireAudience("wallet-registry", "wallet-backend"))
		}
		v1 := protected.Group("/v1")
		{
			v1.POST("/evaluate", requireTACIfEnforced(p.tokenValidator, "r"), p.authzenHandler.Evaluate)
			v1.POST("/resolve", requireTACIfEnforced(p.tokenValidator, "r"), p.authzenHandler.Resolve)
		}
	}
}

// authMiddleware returns the appropriate auth middleware for backend routes.
func (p *BackendProvider) authMiddleware() gin.HandlerFunc {
	if p.tokenValidator != nil {
		return middleware.TokenAuthMiddleware(p.tokenValidator, p.store.Tenants(), p.Services().TokenBlacklist, p.logger)
	}
	// See AuthProvider.authMiddleware's comment - same fix (#382).
	return middleware.AuthMiddlewareWithBlacklist(p.cfg, p.store, p.Services().TokenBlacklist, p.logger)
}

// Close shuts down the backend provider
func (p *BackendProvider) Close() error {
	if p.auth != nil {
		_ = p.auth.Close()
	}
	if p.tokenValidator != nil {
		p.tokenValidator.Stop()
	}
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

// MetadataResolver returns the shared issuer metadata resolver, or nil if
// resolution is not enabled. The engine provider can accept this resolver to
// share the TTL cache with the HTTP /v1/resolve handler.
func (p *BackendProvider) MetadataResolver() *issuermetadata.Resolver {
	return p.metadataResolver
}

// ASModule returns the AS module, or nil if AS is not enabled.
func (p *BackendProvider) ASModule() *as.ASModule {
	return p.asModule
}

// TokenValidator returns the go-tokenauth validator, or nil if AS is not enabled.
func (p *BackendProvider) TokenValidator() *tokenvalidator.Validator {
	return p.tokenValidator
}

// ASSessionCleaner returns the AS session store as a service.SessionCleaner,
// or nil if the AS is not enabled, so user deletion can revoke AS cookie
// sessions alongside engine sessions.
func (p *BackendProvider) ASSessionCleaner() service.SessionCleaner {
	if p.asModule == nil || p.asModule.Sessions == nil {
		return nil
	}
	return p.asModule.Sessions
}

// RegisterAdminRoutes implements AdminRouteProvider for BackendProvider.
func (p *BackendProvider) RegisterAdminRoutes(adminGroup *gin.RouterGroup) {
	adminHandlers := api.NewAdminHandlers(p.store, p.logger, p.auditor)
	adminHandlers.SetAllowHTTP(p.cfg.HTTPClient.AllowsPlaintext())
	adminHandlers.RegisterRoutes(adminGroup)

	// Cache management endpoint — useful in test environments where the
	// conformance suite serves different issuer metadata per test module
	// at the same URL.
	adminGroup.DELETE("/cache/metadata", func(c *gin.Context) {
		if p.metadataResolver != nil {
			p.metadataResolver.ClearCache()
			p.logger.Info("Issuer metadata cache cleared via admin API")
		}
		c.Status(http.StatusNoContent)
	})
}

// =============================================================================
// Admin Provider - standalone admin API (for --mode=admin deployments)
// =============================================================================

// AdminProvider provides only admin routes, without public auth/storage routes.
// Use this when running admin as a standalone mode separate from the backend.
type AdminProvider struct {
	store   backend.Backend
	auditor *audit.Emitter
	cfg     *config.Config
	logger  *zap.Logger
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
		store:   store,
		auditor: newAuditEmitter(cfg, logger),
		cfg:     cfg,
		logger:  logger,
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
	adminHandlers := api.NewAdminHandlers(p.store, p.logger, p.auditor)
	adminHandlers.SetAllowHTTP(p.cfg.HTTPClient.AllowsPlaintext())
	adminHandlers.RegisterRoutes(adminGroup)
}

// =============================================================================
// Registry Provider - handles VCTM registry routes
// =============================================================================

// RegistryProvider provides VCTM registry routes
type RegistryProvider struct {
	cfg        *registry.Config
	logger     *zap.Logger
	store      *registry.Store
	fetcher    *registry.Fetcher
	handler    *registry.Handler
	httpClient *http.Client
	cancel     context.CancelFunc
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

	// Load local VCTM overrides (before remote fetching so they take priority).
	// Clear any stale cached local entries first so removed override files
	// don't persist through the cache.
	if len(cfg.Source.LocalOverrides) > 0 {
		store.ClearLocal()
		if err := registry.LoadLocalOverrides(store, cfg.Source.LocalOverrides, logger); err != nil {
			return nil, fmt.Errorf("failed to load local VCTM overrides: %w", err)
		}
	}

	// Create centralized HTTP client using config
	httpClient := cfg.HTTPClient.NewHTTPClient(cfg.Source.Timeout)

	// Create handler with HTTP client option
	handler := registry.NewHandler(store, &cfg.DynamicCache, &cfg.ImageEmbed, logger,
		registry.WithHTTPClient(httpClient))

	return &RegistryProvider{
		cfg:        cfg,
		logger:     logger,
		store:      store,
		handler:    handler,
		httpClient: httpClient,
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

	p.fetcher = registry.NewFetcher(p.cfg, p.store, p.logger, p.httpClient)
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

// =============================================================================
// Wallet Provider (Isolated) - runs wallet-provider on a separate port
// =============================================================================

// WalletProviderProvider serves only the wallet-provider endpoints
// (key attestation + WIA) on a dedicated HTTP server for PKCS#11 operational
// isolation. When deployed separately, this process holds the HSM session
// while the main backend runs without PKCS#11 access.
type WalletProviderProvider struct {
	cfg            *config.Config
	logger         *zap.Logger
	store          backend.Backend
	handlers       *api.Handlers
	services       *service.Services
	wiaRateLimiter *middleware.AuthRateLimiter
	tokenValidator *tokenvalidator.Validator
}

// NewWalletProviderProvider creates a new isolated wallet-provider.
func NewWalletProviderProvider(cfg *config.Config, logger *zap.Logger) (*WalletProviderProvider, error) {
	store, err := backend.New(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("create backend: %w", err)
	}

	services := service.NewServices(store, cfg, logger)
	// HasSigningKey (not IsSupported): a cert-less signing key is a valid
	// standalone deployment when only "ietf"-mode WIA is needed. Key
	// Attestation generation (registered unconditionally below) still
	// individually gates on IsSupported() and fails gracefully per-request
	// if no certificate is configured.
	if services.WalletProvider == nil || !services.WalletProvider.HasSigningKey() {
		return nil, fmt.Errorf("wallet-provider signing keys not configured or not supported")
	}
	services.Start()

	handlers := api.NewHandlers(services, cfg, logger, []string{"wallet-provider"})

	// Build a go-tokenauth validator when AS is enabled, matching the
	// co-hosted AuthProvider path (see authMiddleware()). Without this,
	// isolated wallet-provider deployments would reject valid AS-issued
	// access tokens — only legacy HMAC JWTs would work.
	var tv *tokenvalidator.Validator
	if cfg.AS.Enabled {
		issuer := cfg.AS.Issuer
		if issuer == "" {
			issuer = cfg.JWT.Issuer
		}
		jwksURL := cfg.AS.ExternalURL + "/auth/.well-known/jwks.json"
		tv = tokenvalidator.New(tokenvalidator.Config{
			JWKSURL:   jwksURL,
			Issuer:    issuer,
			Audiences: cfg.AS.Audiences,
			Legacy: tokenvalidator.LegacyConfig{
				Enabled:    cfg.AS.Legacy.Enabled,
				HMACSecret: []byte(cfg.JWT.Secret),
			},
			// See NewBackendProvider's identical wiring (#382/#383). This
			// provider's own services.TokenBlacklist is fine used as-is here:
			// it never runs co-hosted with BackendProvider (see cmd/server).
			Revocation: blacklistRevocationChecker{blacklist: services.TokenBlacklist},
		})
		tv.Start(context.Background())
	}

	return &WalletProviderProvider{
		cfg:            cfg,
		logger:         logger,
		store:          store,
		handlers:       handlers,
		services:       services,
		wiaRateLimiter: middleware.NewAuthRateLimiter(cfg.WalletProvider.WIA.RateLimit, logger.Named("wia")),
		tokenValidator: tv,
	}, nil
}

func (p *WalletProviderProvider) Transport() Transport { return TransportWalletProvider }
func (p *WalletProviderProvider) Name() string         { return "wallet-provider" }

// authMiddleware returns the appropriate auth middleware: go-tokenauth when a
// validator is available (AS enabled), legacy HMAC AuthMiddleware otherwise —
// mirrors AuthProvider.authMiddleware().
func (p *WalletProviderProvider) authMiddleware() gin.HandlerFunc {
	if p.tokenValidator != nil {
		return middleware.TokenAuthMiddleware(p.tokenValidator, p.store.Tenants(), p.services.TokenBlacklist, p.logger)
	}
	// See AuthProvider.authMiddleware's comment - same fix (#382). This
	// provider never runs co-hosted with BackendProvider (see cmd/server -
	// it's only ever constructed standalone), so its own Services.
	// TokenBlacklist is fine used as-is.
	return middleware.AuthMiddlewareWithBlacklist(p.cfg, p.store, p.services.TokenBlacklist, p.logger)
}

func (p *WalletProviderProvider) RegisterRoutes(router *gin.Engine) {
	// Wallet-provider routes with auth middleware
	wp := router.Group("/wallet-provider")
	wp.Use(p.authMiddleware())
	// Key attestation / WIA are general user-facing routes, not one of the
	// narrow purposes an anonymous token is scoped to - reject a
	// wallet-registry-only token here.
	if p.tokenValidator != nil {
		wp.Use(middleware.RequireAudience("wallet-backend"))
	}
	{
		wp.POST("/key-attestation/generate", requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.GenerateKeyAttestation)
		if p.cfg.WalletProvider.WIA.Enabled && p.services.WIA != nil {
			wiaLimit := middleware.AuthRateLimitMiddlewareWithIdentifier(p.wiaRateLimiter, wiaCallerIdentifier)
			wp.POST("/wia/challenge", wiaLimit, requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.WIAChallenge)
			wp.POST("/wia/generate", wiaLimit, requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.WIAGenerate)
		}
		if p.services.FIDO2Attestation != nil && p.services.FIDO2Attestation.IsEnabled() {
			wp.POST("/fido2-attestation/register", requireTACIfEnforced(p.tokenValidator, "w"), p.handlers.FIDO2AttestationRegister)
		}
	}

	// Register the wallet provider's own JWKS, same as BackendProvider does
	// (see BackendProvider.RegisterRoutes) - deployments that run
	// wallet-provider as its own standalone role (RoleWalletProvider without
	// RoleBackend) still need this for relying parties resolving trust via
	// an iss-based WIA. No-ops if WIA/the wallet provider signing key isn't
	// configured.
	service.RegisterWalletProviderJWKSRoute(router, p.Services().WalletProvider)
}

// Services returns the service aggregate.
func (p *WalletProviderProvider) Services() *service.Services { return p.services }

// Close releases resources.
func (p *WalletProviderProvider) Close() error {
	if p.tokenValidator != nil {
		p.tokenValidator.Stop()
	}
	p.services.Stop()
	return p.store.Close()
}

// newAuditEmitter creates a SET audit emitter from config.
// Returns nil if audit is not enabled (audit is then a no-op).
func newAuditEmitter(cfg *config.Config, logger *zap.Logger) *audit.Emitter {
	return audit.NewFromConfig(cfg, logger)
}
