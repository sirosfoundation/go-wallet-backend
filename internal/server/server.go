// Package server provides unified HTTP server management for multiple modes.
// It separates the concept of "routes" from "servers" - modes provide routes,
// the server manager combines them into HTTP servers.
//
// Architecture:
//   - RouteProvider: modes implement this to contribute routes
//   - ServerManager: combines RouteProviders into HTTP servers
//   - A single HTTP server can serve multiple modes (auth, storage, backend, registry)
//   - WebSocket engine can optionally use its own port (for long-lived connections)
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	"github.com/sirosfoundation/go-wallet-backend/internal/health"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/middleware"
)

// Transport represents a communication transport type
type Transport string

const (
	// TransportHTTP is regular HTTP request/response
	TransportHTTP Transport = "http"
	// TransportWebSocket is for persistent WebSocket connections
	TransportWebSocket Transport = "websocket"
)

// RouteProvider allows modes to register their routes on a shared router.
// This separates route definition from server lifecycle management.
type RouteProvider interface {
	// Transport returns which transport this provider uses.
	// Providers with the same transport can share an HTTP server.
	Transport() Transport

	// RegisterRoutes adds this mode's routes to the router.
	// The router may be shared with other providers.
	RegisterRoutes(router *gin.Engine)

	// Name returns the mode/role name for logging
	Name() string
}

// StartableProvider allows providers to perform background initialization
// (e.g. starting pollers or fetchers) after routes have been registered.
type StartableProvider interface {
	Start(ctx context.Context) error
}

// AdminRouteProvider allows providers to contribute admin API routes.
// The admin server runs on a separate port with token authentication.
type AdminRouteProvider interface {
	// RegisterAdminRoutes adds admin routes to the protected admin group.
	// The group already has admin auth middleware applied.
	RegisterAdminRoutes(adminGroup *gin.RouterGroup)
}

// ReadinessCheckProvider allows providers to contribute readiness checks.
// Providers that implement this interface will have their CheckReady method
// called when the /readyz endpoint is accessed.
type ReadinessCheckProvider interface {
	// CheckReady returns nil if the provider is ready to serve requests,
	// or an error describing why it is not ready.
	CheckReady(ctx context.Context) error
}

// ServerConfig holds unified server configuration
type ServerConfig struct {
	// HTTP server settings (for auth, storage, backend, registry)
	HTTPAddress string
	HTTPPort    int

	// WebSocket server settings (always on separate port - different protocol)
	WSAddress string
	WSPort    int

	// Admin server settings
	AdminPort  int
	AdminToken string
	AdminTLS   *config.TLSConfig // nil = inherit from TLS

	// Common settings
	CORS         config.CORSConfig
	LoggingLevel string

	// TLS configuration
	TLS config.TLSConfig

	// Active roles for status endpoint
	Roles []string
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		HTTPAddress: "0.0.0.0",
		HTTPPort:    8080,
		WSAddress:   "0.0.0.0",
		WSPort:      8081,
	}
}

// Manager manages HTTP servers and combines multiple RouteProviders
type Manager struct {
	cfg    *ServerConfig
	logger *zap.Logger

	providers []RouteProvider

	httpServer  *http.Server
	wsServer    *http.Server // Only used if WSSeparate
	adminServer *http.Server

	httpRouter *gin.Engine
	wsRouter   *gin.Engine // Only used if WSSeparate

	// Readiness management for /readyz endpoint
	readiness *health.ReadinessManager
}

// NewManager creates a new server manager
func NewManager(cfg *ServerConfig, logger *zap.Logger) *Manager {
	return &Manager{
		cfg:       cfg,
		logger:    logger,
		providers: make([]RouteProvider, 0),
		readiness: health.NewReadinessManager(
			health.WithCacheTTL(2*time.Second),
			health.WithCheckTimeout(2*time.Second),
		),
	}
}

// AddProvider adds a RouteProvider to the manager.
// Call this before Start() to register all modes.
// If the provider implements ReadinessCheckProvider, it will be registered
// for readiness checks on the /readyz endpoint.
func (m *Manager) AddProvider(p RouteProvider) {
	m.providers = append(m.providers, p)
	m.logger.Debug("Added route provider",
		zap.String("name", p.Name()),
		zap.String("transport", string(p.Transport())))

	// Register readiness checker if provider implements it
	if checker, ok := p.(ReadinessCheckProvider); ok {
		m.readiness.AddChecker(&providerChecker{
			name:    p.Name(),
			checker: checker,
		})
		m.logger.Debug("Registered readiness checker",
			zap.String("provider", p.Name()))
	}
}

// providerChecker adapts a ReadinessCheckProvider to health.ReadinessChecker
type providerChecker struct {
	name    string
	checker ReadinessCheckProvider
}

func (c *providerChecker) Name() string { return c.name }
func (c *providerChecker) CheckReady(ctx context.Context) error {
	return c.checker.CheckReady(ctx)
}

// Start builds routers and starts http servers
func (m *Manager) Start(ctx context.Context) error {
	// Set Gin mode
	if m.cfg.LoggingLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Build HTTP router with common middleware
	m.httpRouter = m.buildRouter()

	// Separate WebSocket providers if configured
	var httpProviders, wsProviders []RouteProvider
	for _, p := range m.providers {
		if p.Transport() == TransportWebSocket {
			wsProviders = append(wsProviders, p)
		} else {
			httpProviders = append(httpProviders, p)
		}
	}

	// Register HTTP routes
	for _, p := range httpProviders {
		m.logger.Info("Registering HTTP routes", zap.String("mode", p.Name()))
		p.RegisterRoutes(m.httpRouter)
	}

	// Handle WebSocket providers - always on separate port (different protocol)
	if len(wsProviders) > 0 {
		m.wsRouter = m.buildRouter()
		for _, p := range wsProviders {
			m.logger.Info("Registering WebSocket routes", zap.String("mode", p.Name()))
			p.RegisterRoutes(m.wsRouter)
		}
	}

	// Add common status endpoints to HTTP router
	m.addStatusEndpoints(m.httpRouter)

	// Start HTTP server
	httpAddr := fmt.Sprintf("%s:%d", m.cfg.HTTPAddress, m.cfg.HTTPPort)
	m.httpServer = &http.Server{
		Addr:         httpAddr,
		Handler:      m.httpRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		m.logger.Info("HTTP server listening", zap.String("address", httpAddr))
		if err := m.cfg.TLS.ListenAndServe(m.httpServer); err != nil && err != http.ErrServerClosed {
			m.logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	// Start WebSocket server if providers registered
	if m.wsRouter != nil {
		wsAddr := fmt.Sprintf("%s:%d", m.cfg.WSAddress, m.cfg.WSPort)
		m.wsServer = &http.Server{
			Addr:         wsAddr,
			Handler:      m.wsRouter,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  120 * time.Second, // Longer for WebSocket
		}

		// Add status to WebSocket server too
		m.addStatusEndpoints(m.wsRouter)

		go func() {
			m.logger.Info("WebSocket server listening", zap.String("address", wsAddr))
			if err := m.cfg.TLS.ListenAndServe(m.wsServer); err != nil && err != http.ErrServerClosed {
				m.logger.Error("WebSocket server error", zap.Error(err))
			}
		}()
	}

	// Start admin server if configured
	if m.cfg.AdminPort > 0 {
		if err := m.startAdminServer(); err != nil {
			return fmt.Errorf("failed to start admin server: %w", err)
		}
	}

	// Start providers that need background initialization (e.g. registry fetcher)
	for _, p := range m.providers {
		if sp, ok := p.(StartableProvider); ok {
			m.logger.Info("Starting provider background tasks", zap.String("mode", p.Name()))
			if err := sp.Start(ctx); err != nil {
				return fmt.Errorf("failed to start provider %s: %w", p.Name(), err)
			}
		}
	}

	// Start background readiness probe for proactive health checking
	// This ensures cached readiness status is fresh for burst traffic
	m.readiness.StartBackgroundProbe(5 * time.Second)
	m.logger.Info("Started background readiness probe", zap.Duration("interval", 5*time.Second))

	return nil
}

// Shutdown gracefully shuts down all servers
func (m *Manager) Shutdown(ctx context.Context) error {
	// Stop background readiness probe first
	if m.readiness != nil {
		m.readiness.Stop()
	}

	var errs []error

	if m.httpServer != nil {
		if err := m.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("HTTP server shutdown: %w", err))
		}
	}

	if m.wsServer != nil {
		if err := m.wsServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("WebSocket server shutdown: %w", err))
		}
	}

	if m.adminServer != nil {
		if err := m.adminServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("admin server shutdown: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

// buildRouter creates a new router with common middleware
func (m *Manager) buildRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.Logger(m.logger, "/status", "/health", "/readyz"))
	router.Use(cors.New(cors.Config{
		AllowOrigins:     m.cfg.CORS.AllowedOrigins,
		AllowMethods:     m.cfg.CORS.AllowedMethods,
		AllowHeaders:     m.cfg.CORS.AllowedHeaders,
		ExposeHeaders:    m.cfg.CORS.ExposedHeaders,
		AllowCredentials: m.cfg.CORS.AllowCredentials,
		MaxAge:           time.Duration(m.cfg.CORS.MaxAge) * time.Second,
	}))
	return router
}

// addStatusEndpoints adds /health, /status, and /readyz routes
func (m *Manager) addStatusEndpoints(router *gin.Engine) {
	// /health and /status - basic liveness check
	statusHandler := func(c *gin.Context) {
		c.JSON(http.StatusOK, api.StatusResponse{
			Status:       "ok",
			Service:      "wallet-backend",
			Roles:        m.cfg.Roles,
			APIVersion:   api.CurrentAPIVersion,
			Capabilities: api.CapabilitiesForRoles(m.cfg.Roles),
		})
	}
	router.GET("/health", statusHandler)
	router.GET("/status", statusHandler)

	// /readyz - Kubernetes-style readiness probe
	// Returns 200 if all mode-specific dependencies are ready,
	// 503 if any dependency is not ready.
	router.GET("/readyz", func(c *gin.Context) {
		status := m.readiness.CheckReady(c.Request.Context())

		if !status.Ready {
			// Return 503 with details about what's not ready
			m.logger.Warn("Readiness check failed",
				zap.Any("checks", status.Checks))
			c.JSON(http.StatusServiceUnavailable, status)
			return
		}

		// Return 200 - ready to serve
		c.JSON(http.StatusOK, status)
	})
}

// startAdminServer starts the admin API server
func (m *Manager) startAdminServer() error {
	token := m.cfg.AdminToken
	if token == "" {
		var err error
		token, err = middleware.GenerateAdminToken()
		if err != nil {
			return fmt.Errorf("failed to generate admin token: %w", err)
		}
		// Log token at DEBUG level to avoid capture by production log aggregators
		// For production deployments, set WALLET_SERVER_ADMIN_TOKEN or configure
		// WALLET_SERVER_ADMIN_TOKEN_PATH / server.admin_token_path.
		m.logger.Debug("Generated admin API token",
			zap.String("token", token))
		m.logger.Warn("Auto-generated admin token (use WALLET_SERVER_ADMIN_TOKEN, WALLET_SERVER_ADMIN_TOKEN_PATH, or server.admin_token_path for production)")
	}

	// Admin router
	adminRouter := gin.New()
	adminRouter.Use(gin.Recovery())

	// Public admin status endpoint (no auth required)
	adminRouter.GET("/admin/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, api.StatusResponse{
			Status:  "ok",
			Service: "wallet-backend-admin",
			Roles:   m.cfg.Roles,
		})
	})

	// Protected admin routes with token auth
	adminGroup := adminRouter.Group("/admin")
	adminGroup.Use(middleware.AdminAuthMiddleware(token, m.logger))

	// Let providers register their admin routes
	for _, p := range m.providers {
		if adminProvider, ok := p.(AdminRouteProvider); ok {
			m.logger.Info("Registering admin routes", zap.String("provider", p.Name()))
			adminProvider.RegisterAdminRoutes(adminGroup)
		}
	}

	adminAddr := fmt.Sprintf("%s:%d", m.cfg.HTTPAddress, m.cfg.AdminPort)
	m.adminServer = &http.Server{
		Addr:         adminAddr,
		Handler:      adminRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Use dedicated admin TLS config only when it is explicitly enabled,
	// otherwise fall back to the shared TLS configuration.
	adminTLS := effectiveAdminTLS(&m.cfg.TLS, m.cfg.AdminTLS)

	go func() {
		m.logger.Info("Admin server listening", zap.String("address", adminAddr), zap.Bool("tls", adminTLS.Enabled))
		if err := adminTLS.ListenAndServe(m.adminServer); err != nil && err != http.ErrServerClosed {
			m.logger.Error("Admin server error", zap.Error(err))
		}
	}()

	return nil
}

// HTTPRouter returns the main HTTP router.
// Useful for modes that need to add routes after construction.
func (m *Manager) HTTPRouter() *gin.Engine {
	return m.httpRouter
}

// effectiveAdminTLS returns the TLS config to use for the admin server.
// It uses adminTLS only when it is non-nil and explicitly enabled;
// otherwise it falls back to the shared TLS config.
func effectiveAdminTLS(shared *config.TLSConfig, admin *config.TLSConfig) *config.TLSConfig {
	if admin != nil && admin.Enabled {
		return admin
	}
	return shared
}
