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

	// Common settings
	CORS         config.CORSConfig
	LoggingLevel string

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
}

// NewManager creates a new server manager
func NewManager(cfg *ServerConfig, logger *zap.Logger) *Manager {
	return &Manager{
		cfg:       cfg,
		logger:    logger,
		providers: make([]RouteProvider, 0),
	}
}

// AddProvider adds a RouteProvider to the manager.
// Call this before Start() to register all modes.
func (m *Manager) AddProvider(p RouteProvider) {
	m.providers = append(m.providers, p)
	m.logger.Debug("Added route provider",
		zap.String("name", p.Name()),
		zap.String("transport", string(p.Transport())))
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
		if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
			if err := m.wsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

	return nil
}

// Shutdown gracefully shuts down all servers
func (m *Manager) Shutdown(ctx context.Context) error {
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
	router.Use(middleware.Logger(m.logger))
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

// addStatusEndpoints adds /health and /status routes
func (m *Manager) addStatusEndpoints(router *gin.Engine) {
	handler := func(c *gin.Context) {
		c.JSON(http.StatusOK, api.StatusResponse{
			Status:       "ok",
			Service:      "wallet-backend",
			Roles:        m.cfg.Roles,
			APIVersion:   api.CurrentAPIVersion,
			Capabilities: api.CapabilitiesForRoles(m.cfg.Roles),
		})
	}
	router.GET("/health", handler)
	router.GET("/status", handler)
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
		m.logger.Info("Generated admin API token (set env to use a fixed token)",
			zap.String("token", token))
	}

	// Admin router with token auth
	adminRouter := gin.New()
	adminRouter.Use(gin.Recovery())
	adminRouter.Use(middleware.AdminAuthMiddleware(token, m.logger))

	// TODO: Add admin routes from providers that support it

	adminAddr := fmt.Sprintf("%s:%d", m.cfg.HTTPAddress, m.cfg.AdminPort)
	m.adminServer = &http.Server{
		Addr:         adminAddr,
		Handler:      adminRouter,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		m.logger.Info("Admin server listening", zap.String("address", adminAddr))
		if err := m.adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
