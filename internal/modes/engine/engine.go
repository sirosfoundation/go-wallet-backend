// Package engine provides the WebSocket engine mode runner.
// The engine handles stateless WebSocket coordination for OID4VP flows.
package engine

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-wallet-backend/internal/api"
	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func init() {
	modes.Register(modes.ModeEngine, func(cfg interface{}) (modes.Runner, error) {
		c, ok := cfg.(*Config)
		if !ok {
			return nil, fmt.Errorf("invalid config type for engine mode")
		}
		return New(c)
	})
}

// Config holds configuration for the engine mode
type Config struct {
	Config *config.Config
	Logger *zap.Logger
	Roles  []string // Active roles (for status endpoint)
}

// Runner implements the engine mode
type Runner struct {
	cfg     *Config
	manager *wsengine.Manager
	srv     *http.Server
}

// New creates a new engine runner
func New(cfg *Config) (*Runner, error) {
	return &Runner{cfg: cfg}, nil
}

// Role returns the role this runner implements
func (r *Runner) Role() modes.Role {
	return modes.RoleEngine
}

// Name returns the mode name (deprecated, use Role())
func (r *Runner) Name() modes.Mode {
	return modes.ModeEngine
}

// Run starts the engine services
func (r *Runner) Run(ctx context.Context) error {
	cfg := r.cfg.Config
	logger := r.cfg.Logger

	// Create WebSocket manager
	r.manager = wsengine.NewManager(cfg, logger)

	// Register flow handlers
	r.manager.RegisterFlowHandler(wsengine.ProtocolOID4VCI, wsengine.NewOID4VCIHandler)
	r.manager.RegisterFlowHandler(wsengine.ProtocolOID4VP, wsengine.NewOID4VPHandler)
	r.manager.RegisterFlowHandler(wsengine.ProtocolVCTM, wsengine.NewVCTMHandler)

	// Set up HTTP server for WebSocket endpoint
	if cfg.Logging.Level != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger(logger))

	// Determine roles for status endpoint
	roles := r.cfg.Roles
	if len(roles) == 0 {
		roles = []string{"engine"}
	}

	// Health endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, api.StatusResponse{
			Status:       "ok",
			Service:      "wallet-backend",
			Roles:        roles,
			APIVersion:   api.CurrentAPIVersion,
			Capabilities: api.APICapabilities[api.CurrentAPIVersion],
		})
	})
	router.GET("/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, api.StatusResponse{
			Status:       "ok",
			Service:      "wallet-backend",
			Roles:        roles,
			APIVersion:   api.CurrentAPIVersion,
			Capabilities: api.APICapabilities[api.CurrentAPIVersion],
		})
	})

	// WebSocket v2 endpoint
	router.GET("/api/v2/wallet", func(c *gin.Context) {
		r.manager.HandleConnection(c.Writer, c.Request)
	})

	// Create server
	addr := cfg.Server.Address()
	r.srv = &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second, // Longer for WebSocket
	}

	// Start server
	go func() {
		logger.Info("Engine server listening",
			zap.String("address", addr),
			zap.String("endpoint", "/api/v2/wallet"))
		if err := r.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Engine server error", zap.Error(err))
		}
	}()

	// Block until context is cancelled
	<-ctx.Done()
	return nil
}

// Shutdown gracefully shuts down the engine services
func (r *Runner) Shutdown(ctx context.Context) error {
	logger := r.cfg.Logger

	if r.manager != nil {
		r.manager.Close()
	}

	if r.srv != nil {
		if err := r.srv.Shutdown(ctx); err != nil {
			logger.Error("Engine server forced to shutdown", zap.Error(err))
			return err
		}
	}

	return nil
}

// requestLogger returns a Gin middleware for logging requests
func requestLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		// Don't log WebSocket upgrades in detail
		if c.Request.Header.Get("Upgrade") == "websocket" {
			logger.Debug("websocket connection",
				zap.String("path", path),
				zap.Int("status", status))
		} else {
			logger.Info("request",
				zap.String("method", c.Request.Method),
				zap.String("path", path),
				zap.Int("status", status),
				zap.Duration("latency", latency))
		}
	}
}
