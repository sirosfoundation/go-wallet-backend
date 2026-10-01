package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.uber.org/zap"

	wsengine "github.com/sirosfoundation/go-wallet-backend/internal/engine"
	"github.com/sirosfoundation/go-wallet-backend/internal/modes"
	"github.com/sirosfoundation/go-wallet-backend/internal/server"
	"github.com/sirosfoundation/go-wallet-backend/internal/service"
	"github.com/sirosfoundation/go-wallet-backend/internal/storage"
	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
	"github.com/sirosfoundation/go-wallet-backend/pkg/issuermetadata"
	"github.com/sirosfoundation/go-wallet-backend/pkg/logging"
)

var (
	configFile         = flag.String("config", "configs/config.yaml", "Path to backend configuration file")
	registryConfigFile = flag.String("registry-config", "configs/registry.yaml", "DEPRECATED: path to the old standalone registry configuration file; use the registry: section of --config")
	modeFlag           = flag.String("mode", "backend", "Operating roles: backend, registry, engine, admin, auth, wallet-provider (comma-separated or 'all')")
	version            = "dev"
	commit             = "unknown"
	buildTime          = "unknown"
)

func main() {
	flag.Parse()

	// Parse roles (supports comma-separated list or "all")
	roles, err := modes.ParseRoles(*modeFlag)
	if err != nil {
		log.Fatalf("Invalid mode: %v", err)
	}
	roleStrings := roles.Strings()

	// Load backend configuration (needed for backend, engine, admin, auth, and wallet-provider roles)
	var backendCfg *config.Config
	needsBackendCfg := roles.Has(modes.RoleBackend) || roles.Has(modes.RoleEngine) || roles.Has(modes.RoleAdmin) || roles.Has(modes.RoleAuth) || roles.Has(modes.RoleWalletProvider)
	if needsBackendCfg {
		backendCfg, err = config.Load(*configFile)
		if err != nil {
			log.Fatalf("Failed to load backend configuration: %v", err)
		}
		if roles.Has(modes.RoleAuth) {
			backendCfg.EnableForRole()
			// EnableForRole mutates the already-validated config (e.g.
			// falling back to WalletProvider's signing key for AS), so
			// re-validate rather than let an invalid resulting state (say,
			// AS enabled with no signing key anywhere) surface later as a
			// less actionable failure during provider init.
			if err := backendCfg.Validate(); err != nil {
				log.Fatalf("Invalid backend configuration after enabling AS for role: %v", err)
			}
		}
	}

	// Registry role: the registry section lives in the backend config. When
	// the registry runs alone, only the registry-relevant parts of that config
	// are required (see config.LoadRegistryOnly).
	registryOnly := roles.Has(modes.RoleRegistry) && !needsBackendCfg
	var registryCfg *config.Config // full config used by the registry role
	var registryWarnings []string
	if roles.Has(modes.RoleRegistry) {
		if registryOnly {
			registryCfg, err = config.LoadRegistryOnly(*configFile)
			if err != nil {
				log.Fatalf("Failed to load configuration for registry role: %v", err)
			}
		} else {
			registryCfg = backendCfg
		}
		registryWarnings, err = setupRegistryConfig(registryCfg, *registryConfigFile, registryOnly)
		if err != nil {
			log.Fatalf("Invalid registry configuration: %v", err)
		}
	}

	// Initialize logger from the (shared) backend logging config
	var logger *zap.Logger
	if logCfg := loggingConfig(backendCfg, registryCfg); logCfg != nil {
		logger, err = logging.NewLogger(*logCfg)
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() { _ = logger.Sync() }()

	for _, w := range registryWarnings {
		logger.Warn(w)
	}
	if registryCfg != nil {
		for _, w := range registryCfg.Warnings() {
			logger.Warn(w)
		}
	}

	logger.Info("Starting Wallet Backend",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("build_time", buildTime),
		zap.Strings("roles", roleStrings),
	)

	// Security configuration validation for production environments
	// Checks for potentially dangerous configurations and logs warnings
	isProduction := os.Getenv("ENVIRONMENT") == "production" ||
		os.Getenv("GO_ENV") == "production" ||
		os.Getenv("APP_ENV") == "production"

	if backendCfg != nil {
		// Issue #70: Warn when trust evaluation is disabled (allows any issuer/verifier)
		// Cache the results to avoid repeated calls
		issuerEnabled := backendCfg.Trust.IsIssuerTrustEnabled()
		verifierEnabled := backendCfg.Trust.IsVerifierTrustEnabled()

		if !issuerEnabled || !verifierEnabled {
			// Use Error level in production to ensure visibility in alerting pipelines
			level := zap.WarnLevel
			if isProduction {
				level = zap.ErrorLevel
			}

			if !issuerEnabled && !verifierEnabled {
				logger.Log(level, "Trust evaluation is disabled - all issuers and verifiers will be accepted without verification",
					zap.Bool("issuer_trust_enabled", false),
					zap.Bool("verifier_trust_enabled", false),
					zap.Bool("production", isProduction))
			} else if !issuerEnabled {
				logger.Log(level, "Issuer trust evaluation is disabled - all issuers will be accepted without verification",
					zap.Bool("issuer_trust_enabled", false),
					zap.Bool("production", isProduction))
			} else {
				logger.Log(level, "Verifier trust evaluation is disabled - all verifiers will be accepted without verification",
					zap.Bool("verifier_trust_enabled", false),
					zap.Bool("production", isProduction))
			}
		}

		// Issue #71: Warn when CORS allows wildcard origin
		for _, origin := range backendCfg.Server.CORS.AllowedOrigins {
			if origin == "*" {
				level := zap.WarnLevel
				if isProduction {
					level = zap.ErrorLevel
				}
				logger.Log(level, "CORS wildcard (*) configured - this allows any origin to make requests",
					zap.Strings("allowed_origins", backendCfg.Server.CORS.AllowedOrigins),
					zap.Bool("allow_credentials", backendCfg.Server.CORS.AllowCredentials),
					zap.Strings("allowed_headers", backendCfg.Server.CORS.AllowedHeaders),
					zap.Strings("allowed_methods", backendCfg.Server.CORS.AllowedMethods),
					zap.Bool("production", isProduction))
				break
			}
		}
	}

	// Build server configuration
	serverCfg := server.DefaultServerConfig()
	serverCfg.Roles = roleStrings

	if backendCfg != nil {
		serverCfg.HTTPAddress = backendCfg.Server.Host
		serverCfg.HTTPPort = backendCfg.Server.Port
		serverCfg.WSAddress = backendCfg.Server.Host
		serverCfg.WSPort = backendCfg.Server.EnginePort
		serverCfg.AdminPort = backendCfg.Server.AdminPort
		serverCfg.AdminToken = backendCfg.Server.AdminToken
		serverCfg.CORS = backendCfg.Server.CORS
		serverCfg.LoggingLevel = backendCfg.Logging.Level
		serverCfg.TLS = backendCfg.Server.TLS
		serverCfg.AdminTLS = backendCfg.Server.AdminTLS

		// Wallet-provider isolation port
		if backendCfg.Server.WPPort > 0 {
			serverCfg.WPAddress = backendCfg.Server.WPHost
			if serverCfg.WPAddress == "" {
				serverCfg.WPAddress = backendCfg.Server.Host
			}
			serverCfg.WPPort = backendCfg.Server.WPPort
		}
	} else if registryCfg != nil {
		// Registry-only mode: shared server/logging/CORS settings of the
		// backend config, listening on server.registry_host/registry_port
		// (default <host>:8097, as the retired standalone binary did).
		addr := registryCfg.Server.RegistryAddress()
		host, port := registryListenAddr(addr)
		serverCfg.HTTPAddress = host
		serverCfg.HTTPPort = port
		serverCfg.LoggingLevel = registryCfg.Logging.Level
		serverCfg.CORS = registryCfg.Server.CORS
		serverCfg.TLS = registryCfg.Server.TLS
		serverCfg.TrustedProxies = registryCfg.Server.TrustedProxies
	}

	if backendCfg != nil {
		serverCfg.ServedByHeader = backendCfg.Server.ResolvedServedBy()
		serverCfg.TrustedProxies = backendCfg.Server.TrustedProxies
		serverCfg.WarnUntrustedClientIP = backendCfg.Security.OIDCGateRateLimit.PerIP.Enabled
	} else if registryCfg != nil {
		serverCfg.ServedByHeader = registryCfg.Server.ResolvedServedBy()
	}
	serverCfg.IsProduction = isProduction

	// Create unified server manager
	mgr := server.NewManager(serverCfg, logger)

	// Track closeable resources
	type closeable interface{ Close() error }
	var resources []closeable

	// Add providers based on roles
	var backendProvider *server.BackendProvider
	if roles.Has(modes.RoleBackend) {
		var err error
		backendProvider, err = server.NewBackendProvider(backendCfg, logger, roleStrings)
		if err != nil {
			logger.Fatal("Failed to create backend provider", zap.Error(err))
		}
		mgr.AddProvider(backendProvider)
		resources = append(resources, backendProvider)
	}

	var registryProvider *server.RegistryProvider
	if roles.Has(modes.RoleRegistry) {
		provider, err := server.NewRegistryProvider(registryCfg, logger)
		if err != nil {
			logger.Fatal("Failed to create registry provider", zap.Error(err))
		}
		// Registry-only: keep the retired standalone binary's root paths.
		provider.SetRootAliases(registryOnly)
		// Co-located with the backend: share its tenant store and token
		// blacklist so revocation and tenant checks apply to the registry too.
		if backendProvider != nil {
			provider.SetTenantLookup(backendProvider.Store().Tenants())
			provider.SetTokenBlacklist(backendProvider.Services().TokenBlacklist)
		}
		registryProvider = provider
		mgr.AddProvider(provider)
		resources = append(resources, provider)
	}

	var engineProvider *server.EngineProvider
	if roles.Has(modes.RoleEngine) {
		// Wire verifier store from backend if available (for trust caching)
		var verifierStore storage.VerifierStore
		if backendProvider != nil {
			verifierStore = backendProvider.Store().Verifiers()
		}
		// Share the metadata resolver from the backend so the TTL cache is not duplicated.
		var sharedResolver *issuermetadata.Resolver
		if backendProvider != nil {
			sharedResolver = backendProvider.MetadataResolver()
		}
		// Share the issuer lookup so the engine gets the same registered-issuer
		// enrichment as the /v1/resolve HTTP endpoint.
		var issuerLookup wsengine.CredentialIssuerLookup
		if backendProvider != nil {
			issuerLookup = backendProvider.Store().Issuers()
		}
		provider, err := server.NewEngineProvider(backendCfg, logger, verifierStore, sharedResolver, issuerLookup)
		if err != nil {
			logger.Fatal("Failed to create engine provider", zap.Error(err))
		}
		// Engine and registry in one process: the registry is served by the
		// shared HTTP server under /registry (not on server.registry_port),
		// and the outbound HTTP guards reject loopback, so give the engine's
		// VCTM client the registry in-process - unless trust.registry_url
		// names an explicit registry.
		if registryProvider != nil && backendCfg.Trust.RegistryURL == "" {
			provider.SetRegistryHandler(registryProvider.InProcessHandler())
		}
		// Wire token validator for WebSocket handshake auth
		if backendProvider != nil && backendProvider.TokenValidator() != nil {
			provider.SetTokenValidator(backendProvider.TokenValidator())
		}
		// Wire the same token blacklist the HTTP auth middlewares use, so a
		// revoked token (or a deleted user's other tokens) is rejected
		// during the WebSocket handshake too, on both the go-tokenauth and
		// legacy HMAC paths - see EngineProvider.SetTokenBlacklist.
		if backendProvider != nil {
			provider.SetTokenBlacklist(backendProvider.Services().TokenBlacklist)
		}
		mgr.AddProvider(provider)
		engineProvider = provider
	}

	// Wire session stores into UserService so DeleteUser purges AS cookie
	// sessions and, when the engine runs in this process, active engine
	// (WebSocket) sessions alike. The AS cleaner is wired regardless of the
	// engine role: a --mode=backend deployment has AS sessions to drop too.
	// Both engine cleaners are wired: SessionStore() only purges the
	// persisted SessionData bookkeeping record, while Manager() closes the
	// live *websocket.Conn* itself - without the latter, a connection that
	// was already established before the user was deleted stayed open and
	// usable until it disconnected on its own (#393).
	if backendProvider != nil {
		cleaners := service.MultiSessionCleaner{backendProvider.ASSessionCleaner()}
		if engineProvider != nil {
			cleaners = append(cleaners, engineProvider.SessionStore(), engineProvider.Manager())
		}
		backendProvider.Services().User.SetSessionCleaner(cleaners)
	}

	// Admin-only mode: standalone admin API without backend auth/storage routes.
	// Skipped when RoleBackend is active, since BackendProvider already registers admin routes.
	if roles.Has(modes.RoleAdmin) && !roles.Has(modes.RoleBackend) {
		provider, err := server.NewAdminProvider(backendCfg, logger)
		if err != nil {
			logger.Fatal("Failed to create admin provider", zap.Error(err))
		}
		mgr.AddProvider(provider)
		resources = append(resources, provider)
	}

	// Wallet-provider isolation mode: runs wallet-provider endpoints on a
	// separate server for PKCS#11 operational isolation.
	// When co-deployed with backend (no --mode=wallet-provider), routes are
	// served from the shared HTTP server as usual.
	if roles.Has(modes.RoleWalletProvider) && !roles.Has(modes.RoleBackend) {
		provider, err := server.NewWalletProviderProvider(backendCfg, logger)
		if err != nil {
			logger.Fatal("Failed to create wallet-provider provider", zap.Error(err))
		}
		mgr.AddProvider(provider)
		resources = append(resources, provider)

		logger.Info("Wallet-provider running in isolated mode",
			zap.Int("port", backendCfg.Server.WPPort),
			zap.Bool("pkcs11", backendCfg.WalletProvider.PKCS11 != nil))
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start all servers
	if err := mgr.Start(ctx); err != nil {
		logger.Fatal("Failed to start servers", zap.Error(err))
	}

	// Wait for shutdown signal
	var serveErr error
	select {
	case <-quit:
		logger.Info("Received shutdown signal")
	case serveErr = <-mgr.ServeErrors():
		logger.Error("Listener stopped serving, shutting down", zap.Error(serveErr))
	}
	cancel()

	// Graceful shutdown
	logger.Info("Shutting down...", zap.Strings("roles", roleStrings))
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := mgr.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}

	// Cleanup resources
	for _, r := range resources {
		if err := r.Close(); err != nil {
			logger.Error("Resource cleanup error", zap.Error(err))
		}
	}

	logger.Info("Server exited")
	if serveErr != nil {
		_ = logger.Sync()
		os.Exit(1) //nolint:gocritic // cleanup above is complete; deferred cancel is irrelevant
	}
}

// setupRegistryConfig applies the deprecated standalone registry
// configuration (--registry-config, REGISTRY_*) on top of cfg, then validates
// everything the registry role needs. It returns the deprecation warnings to
// log once the logger exists.
func setupRegistryConfig(cfg *config.Config, legacyPath string, standalone bool) ([]string, error) {
	warnings, err := cfg.ApplyLegacyRegistryConfig(legacyPath, standalone)
	if err != nil {
		return nil, err
	}
	// The overlay can change server settings (registry_port, TLS, CORS, ...)
	// after LoadRegistryOnly validated the defaults: revalidate them.
	if standalone {
		if err := cfg.ValidateRegistryStandalone(); err != nil {
			return warnings, err
		}
	}
	if err := cfg.ValidateRegistry(); err != nil {
		return warnings, err
	}
	return warnings, nil
}

// registryListenAddr splits a host:port address as returned by
// config.ServerConfig.RegistryAddress.
func registryListenAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 8097
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 8097
	}
	return host, port
}

// loggingConfig picks the logging settings: the backend config when any
// backend role runs, otherwise the registry-only config; nil when neither is
// loaded.
func loggingConfig(backendCfg, registryCfg *config.Config) *logging.Config {
	src := backendCfg
	if src == nil {
		src = registryCfg
	}
	if src == nil {
		return nil
	}
	return &logging.Config{Level: src.Logging.Level, Format: src.Logging.Format}
}
