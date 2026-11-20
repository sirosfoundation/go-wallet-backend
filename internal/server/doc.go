// Package server provides unified HTTP server management for multiple modes.
//
// Architecture:
//   - RouteProvider: modes implement this to contribute routes
//   - Manager: combines RouteProviders into HTTP servers
//   - HTTP modes (auth, storage, backend, registry) share a single HTTP server
//   - The wallet-provider can be isolated on its own port (PKCS#11 isolation)
package server

// Configuration:
//
//   --mode=backend,registry
//   WALLET_SERVER_PORT=8080          (HTTP: auth, storage, registry)
//
// Benefits:
//   1. Single port for all HTTP services (simpler firewall/LB config)
//   2. Shared middleware setup (less code duplication)
//   3. Clear separation of concerns (RouteProvider per mode)
//
// Usage:
//
//   mgr := server.NewManager(&server.ServerConfig{
//       HTTPAddress:  "0.0.0.0",
//       HTTPPort:     8080,
//       CORS:         cfg.Server.CORS,
//       LoggingLevel: cfg.Logging.Level,
//       Roles:        roleStrings,
//   }, logger)
//
//   mgr.AddProvider(backendProvider)
//   mgr.AddProvider(registryProvider)
//
//   mgr.Start(ctx)
