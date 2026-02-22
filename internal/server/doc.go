// Package server provides unified HTTP server management for multiple modes.
//
// Architecture:
//   - RouteProvider: modes implement this to contribute routes
//   - Manager: combines RouteProviders into HTTP servers
//   - HTTP modes (auth, storage, backend, registry) share a single HTTP server
//   - WebSocket mode (engine) runs on a separate port (different protocol = different port)
package server

// Architecture Summary:
//
// BEFORE (legacy):
//   - Each mode creates its own http.Server
//   - backend:8080, engine:8081, registry:8082
//   - Duplication of middleware, router setup, status endpoints
//
// AFTER (current):
//   - server.Manager creates shared HTTP server for HTTP-based modes
//   - RouteProviders add routes to shared router
//   - backend + auth + storage + registry can all run on :8080
//   - engine (WebSocket) always runs on separate port :8081 (different protocol)
//
// Configuration:
//
//   --mode=backend,engine,registry
//   WALLET_SERVER_PORT=8080          (HTTP: auth, storage, registry)
//   WALLET_SERVER_ENGINE_PORT=8081   (WebSocket: engine)
//
// Benefits:
//   1. Single port for all HTTP services (simpler firewall/LB config)
//   2. Shared middleware setup (less code duplication)
//   3. Clear separation of concerns (RouteProvider per mode)
//   4. WebSocket on separate port (protocol isolation)
//
// Usage:
//
//   mgr := server.NewManager(&server.ServerConfig{
//       HTTPAddress:  "0.0.0.0",
//       HTTPPort:     8080,
//       WSAddress:    "0.0.0.0",
//       WSPort:       8081,
//       CORS:         cfg.Server.CORS,
//       LoggingLevel: cfg.Logging.Level,
//       Roles:        roleStrings,
//   }, logger)
//
//   // Add HTTP providers (share port 8080)
//   mgr.AddProvider(backendProvider)
//   mgr.AddProvider(registryProvider)
//
//   // Add WebSocket provider (uses port 8081)
//   mgr.AddProvider(engineProvider)
//
//   // Start both servers
//   mgr.Start(ctx)

