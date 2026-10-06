// Package registry provides a VCTM (Verifiable Credential Type Metadata) registry server.
// It fetches VCTMs from registry.siros.org and serves them via HTTP with rate limiting.
//
// The registry is a role (--mode=registry) of the main go-wallet-backend
// binary. Its configuration is the `registry:` section of the backend
// configuration (pkg/config.RegistryConfig); the aliases below keep the
// package-local names used throughout the registry code.
package registry

import (
	pkgconfig "github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Config is the registry section of the backend configuration.
type Config = pkgconfig.RegistryConfig

// Aliases for the registry configuration types.
type (
	APIMode            = pkgconfig.RegistryAPIMode
	RemoteSourceConfig = pkgconfig.RegistryRemoteSourceConfig
	SourceConfig       = pkgconfig.RegistrySourceConfig
	CacheConfig        = pkgconfig.RegistryCacheConfig
	DynamicCacheConfig = pkgconfig.RegistryDynamicCacheConfig
	FilterConfig       = pkgconfig.RegistryFilterConfig
	RateLimitConfig    = pkgconfig.RegistryRateLimitConfig
)

const (
	// APIModeTS11 uses the TS11 /api/v1/schemas.json endpoint.
	APIModeTS11 = pkgconfig.RegistryAPIModeTS11
	// APIModeRegistry uses the /api/v1/registry.json endpoint.
	APIModeRegistry = pkgconfig.RegistryAPIModeRegistry
)

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() *Config {
	cfg := pkgconfig.DefaultRegistryConfig()
	return &cfg
}
