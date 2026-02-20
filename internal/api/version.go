// Package api provides HTTP API handlers for the wallet backend.
package api

// APIVersion represents the current API version supported by this server.
// This allows frontends to auto-detect capabilities and use appropriate endpoints.
//
// Note: API versioning refers to capability levels, not URL prefixes.
// - REST API endpoints are at /api/... (no version prefix)
// - WebSocket API (future) will be at /api/v2/wallet
//
// The api_version field in /status indicates what features are available.
const (
	// APIVersion1 is the original API version (backward compatible).
	APIVersion1 = 1

	// CurrentAPIVersion is the highest API version supported by this server.
	// Trust evaluation is handled internally via go-trust (AuthZEN) endpoints.
	CurrentAPIVersion = APIVersion1
)

// APICapabilities describes the features available at each API version.
var APICapabilities = map[int][]string{
	APIVersion1: {
		"webauthn",
		"storage",
		"proxy",
		"multi-tenancy",
		"vctm-registry", // VCTM caching with pre-computed trust
	},
}

// StatusResponse is the response from the /status endpoint.
type StatusResponse struct {
	Status       string   `json:"status"`
	Service      string   `json:"service"`
	Roles        []string `json:"roles"`
	APIVersion   int      `json:"api_version"`
	Capabilities []string `json:"capabilities,omitempty"`
}
