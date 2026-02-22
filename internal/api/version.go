// Package api provides HTTP API handlers for the wallet backend.
package api

// APIVersion represents the current API version supported by this server.
// This allows frontends to auto-detect capabilities and use appropriate endpoints.
//
// Note: API versioning refers to capability levels, not URL prefixes.
// - REST API endpoints are at /api/... (no version prefix)
// - WebSocket API is at /api/v2/wallet (when engine role is active)
//
// The api_version field in /status indicates what features are available.
const (
	// APIVersion1 is the original API version (backward compatible).
	APIVersion1 = 1

	// CurrentAPIVersion is the highest API version supported by this server.
	// Trust evaluation is handled internally via go-trust (AuthZEN) endpoints.
	CurrentAPIVersion = APIVersion1
)

// Base capabilities available in all modes
var baseCapabilities = []string{
	"multi-tenancy",
}

// Role-specific capabilities
var roleCapabilities = map[string][]string{
	"backend": {
		"webauthn",
		"storage",
		"proxy",
	},
	"registry": {
		"vctm-registry",
	},
	"engine": {
		"websocket", // WebSocket v2 protocol at /api/v2/wallet
	},
	"auth": {
		"webauthn", // WebAuthn registration/authentication
		"session",  // Session management (account-info, settings)
	},
	"storage": {
		"credentials",   // VC storage and retrieval
		"presentations", // VP storage and retrieval
		"private-data",  // Encrypted keystore data
	},
}

// APICapabilities describes the features available at each API version.
// Deprecated: Use CapabilitiesForRoles instead for role-aware capabilities.
var APICapabilities = map[int][]string{
	APIVersion1: {
		"webauthn",
		"storage",
		"proxy",
		"multi-tenancy",
		"vctm-registry",
	},
}

// CapabilitiesForRoles returns the capabilities available for the given roles.
func CapabilitiesForRoles(roles []string) []string {
	caps := make(map[string]bool)

	// Add base capabilities
	for _, cap := range baseCapabilities {
		caps[cap] = true
	}

	// Add role-specific capabilities
	for _, role := range roles {
		if roleCaps, ok := roleCapabilities[role]; ok {
			for _, cap := range roleCaps {
				caps[cap] = true
			}
		}
	}

	// Convert to sorted slice
	result := make([]string, 0, len(caps))
	for cap := range caps {
		result = append(result, cap)
	}
	return result
}

// StatusResponse is the response from the /status endpoint.
type StatusResponse struct {
	Status       string   `json:"status"`
	Service      string   `json:"service"`
	Roles        []string `json:"roles"`
	APIVersion   int      `json:"api_version"`
	Capabilities []string `json:"capabilities,omitempty"`
}
