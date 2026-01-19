// Package api provides HTTP API handlers for the wallet backend.
package api

// APIVersion represents the current API version supported by this server.
// This allows frontends to auto-detect capabilities and use appropriate endpoints.
const (
	// APIVersion1 is the original API version (backward compatible).
	APIVersion1 = 1

	// APIVersion2 adds the discover-and-trust endpoint for combined
	// discovery and trust evaluation.
	APIVersion2 = 2

	// CurrentAPIVersion is the highest API version supported by this server.
	CurrentAPIVersion = APIVersion2
)

// APICapabilities describes the features available at each API version.
var APICapabilities = map[int][]string{
	APIVersion1: {
		"webauthn",
		"storage",
		"proxy",
		"multi-tenancy",
	},
	APIVersion2: {
		"webauthn",
		"storage",
		"proxy",
		"multi-tenancy",
		"discover-and-trust",
	},
}

// StatusResponse is the response from the /status endpoint.
type StatusResponse struct {
	Status       string   `json:"status"`
	Service      string   `json:"service"`
	APIVersion   int      `json:"api_version"`
	Capabilities []string `json:"capabilities,omitempty"`
}
