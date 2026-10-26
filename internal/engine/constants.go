// Package engine provides constants used across the engine package.
package engine

// MaxHTTPResponseBodyBytes defines the maximum allowed HTTP response body size
// to prevent memory exhaustion attacks from malicious servers.
const MaxHTTPResponseBodyBytes = 10 * 1024 * 1024 // 10MB

// MaxErrorBodyBytes is a smaller limit for reading error response bodies for logging.
const MaxErrorBodyBytes = 64 * 1024 // 64KB

// MaxClientMetadataBytes bounds a verifier's client_metadata, however it
// arrives (inline, inside a request object, or fetched from
// client_metadata_uri). The object is retained for the life of the flow and
// relayed verbatim over the WebSocket three times (credential_selection,
// match_request, sign_request), so it gets its own, far smaller bound than
// MaxHTTPResponseBodyBytes. Real client_metadata is a few KB. Larger values
// are refused, never truncated.
const MaxClientMetadataBytes = 64 << 10 // 64KB
