// Package engine provides constants used across the engine package.
package engine

// MaxHTTPResponseBodyBytes defines the maximum allowed HTTP response body size
// to prevent memory exhaustion attacks from malicious servers.
const MaxHTTPResponseBodyBytes = 10 * 1024 * 1024 // 10MB

// MaxErrorBodyBytes is a smaller limit for reading error response bodies for logging.
const MaxErrorBodyBytes = 64 * 1024 // 64KB
