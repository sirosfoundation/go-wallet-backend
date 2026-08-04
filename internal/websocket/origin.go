package websocket

import (
	"net/http"
	"net/url"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// CheckOriginFromConfig returns a CheckOrigin function that validates the
// request Origin header against the configured CORS allowed origins and
// RP origins. This prevents cross-site WebSocket hijacking attacks.
func CheckOriginFromConfig(cfg *config.Config) func(r *http.Request) bool {
	// Build the allowed origins set once at startup.
	allowed := make(map[string]struct{})
	allowAll := false

	for _, o := range cfg.Server.CORS.AllowedOrigins {
		if o == "*" {
			allowAll = true
			break
		}
		allowed[o] = struct{}{}
	}

	// Also allow RP origins (WebAuthn relying party origins are legitimate WebSocket clients).
	for _, o := range cfg.Server.GetRPOrigins() {
		allowed[o] = struct{}{}
	}

	return func(r *http.Request) bool {
		if allowAll {
			return true
		}

		origin := r.Header.Get("Origin")
		if origin == "" {
			// No Origin header — same-origin request or non-browser client.
			// Allow: server-to-server (no browser) connections are fine.
			return true
		}

		// Normalize: parse and reconstruct to handle trailing slashes, port defaults, etc.
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		normalized := u.Scheme + "://" + u.Host

		if _, ok := allowed[origin]; ok {
			return true
		}
		if _, ok := allowed[normalized]; ok {
			return true
		}

		return false
	}
}
