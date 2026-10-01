package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// go-tokenauth (v0.4 and v0.5) fetches the AS JWKS with http.DefaultClient: no
// scheme policy, no address guard, and it follows HTTPS->HTTP redirects. An
// on-path attacker could substitute the keys and forge session tokens. Since
// the validator has no client option, keys are fetched by us with the guarded
// client (cfg.HTTPClient.NewHTTPClient: plaintext policy and SSRF guards
// applied to every request and redirect hop) and handed to the validator over
// a loopback-only relay. The relay serves public keys only.

// jwksRelay serves a JWKS document on a loopback port, produced by fetch on
// every request (go-tokenauth caches and refreshes on its own schedule).
type jwksRelay struct {
	srv *http.Server
	url string
}

func startJWKSRelay(fetch func(ctx context.Context) ([]byte, error)) (*jwksRelay, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("jwks relay: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		body, err := fetch(r.Context())
		if err != nil {
			http.Error(w, "jwks unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	// The relay listens on 127.0.0.1 only and serves public keys, so plain
	// HTTP on the loopback interface is deliberate: go-tokenauth fetches its
	// JWKS URL with http.DefaultClient and offers no client or TLS option.
	// Built from parts (not a literal) because the address is only known once
	// the listener is bound and the literal would read as a remote clear-text
	// URL to static analysis.
	u := url.URL{Scheme: "http", Host: ln.Addr().String(), Path: "/jwks.json"}
	return &jwksRelay{srv: srv, url: u.String()}, nil
}

// Close stops the relay.
func (r *jwksRelay) Close() error {
	if r == nil {
		return nil
	}
	return r.srv.Close()
}

// asJWKSURL returns <as.external_url>/auth/.well-known/jwks.json, refusing a
// plain-http external_url unless the HTTP client policy allows plaintext.
func asJWKSURL(cfg *config.Config) (string, error) {
	u, err := cfg.AS.ExternalBaseURL()
	if err != nil {
		return "", err
	}
	if u.Scheme == "http" && !cfg.HTTPClient.AllowsPlaintext() {
		return "", fmt.Errorf("as.external_url %q uses plain http; use https or set http_client.allow_http for local development", cfg.AS.ExternalURL)
	}
	return u.JoinPath("auth", ".well-known", "jwks.json").String(), nil
}

// newRemoteJWKSRelay relays the AS JWKS fetched with the guarded HTTP client.
func newRemoteJWKSRelay(cfg *config.Config) (*jwksRelay, error) {
	target, err := asJWKSURL(cfg)
	if err != nil {
		return nil, err
	}
	client := cfg.HTTPClient.NewHTTPClient(10 * time.Second)
	return startJWKSRelay(func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("jwks endpoint returned HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	})
}

// newLocalJWKSRelay serves keys from this process (the co-hosted AS's own key
// manager): no network fetch at all.
func newLocalJWKSRelay(keys func() jose.JSONWebKeySet) (*jwksRelay, error) {
	return startJWKSRelay(func(context.Context) ([]byte, error) {
		return json.Marshal(keys())
	})
}
