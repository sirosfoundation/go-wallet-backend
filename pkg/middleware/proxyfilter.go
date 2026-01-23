// Package middleware provides HTTP middleware for the wallet backend.
package middleware

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ProxyFilterConfig configures the proxy URL filter.
type ProxyFilterConfig struct {
	// Enabled turns proxy filtering on/off (default: true in production).
	Enabled bool `yaml:"enabled" envconfig:"PROXY_FILTER_ENABLED"`

	// RequireHTTPS requires all proxied URLs to use HTTPS.
	// This is the PRIMARY defense against SSRF - cloud metadata endpoints
	// and internal services typically don't have valid TLS certificates.
	// Strongly recommended for production.
	RequireHTTPS bool `yaml:"require_https" envconfig:"PROXY_REQUIRE_HTTPS"`

	// BlockLoopback blocks requests to 127.0.0.0/8, ::1, and localhost hostnames.
	BlockLoopback bool `yaml:"block_loopback" envconfig:"PROXY_BLOCK_LOOPBACK"`

	// BlockRFC1918 blocks requests to RFC 1918 private addresses (10/8, 172.16/12, 192.168/16).
	// Note: This is defense-in-depth only. DNS rebinding can bypass this.
	BlockRFC1918 bool `yaml:"block_rfc1918" envconfig:"PROXY_BLOCK_RFC1918"`

	// BlockLinkLocal blocks requests to link-local addresses (169.254.0.0/16, fe80::/10).
	// This blocks cloud metadata services (169.254.169.254 on AWS/GCP/Azure).
	BlockLinkLocal bool `yaml:"block_link_local" envconfig:"PROXY_BLOCK_LINK_LOCAL"`

	// BlockedHosts is a list of additional blocked hostnames (case-insensitive).
	BlockedHosts []string `yaml:"blocked_hosts" envconfig:"PROXY_BLOCKED_HOSTS"`

	// SeenHostsTTL is how long to remember "seen" hosts (default: 1 hour).
	SeenHostsTTL time.Duration `yaml:"seen_hosts_ttl" envconfig:"PROXY_SEEN_HOSTS_TTL"`

	// MaxSeenHosts limits the size of the seen hosts cache.
	MaxSeenHosts int `yaml:"max_seen_hosts" envconfig:"PROXY_MAX_SEEN_HOSTS"`
}

// DefaultProxyFilterConfig returns sensible production defaults.
func DefaultProxyFilterConfig() ProxyFilterConfig {
	return ProxyFilterConfig{
		Enabled:        true,
		RequireHTTPS:   true,  // Primary SSRF defense
		BlockLoopback:  true,  // Block localhost access
		BlockRFC1918:   true,  // Defense-in-depth for private networks
		BlockLinkLocal: true,  // Block cloud metadata (169.254.169.254)
		BlockedHosts: []string{
			// Cloud metadata hostnames (defense-in-depth, link-local blocking is primary)
			"metadata.google.internal",
		},
		SeenHostsTTL: time.Hour,
		MaxSeenHosts: 100,
	}
}

// DevelopmentProxyFilterConfig returns permissive defaults for local development.
// All security checks are disabled to allow testing with local services.
func DevelopmentProxyFilterConfig() ProxyFilterConfig {
	return ProxyFilterConfig{
		Enabled:        true,  // Still route through filter for logging/tracking
		RequireHTTPS:   false, // Allow HTTP for local dev servers
		BlockLoopback:  false, // Allow localhost
		BlockRFC1918:   false, // Allow private networks
		BlockLinkLocal: false, // Allow link-local
		BlockedHosts:   nil,
		SeenHostsTTL:   time.Hour,
		MaxSeenHosts:   100,
	}
}

// seenHostEntry tracks when a host was first seen.
type seenHostEntry struct {
	Host      string
	FirstSeen time.Time
}

// ProxyFilter validates and filters proxy target URLs.
//
// Security model:
//   - RequireHTTPS is the primary defense. Cloud metadata endpoints and internal
//     services don't have valid TLS certificates, so requiring HTTPS blocks most SSRF.
//   - BlockLoopback prevents access to local services.
//   - BlockLinkLocal prevents access to cloud metadata services (169.254.169.254).
//   - BlockRFC1918 is defense-in-depth but can be bypassed via DNS rebinding.
//   - "Seen hosts" cache is for optimization, not security.
type ProxyFilter struct {
	cfg ProxyFilterConfig

	// Seen hosts cache (hosts that passed validation)
	seenHosts map[string]seenHostEntry
	mu        sync.RWMutex

	logger *zap.Logger
}

// NewProxyFilter creates a new proxy filter with the given configuration.
func NewProxyFilter(cfg ProxyFilterConfig, logger *zap.Logger) *ProxyFilter {
	pf := &ProxyFilter{
		cfg:       cfg,
		seenHosts: make(map[string]seenHostEntry),
		logger:    logger.Named("proxy-filter"),
	}

	// Start cleanup goroutine if TTL is set
	if cfg.SeenHostsTTL > 0 {
		go pf.cleanupLoop()
	}

	return pf
}

// cleanupLoop periodically removes expired seen hosts.
func (pf *ProxyFilter) cleanupLoop() {
	ticker := time.NewTicker(pf.cfg.SeenHostsTTL / 2)
	defer ticker.Stop()

	for range ticker.C {
		pf.cleanupExpired()
	}
}

// cleanupExpired removes hosts older than TTL.
func (pf *ProxyFilter) cleanupExpired() {
	if pf.cfg.SeenHostsTTL == 0 {
		return
	}

	cutoff := time.Now().Add(-pf.cfg.SeenHostsTTL)

	pf.mu.Lock()
	defer pf.mu.Unlock()

	for host, entry := range pf.seenHosts {
		if entry.FirstSeen.Before(cutoff) {
			delete(pf.seenHosts, host)
			pf.logger.Debug("Expired seen host", zap.String("host", host))
		}
	}
}

// MarkHostSeen records that a host has been successfully contacted.
func (pf *ProxyFilter) MarkHostSeen(rawURL string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	host := normalizeHost(parsed.Host)
	if host == "" {
		return
	}

	pf.mu.Lock()
	defer pf.mu.Unlock()

	if _, exists := pf.seenHosts[host]; !exists {
		// Enforce max size (evict oldest)
		if pf.cfg.MaxSeenHosts > 0 && len(pf.seenHosts) >= pf.cfg.MaxSeenHosts {
			var oldestHost string
			var oldestTime time.Time
			for h, e := range pf.seenHosts {
				if oldestHost == "" || e.FirstSeen.Before(oldestTime) {
					oldestHost = h
					oldestTime = e.FirstSeen
				}
			}
			if oldestHost != "" {
				delete(pf.seenHosts, oldestHost)
			}
		}

		pf.seenHosts[host] = seenHostEntry{
			Host:      host,
			FirstSeen: time.Now(),
		}
		pf.logger.Debug("Marked host as seen", zap.String("host", host))
	}
}

// IsHostSeen checks if a host has been previously contacted.
func (pf *ProxyFilter) IsHostSeen(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}

	pf.mu.RLock()
	defer pf.mu.RUnlock()

	entry, exists := pf.seenHosts[host]
	if !exists {
		return false
	}

	if pf.cfg.SeenHostsTTL > 0 && time.Since(entry.FirstSeen) > pf.cfg.SeenHostsTTL {
		return false
	}

	return true
}

// GetSeenHosts returns all currently seen hosts.
func (pf *ProxyFilter) GetSeenHosts() []string {
	pf.mu.RLock()
	defer pf.mu.RUnlock()

	hosts := make([]string, 0, len(pf.seenHosts))
	for host := range pf.seenHosts {
		hosts = append(hosts, host)
	}
	return hosts
}

// IsAllowed checks if a URL passes the security filters.
// Returns nil if allowed, error describing why if blocked.
func (pf *ProxyFilter) IsAllowed(rawURL string) error {
	if !pf.cfg.Enabled {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Only HTTP/HTTPS allowed
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("only HTTP(S) URLs allowed, got %s", scheme)
	}

	// Primary defense: require HTTPS
	if pf.cfg.RequireHTTPS && scheme != "https" {
		return fmt.Errorf("HTTPS required (security policy)")
	}

	host := normalizeHost(parsed.Host)
	if host == "" {
		return fmt.Errorf("empty host")
	}

	hostname := parsed.Hostname()

	// Check blocked hosts
	for _, blocked := range pf.cfg.BlockedHosts {
		if strings.EqualFold(hostname, blocked) {
			return fmt.Errorf("host %q is blocked", hostname)
		}
	}

	// Check if hostname is an IP address - apply IP-based filters
	if ip := net.ParseIP(hostname); ip != nil {
		// Block loopback (127.0.0.0/8, ::1)
		if pf.cfg.BlockLoopback && ip.IsLoopback() {
			return fmt.Errorf("loopback addresses are blocked")
		}

		// Block link-local (169.254.0.0/16, fe80::/10) - catches cloud metadata
		if pf.cfg.BlockLinkLocal && ip.IsLinkLocalUnicast() {
			return fmt.Errorf("link-local addresses are blocked (cloud metadata)")
		}

		// Block RFC 1918 private addresses (defense-in-depth)
		if pf.cfg.BlockRFC1918 && isRFC1918(ip) {
			return fmt.Errorf("RFC 1918 private addresses are blocked")
		}
	} else {
		// Hostname - check for localhost variants
		if pf.cfg.BlockLoopback && isLocalhostName(hostname) {
			return fmt.Errorf("localhost is blocked")
		}
	}

	return nil
}

// normalizeHost extracts and lowercases the hostname, stripping port.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(host)
}

// isRFC1918 checks if an IP is in RFC 1918 private address space.
// These are: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
func isRFC1918(ip net.IP) bool {
	// Convert to 4-byte representation for IPv4
	ip4 := ip.To4()
	if ip4 == nil {
		// Not IPv4 - check IPv6 unique local (fc00::/7) separately if needed
		return false
	}

	// 10.0.0.0/8
	if ip4[0] == 10 {
		return true
	}

	// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return true
	}

	// 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}

	return false
}

// isLocalhostName checks if a hostname refers to localhost.
func isLocalhostName(hostname string) bool {
	h := strings.ToLower(hostname)
	return h == "localhost" ||
		h == "localhost.localdomain" ||
		strings.HasSuffix(h, ".localhost")
}
