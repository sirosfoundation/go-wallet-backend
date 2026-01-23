package middleware

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestProxyFilter_IsAllowed_RequireHTTPS(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.RequireHTTPS = true
	pf := NewProxyFilter(cfg, logger)

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"https allowed", "https://example.com/api", false},
		{"http blocked when HTTPS required", "http://example.com/api", true},
		{"https with path", "https://example.com/path/to/resource", false},
		{"https with query", "https://example.com/api?foo=bar", false},
		{"https with port", "https://example.com:8443/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.IsAllowed(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestProxyFilter_IsAllowed_HTTPAllowed(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.RequireHTTPS = false // Allow HTTP for testing
	pf := NewProxyFilter(cfg, logger)

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"http allowed when not required", "http://example.com/api", false},
		{"https still works", "https://example.com/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.IsAllowed(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestProxyFilter_IsAllowed_BlockedHosts(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.RequireHTTPS = false // Disable to test other checks
	pf := NewProxyFilter(cfg, logger)

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"google metadata blocked", "http://metadata.google.internal/api", true},
		{"169.254.169.254 blocked (link-local)", "http://169.254.169.254/any/path", true},
		{"normal host allowed", "http://example.com/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.IsAllowed(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestProxyFilter_IsAllowed_LinkLocal(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.RequireHTTPS = false
	cfg.BlockLinkLocal = true
	pf := NewProxyFilter(cfg, logger)

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"169.254.169.254 blocked (cloud metadata)", "http://169.254.169.254/any/path", true},
		{"169.254.1.1 blocked (link-local)", "http://169.254.1.1/api", true},
		{"normal IP allowed", "http://8.8.8.8/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.IsAllowed(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestProxyFilter_IsAllowed_Loopback(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.RequireHTTPS = false
	cfg.BlockLoopback = true
	pf := NewProxyFilter(cfg, logger)

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"localhost blocked", "http://localhost/admin", true},
		{"localhost.localdomain blocked", "http://localhost.localdomain/admin", true},
		{"sub.localhost blocked", "http://app.localhost/admin", true},
		{"127.0.0.1 blocked", "http://127.0.0.1/admin", true},
		{"127.0.0.2 blocked (loopback range)", "http://127.0.0.2/admin", true},
		{"external host allowed", "http://example.com/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.IsAllowed(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestProxyFilter_IsAllowed_RFC1918(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.RequireHTTPS = false
	cfg.BlockRFC1918 = true
	pf := NewProxyFilter(cfg, logger)

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"10.x blocked", "http://10.0.0.1/api", true},
		{"10.255.x blocked", "http://10.255.255.255/api", true},
		{"172.16.x blocked", "http://172.16.0.1/api", true},
		{"172.31.x blocked", "http://172.31.255.255/api", true},
		{"172.15.x allowed (not RFC1918)", "http://172.15.0.1/api", false},
		{"172.32.x allowed (not RFC1918)", "http://172.32.0.1/api", false},
		{"192.168.x blocked", "http://192.168.1.1/api", true},
		{"192.167.x allowed (not RFC1918)", "http://192.167.1.1/api", false},
		{"public IP allowed", "http://8.8.8.8/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.IsAllowed(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestProxyFilter_IsAllowed_InvalidURLs(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.RequireHTTPS = false
	pf := NewProxyFilter(cfg, logger)

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"ftp blocked", "ftp://ftp.example.com/file", true},
		{"file blocked", "file:///etc/passwd", true},
		{"empty host", "http:///path", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pf.IsAllowed(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestProxyFilter_IsAllowed_Disabled(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.Enabled = false
	pf := NewProxyFilter(cfg, logger)

	// Even blocked URLs should pass when disabled
	err := pf.IsAllowed("http://localhost/admin")
	if err != nil {
		t.Errorf("Expected nil error when filter disabled, got %v", err)
	}
}

func TestProxyFilter_SeenHosts(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.SeenHostsTTL = time.Hour
	cfg.MaxSeenHosts = 10
	pf := NewProxyFilter(cfg, logger)

	// Initially not seen
	if pf.IsHostSeen("example.com") {
		t.Error("Host should not be seen initially")
	}

	// Mark as seen
	pf.MarkHostSeen("https://example.com/api")

	// Now should be seen
	if !pf.IsHostSeen("example.com") {
		t.Error("Host should be seen after marking")
	}

	// Check with different port - same host
	if !pf.IsHostSeen("example.com:443") {
		t.Error("Host with port should also be seen")
	}

	// Get all seen hosts
	hosts := pf.GetSeenHosts()
	if len(hosts) != 1 || hosts[0] != "example.com" {
		t.Errorf("GetSeenHosts() = %v, want [example.com]", hosts)
	}
}

func TestProxyFilter_SeenHosts_MaxSize(t *testing.T) {
	logger := zap.NewNop()
	cfg := DefaultProxyFilterConfig()
	cfg.SeenHostsTTL = time.Hour
	cfg.MaxSeenHosts = 3
	pf := NewProxyFilter(cfg, logger)

	// Add 3 hosts
	pf.MarkHostSeen("https://host1.com/")
	time.Sleep(10 * time.Millisecond)
	pf.MarkHostSeen("https://host2.com/")
	time.Sleep(10 * time.Millisecond)
	pf.MarkHostSeen("https://host3.com/")

	if len(pf.GetSeenHosts()) != 3 {
		t.Errorf("Expected 3 seen hosts, got %d", len(pf.GetSeenHosts()))
	}

	// Add a 4th host - should evict oldest (host1)
	time.Sleep(10 * time.Millisecond)
	pf.MarkHostSeen("https://host4.com/")

	hosts := pf.GetSeenHosts()
	if len(hosts) != 3 {
		t.Errorf("Expected 3 seen hosts after eviction, got %d", len(hosts))
	}

	if pf.IsHostSeen("host1.com") {
		t.Error("host1.com should have been evicted")
	}

	if !pf.IsHostSeen("host4.com") {
		t.Error("host4.com should be seen")
	}
}

func TestIsRFC1918(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		// 10.0.0.0/8
		{"10.0.0.0", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},

		// 172.16.0.0/12
		{"172.16.0.0", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.15.255.255", false}, // Just below range
		{"172.32.0.0", false},     // Just above range

		// 192.168.0.0/16
		{"192.168.0.0", true},
		{"192.168.1.1", true},
		{"192.168.255.255", true},
		{"192.167.255.255", false}, // Just below range
		{"192.169.0.0", false},     // Just above range

		// Public IPs
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := isRFC1918(ip)
			if result != tt.expected {
				t.Errorf("isRFC1918(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"example.com:443", "example.com"},
		{"example.com:8080", "example.com"},
		{"EXAMPLE.COM:443", "example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeHost(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeHost(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
