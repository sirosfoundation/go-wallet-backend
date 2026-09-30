package server

import (
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

func TestNewR2PSClient(t *testing.T) {
	cfg := &config.Config{}
	if c, err := newR2PSClient(cfg); c != nil || err != nil {
		t.Fatalf("unconfigured: want (nil, nil), got (%v, %v)", c, err)
	}

	cfg.R2PSAdmin.BaseURL = "https://r2ps.example.org"
	if c, err := newR2PSClient(cfg); c == nil || err != nil {
		t.Fatalf("https: want client, got (%v, %v)", c, err)
	}

	cfg.R2PSAdmin.BaseURL = "http://r2ps:8444"
	if c, err := newR2PSClient(cfg); c != nil || err == nil {
		t.Fatalf("plaintext without allow: want error, got (%v, %v)", c, err)
	}

	cfg.HTTPClient.AllowHTTP = true
	if c, err := newR2PSClient(cfg); c == nil || err != nil {
		t.Fatalf("plaintext with allow_http: want client, got (%v, %v)", c, err)
	}

	cfg.R2PSAdmin.BaseURL = "not a url"
	if _, err := newR2PSClient(cfg); err == nil {
		t.Fatal("invalid URL: want error")
	}
}
