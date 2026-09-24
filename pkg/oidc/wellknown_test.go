package oidc

import "testing"

func TestWellKnownURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		suffix  string
		want    string
		wantErr bool
	}{
		{
			name:    "no path",
			baseURL: "https://example.com",
			suffix:  "openid-credential-issuer",
			want:    "https://example.com/.well-known/openid-credential-issuer",
		},
		{
			name:    "with path",
			baseURL: "https://example.com/test/a/alias",
			suffix:  "openid-credential-issuer",
			want:    "https://example.com/.well-known/openid-credential-issuer/test/a/alias",
		},
		{
			name:    "trailing slash preserved",
			baseURL: "https://example.com/issuer/",
			suffix:  "openid-credential-issuer",
			want:    "https://example.com/.well-known/openid-credential-issuer/issuer/",
		},
		{
			name:    "oauth authorization server",
			baseURL: "https://as.example.com/tenant/1",
			suffix:  "oauth-authorization-server",
			want:    "https://as.example.com/.well-known/oauth-authorization-server/tenant/1",
		},
		{
			name:    "openid-configuration",
			baseURL: "https://idp.example.com",
			suffix:  "openid-configuration",
			want:    "https://idp.example.com/.well-known/openid-configuration",
		},
		{
			name:    "percent-encoded path preserved",
			baseURL: "https://example.com/path%2Fwith%2Fslashes/issuer",
			suffix:  "openid-credential-issuer",
			want:    "https://example.com/.well-known/openid-credential-issuer/path%2Fwith%2Fslashes/issuer",
		},
		{
			name:    "with port",
			baseURL: "https://localhost:8443/test/a/siros-wallet",
			suffix:  "openid-credential-issuer",
			want:    "https://localhost:8443/.well-known/openid-credential-issuer/test/a/siros-wallet",
		},
		{
			name:    "invalid URL",
			baseURL: "://not-a-url",
			suffix:  "openid-credential-issuer",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WellKnownURL(tt.baseURL, tt.suffix)
			if (err != nil) != tt.wantErr {
				t.Errorf("WellKnownURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("WellKnownURL()\n  got  = %s\n  want = %s", got, tt.want)
			}
		})
	}
}

func TestNormalizeIssuerURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no path, no slash", "https://issuer.example.com", "https://issuer.example.com"},
		{"no path, trailing slash", "https://issuer.example.com/", "https://issuer.example.com"},
		{"meaningful path, no trailing slash", "https://issuer.example.com/tenant", "https://issuer.example.com/tenant"},
		{"meaningful path, trailing slash preserved", "https://issuer.example.com/tenant/", "https://issuer.example.com/tenant/"},
		{"invalid URL returned unchanged", "://not-a-url", "://not-a-url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeIssuerURL(tt.in)
			if got != tt.want {
				t.Errorf("NormalizeIssuerURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
