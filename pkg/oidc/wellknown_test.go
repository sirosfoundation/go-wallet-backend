package oidc

import (
	"reflect"
	"testing"
)

func TestCredentialIssuerMetadataURLs(t *testing.T) {
	const w = "/.well-known/openid-credential-issuer"
	for _, tt := range []struct {
		name, in string
		want     []string
		wantErr  bool
	}{
		{"1.1 example: path", "https://issuer.example.com/tenant", []string{"https://issuer.example.com" + w + "/tenant"}, false},
		{"1.1 example: path with terminating slash", "https://issuer.example.com/tenant/",
			[]string{"https://issuer.example.com" + w + "/tenant/", "https://issuer.example.com" + w + "/tenant"}, false},
		{"1.1 example: host only", "https://tenant.issuer.example.com", []string{"https://tenant.issuer.example.com" + w}, false},
		{"OIDF conformance (issue 505)", "https://www.certification.openid.net/test/a/siros-wallet-vci-test-tecca-1/",
			[]string{"https://www.certification.openid.net" + w + "/test/a/siros-wallet-vci-test-tecca-1/", "https://www.certification.openid.net" + w + "/test/a/siros-wallet-vci-test-tecca-1"}, false},
		{"bare root slash", "https://h.example/", []string{"https://h.example" + w + "/", "https://h.example" + w}, false},
		{"nested path", "https://example.com/test/a/alias", []string{"https://example.com" + w + "/test/a/alias"}, false},
		{"percent-encoded path preserved", "https://example.com/path%2Fwith%2Fslashes/issuer",
			[]string{"https://example.com" + w + "/path%2Fwith%2Fslashes/issuer"}, false},
		{"percent-encoded with terminating slash", "https://example.com/a%2Fb/",
			[]string{"https://example.com" + w + "/a%2Fb/", "https://example.com" + w + "/a%2Fb"}, false},
		{"repeated terminating slash: strips one", "https://example.com/t//",
			[]string{"https://example.com" + w + "/t//", "https://example.com" + w + "/t/"}, false},
		{"port", "https://localhost:8443/t", []string{"https://localhost:8443" + w + "/t"}, false},
		{"invalid", "://not-a-url", nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CredentialIssuerMetadataURLs(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v\nwant %v", got, tt.want)
			}
		})
	}
}

// RFC 8414 section 3.1: terminating slash removed, no fallback.
func TestAuthorizationServerMetadataURL(t *testing.T) {
	const w = "/.well-known/oauth-authorization-server"
	for _, tt := range []struct {
		name, in, want string
		wantErr        bool
	}{
		{"path", "https://as.example.com/tenant/1", "https://as.example.com" + w + "/tenant/1", false},
		{"path with terminating slash", "https://as.example.com/tenant/", "https://as.example.com" + w + "/tenant", false},
		{"host only", "https://as.example.com", "https://as.example.com" + w, false},
		{"root slash", "https://as.example.com/", "https://as.example.com" + w, false},
		{"percent-encoded", "https://as.example.com/a%2Fb", "https://as.example.com" + w + "/a%2Fb", false},
		{"repeated slash strips one", "https://as.example.com/t//", "https://as.example.com" + w + "/t/", false},
		{"invalid", "://not-a-url", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AuthorizationServerMetadataURL(tt.in)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("got %q err %v, want %q", got, err, tt.want)
			}
		})
	}
}
