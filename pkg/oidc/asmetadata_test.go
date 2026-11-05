package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchAuthorizationServerMetadata(t *testing.T) {
	const rfc = "/.well-known/oauth-authorization-server"
	const oidcPath = "/.well-known/openid-configuration"
	type route struct {
		status int
		body   func(base string) string
	}
	issuerDoc := func(iss func(base string) string) func(string) string {
		return func(b string) string { return `{"issuer":"` + iss(b) + `"}` }
	}
	self := func(b string) string { return b }

	for _, tt := range []struct {
		name      string
		suffix    string
		routes    map[string]route
		wantErr   error
		wantStat  int
		wantPaths []string
	}{
		{"RFC 8414 form", "", map[string]route{rfc: {200, issuerDoc(self)}}, nil, 0, []string{rfc}},
		{"path identifier", "/t/1", map[string]route{rfc + "/t/1": {200, issuerDoc(self)}}, nil, 0, []string{rfc + "/t/1"}},
		{"only openid-configuration", "", map[string]route{oidcPath: {200, issuerDoc(self)}}, nil, 0, []string{rfc, oidcPath}},
		{"only openid-configuration, path", "/t/1/", map[string]route{"/t/1" + oidcPath: {200, issuerDoc(self)}}, nil, 0, []string{rfc + "/t/1", "/t/1" + oidcPath}},
		{"all 404", "", nil, ErrASMetadataNotFound, 0, []string{rfc, oidcPath}},
		{"5xx no fallback", "", map[string]route{rfc: {503, issuerDoc(self)}, oidcPath: {200, issuerDoc(self)}}, nil, 503, []string{rfc}},
		{"401 no fallback", "", map[string]route{rfc: {401, issuerDoc(self)}, oidcPath: {200, issuerDoc(self)}}, nil, 401, []string{rfc}},
		{"410 no fallback", "", map[string]route{rfc: {410, issuerDoc(self)}, oidcPath: {200, issuerDoc(self)}}, nil, 410, []string{rfc}},
		{"mismatch RFC form", "", map[string]route{rfc: {200, issuerDoc(func(string) string { return "https://evil.example" })}, oidcPath: {200, issuerDoc(self)}}, ErrASIssuerMismatch, 0, []string{rfc}},
		{"mismatch OIDC form", "", map[string]route{oidcPath: {200, issuerDoc(func(b string) string { return b + "/" })}}, ErrASIssuerMismatch, 0, []string{rfc, oidcPath}},
		{"uppercase Issuer only", "", map[string]route{rfc: {200, func(b string) string { return `{"Issuer":"` + b + `"}` }}}, ErrASIssuerMismatch, 0, []string{rfc}},
		{"lowercase wrong, uppercase right", "", map[string]route{rfc: {200, func(b string) string { return `{"issuer":"https://other.example","Issuer":"` + b + `"}` }}}, ErrASIssuerMismatch, 0, []string{rfc}},
		{"issuer not a string", "", map[string]route{rfc: {200, func(string) string { return `{"issuer":1}` }}}, ErrASIssuerMismatch, 0, []string{rfc}},
		{"not JSON", "", map[string]route{rfc: {200, func(string) string { return "nope" }}}, ErrASMetadataInvalid, 0, []string{rfc}},
		{"too large", "", map[string]route{rfc: {200, func(b string) string { return `{"issuer":"` + b + `","x":"` + strings.Repeat("a", 4096) + `"}` }}}, ErrASMetadataInvalid, 0, []string{rfc}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var paths []string
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.EscapedPath())
				rt, ok := tt.routes[r.URL.EscapedPath()]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(rt.status)
				_, _ = w.Write([]byte(rt.body(srv.URL + tt.suffix)))
			}))
			defer srv.Close()

			body, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL+tt.suffix, 1024)
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err %v, want %v", err, tt.wantErr)
				}
			case tt.wantStat != 0:
				var se *ASMetadataStatusError
				if !errors.As(err, &se) || se.Status != tt.wantStat {
					t.Fatalf("err %v, want status %d", err, tt.wantStat)
				}
			default:
				if err != nil || len(body) == 0 {
					t.Fatalf("err %v body %q", err, body)
				}
			}
			if strings.Join(paths, ",") != strings.Join(tt.wantPaths, ",") {
				t.Errorf("requests %q, want %q", paths, tt.wantPaths)
			}
		})
	}
}

func TestValidateAuthorizationServerIdentifier(t *testing.T) {
	for _, tt := range []struct {
		in string
		ok bool
	}{
		{"https://as.example.com", true},
		{"https://as.example.com/tenant/1/", true},
		{"https://as.example.com:8443/t", true},
		{"http://localhost:8080", true}, // plain http is the client's policy
		{"", false},
		{"as.example.com", false},
		{"ftp://as.example.com", false},
		{"file:///etc/passwd", false},
		{"javascript:alert(1)", false},
		{"https://", false},
		{"https:///path", false},
		{"https://user:pw@as.example.com", false},
		{"https://user@as.example.com", false},
		{"https://as.example.com/t?x=1", false},
		{"https://as.example.com/t?", false},
		{"https://as.example.com/t#frag", false},
		{"https://as.example.com/t#", false},
		{"://bad", false},
	} {
		err := ValidateAuthorizationServerIdentifier(tt.in)
		if (err == nil) != tt.ok {
			t.Errorf("%q: err %v, want ok=%v", tt.in, err, tt.ok)
		}
	}
}

// Rejected identifiers must not cause any request.
func TestFetchAuthorizationServerMetadata_InvalidIdentifierNoRequest(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	for _, id := range []string{"ftp://x", srv.URL + "?a=b", srv.URL + "#f", "http://u:p@" + strings.TrimPrefix(srv.URL, "http://")} {
		if _, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), id, 1024); !errors.Is(err, ErrASIdentifierInvalid) {
			t.Errorf("%q: err %v", id, err)
		}
	}
	if hits != 0 {
		t.Errorf("%d requests made", hits)
	}
}

// A redirect to a non-http(s) URL or one with userinfo is refused, and the
// target is not requested.
func TestFetchAuthorizationServerMetadata_RedirectGuard(t *testing.T) {
	for _, loc := range []string{"ftp://as.example.com/x", "http://u:p@127.0.0.1:1/x", "file:///etc/passwd"} {
		t.Run(loc, func(t *testing.T) {
			hits := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				http.Redirect(w, r, loc, http.StatusFound)
			}))
			defer srv.Close()
			if _, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL, 1024); err == nil {
				t.Fatal("redirect followed")
			}
			if hits != 1 {
				t.Errorf("%d requests, want 1", hits)
			}
		})
	}
	t.Run("redirect loop is bounded", func(t *testing.T) {
		hits := 0
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits++
			http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
		}))
		defer srv.Close()
		if _, err := FetchAuthorizationServerMetadata(context.Background(), srv.Client(), srv.URL, 1024); err == nil {
			t.Fatal("expected error")
		}
		if hits > maxASRedirects+1 {
			t.Errorf("%d requests", hits)
		}
	})
}
