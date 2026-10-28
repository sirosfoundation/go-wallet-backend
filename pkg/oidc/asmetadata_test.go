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
