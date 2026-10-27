package metadata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A bare trailing slash on the issuer URL must not change the well-known URI
// (RFC 8615): both spellings of a root issuer fetch the same path.
func TestFetchIssuerMetadata_RootSlashSamePath(t *testing.T) {
	for _, suffix := range []string{"", "/"} {
		var gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}))
		if _, err := fetchIssuerMetadata(context.Background(), srv.URL+suffix, srv.Client()); err != nil {
			t.Fatalf("suffix %q: %v", suffix, err)
		}
		srv.Close()
		if want := "/.well-known/openid-credential-issuer"; gotPath != want {
			t.Errorf("suffix %q: fetched %q, want %q", suffix, gotPath, want)
		}
	}
}

// An issuer with a path keeps it, trailing slash included, after the well-known
// segment.
func TestFetchIssuerMetadata_PathIssuerKeepsPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if _, err := fetchIssuerMetadata(context.Background(), srv.URL+"/tenant", srv.Client()); err != nil {
		t.Fatal(err)
	}
	if want := "/.well-known/openid-credential-issuer/tenant"; gotPath != want {
		t.Errorf("fetched %q, want %q", gotPath, want)
	}
}
