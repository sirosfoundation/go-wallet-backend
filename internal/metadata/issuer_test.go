package metadata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// Candidate order for a root identifier: the 1.0 literal form (path "/") first,
// the 1.1 draft form second, only on 404. A host-only identifier has one.
func TestFetchIssuerMetadata_RootSlashCandidates(t *testing.T) {
	for _, tc := range []struct {
		suffix string
		want   []string
	}{
		{"", []string{"/.well-known/openid-credential-issuer"}},
		{"/", []string{"/.well-known/openid-credential-issuer/", "/.well-known/openid-credential-issuer"}},
	} {
		var got []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = append(got, r.URL.Path)
			if r.URL.Path != "/.well-known/openid-credential-issuer" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}))
		if _, err := fetchIssuerMetadata(context.Background(), srv.URL+tc.suffix, srv.Client()); err != nil {
			t.Fatalf("suffix %q: %v", tc.suffix, err)
		}
		srv.Close()
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("suffix %q: requests %v, want %v", tc.suffix, got, tc.want)
		}
	}
}

// An issuer with a path keeps that path after the well-known segment, with a
// terminating slash kept in the first (1.0 literal) request. RFC 8615 only
// defines the /.well-known/ namespace; the insertion rule is OpenID4VCI's.
func TestFetchIssuerMetadata_PathIssuerKeepsPath(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	if _, err := fetchIssuerMetadata(context.Background(), srv.URL+"/tenant/", srv.Client()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/.well-known/openid-credential-issuer/tenant/"}; !reflect.DeepEqual(got, want) {
		t.Errorf("requests %v, want %v", got, want)
	}
}

// 5xx on the first candidate is not retried against the second.
func TestFetchIssuerMetadata_NoFallbackOn5xx(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := fetchIssuerMetadata(context.Background(), srv.URL+"/tenant/", srv.Client()); err == nil || n != 1 {
		t.Fatalf("err=%v requests=%d", err, n)
	}
}
