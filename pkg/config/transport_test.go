package config

import (
	"net/http"
	"testing"
)

type stubRoundTripper struct{}

func (stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

// TestCloneDefaultTransport_NonTransportDefault proves a replaced
// http.DefaultTransport (not an *http.Transport) yields a usable fresh
// Transport rather than a panic.
func TestCloneDefaultTransport_NonTransportDefault(t *testing.T) {
	orig := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = orig })
	http.DefaultTransport = stubRoundTripper{}

	tr := cloneDefaultTransport()
	if tr == nil || tr.Proxy == nil || tr.DialContext == nil {
		t.Fatalf("expected a fully-populated fallback transport, got %+v", tr)
	}
}

func TestCloneDefaultTransport_ClonesDefault(t *testing.T) {
	def, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("default transport replaced")
	}
	tr := cloneDefaultTransport()
	if tr == def {
		t.Fatal("expected a clone, got the shared default")
	}
}
