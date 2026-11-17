package statuslist

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/config"
)

// Every spelling of an internal host must be refused before a connection is
// made, by the URL check or the guarded client. Each host is tried on the port
// of a live loopback server, which records any request that gets through.
func TestFetch_RefusesInternalHostSpellings(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	for _, host := range []string{
		"127.0.0.1", "[::1]", "[::ffff:127.0.0.1]", "[fe80::1%25eth0]", "0x7f.0.0.1", "2130706433",
		"0177.0.0.1", "127.1", "0.0.0.0", "localhost", "localhost.", "10.0.0.1", "100.64.0.1",
		"169.254.169.254", "100.100.100.200", "[64:ff9b::7f00:1]", "user:pw@127.0.0.1", "user@localhost",
		"%31%32%37.0.0.1",
	} {
		t.Run(host, func(t *testing.T) {
			c := newTestChecker((config.HTTPClientConfig{}).NewHTTPClient(0), false, trustAll)
			for _, uri := range []string{"https://" + host + "/l", "https://" + host + ":" + port + "/l"} {
				if _, err := c.fetch(context.Background(), uri, ""); err == nil {
					t.Errorf("%s: fetch succeeded", uri)
				}
			}
			// Plain http is refused too, even for the loopback server itself.
			if _, err := c.fetch(context.Background(), "http://"+host+":"+port+"/l", ""); err == nil {
				t.Errorf("http://%s: fetch succeeded", host)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d request(s) reached the loopback server", n)
	}
}

func TestValidateFetchURI(t *testing.T) {
	c := newTestChecker(http.DefaultClient, false, trustAll)
	for _, ok := range []string{"https://status.example/l", "https://status.example:8443/l?x=1#f", "https://[2001:db8::1]/l", "https://xn--bcher-kva.example/l"} {
		if _, err := c.validateFetchURI(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://status.example/l", "ftp://status.example/l", "//status.example/l", "status.example/l",
		"https:///l", "https://user@status.example/l", "https://:pw@status.example/l",
		"https://[fe80::1%25eth0]/l", "https://status.example:99999999999/l", "https://stat us.example/l",
	} {
		if _, err := c.validateFetchURI(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	h := newTestChecker(http.DefaultClient, true, trustAll)
	if _, err := h.validateFetchURI("http://status.example/l"); err != nil {
		t.Errorf("http refused with allowHTTP: %v", err)
	}
}
