package issuermetadata

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newCacheToggleResolver(t *testing.T, disabled bool) *Resolver {
	t.Helper()
	r, err := New(Config{
		HTTPClient:    testHTTPClient(),
		CacheTTL:      5 * time.Minute,
		AllowHTTP:     true,
		MetadataType:  MetadataTypeAny,
		CacheDisabled: disabled,
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return r
}

// changingServer serves metadata whose "version" member can be changed
// between requests; it counts the requests it receives.
func changingServer(t *testing.T) (srv *httptest.Server, setVersion func(string), calls *atomic.Int32) {
	t.Helper()
	var version atomic.Value
	version.Store("v1")
	calls = new(atomic.Int32)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"credential_issuer": "http://" + r.Host,
			"version":           version.Load().(string),
		})
	}))
	t.Cleanup(srv.Close)
	return srv, func(v string) { version.Store(v) }, calls
}

func TestResolve_CacheToggle_ChangedMetadata(t *testing.T) {
	for _, tc := range []struct {
		name     string
		disabled bool
		want     string
	}{
		{"cache on serves stale metadata within TTL", false, "v1"},
		{"cache off sees changed metadata", true, "v2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, setVersion, _ := changingServer(t)
			r := newCacheToggleResolver(t, tc.disabled)
			first, err := r.Resolve(context.Background(), srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if first["version"] != "v1" {
				t.Fatalf("first version = %v", first["version"])
			}
			setVersion("v2")
			second, err := r.Resolve(context.Background(), srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			if second["version"] != tc.want {
				t.Errorf("second version = %v, want %s", second["version"], tc.want)
			}
		})
	}
}

// With the cache off, concurrent resolves of the same identifier are still
// coalesced by singleflight into one upstream request.
func TestResolve_CacheDisabled_ConcurrentCoalesced(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{}, 16)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		started <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"credential_issuer": "http://" + r.Host}) //nolint:errcheck
	}))
	defer srv.Close()

	r := newCacheToggleResolver(t, true)
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Resolve(context.Background(), srv.URL)
			errs <- err
		}()
	}
	<-started
	time.Sleep(300 * time.Millisecond) // let the other callers join the in-flight call
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("expected 1 upstream request for %d concurrent resolves, got %d", n, got)
	}
}

// The option-C fallback (404 on the literal form, then the 1.1 form) works
// with the cache off, on every resolve.
func TestResolve_CacheDisabled_404Fallback(t *testing.T) {
	cs := newCandidateServer(t)
	id := cs.URL + "/tenant/"
	cs.status[wk+"/tenant/"] = 404
	cs.claim[wk+"/tenant"] = id

	r := newCacheToggleResolver(t, true)
	for i := 0; i < 2; i++ {
		res, err := r.ResolveWithInfo(context.Background(), id)
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		if res.Cached {
			t.Errorf("resolve %d served from cache", i)
		}
	}
	if len(cs.paths) != 4 {
		t.Errorf("requests = %v, want 4 (two candidates per resolve)", cs.paths)
	}
}
