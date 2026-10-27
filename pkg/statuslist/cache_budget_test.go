package statuslist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

func budgetEntry(c *Checker) parsedList {
	return parsedList{list: []byte{0, 0}, lst: []byte{0}, iat: 1, expires: c.now().Add(60e9)}
}

// An upstream ETag is charged to the budget, so a list host cannot pad entries
// with it.
func TestCache_UpstreamETagCountsAgainstBudget(t *testing.T) {
	c := newTestChecker(http.DefaultClient, false, nil)
	c.cacheLimit = 1 << 20
	pl := budgetEntry(c)
	pl.upstreamETag = strings.Repeat("e", 2<<20)
	c.store("k", pl, nil)
	if len(c.cache) != 0 || c.cacheBytes != 0 {
		t.Fatalf("entry padded by upstream ETag was cached: entries=%d bytes=%d", len(c.cache), c.cacheBytes)
	}
	pl.upstreamETag = `"abc"`
	c.store("k", pl, nil)
	if len(c.cache) != 1 {
		t.Fatalf("normal entry not cached")
	}
}

// End to end: an oversized ETag from the host is not retained or replayed.
func TestFetch_OversizedETagNotRetained(t *testing.T) {
	key := newKey(t)
	var gotINM []string
	var etag string
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotINM = append(gotINM, r.Header.Get("If-None-Match"))
		w.Header().Set("Content-Type", mediaTypeJWT)
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(makeToken(t, tokenOpts{sub: uri, key: key})))
	}))
	t.Cleanup(srv.Close)
	uri = srv.URL + "/l/1"
	c := newTestChecker(srv.Client(), false, trustAll)

	etag = `"` + strings.Repeat("x", 2<<20) + `"`
	if err := c.Check(context.Background(), &Reference{Idx: 1, URI: uri}); err != nil {
		t.Fatal(err)
	}
	for _, e := range c.cache {
		if e.upstreamETag != "" {
			t.Fatalf("oversized ETag retained (%d bytes)", len(e.upstreamETag))
		}
	}
	if c.cacheBytes > 1<<20 {
		t.Fatalf("cache charged %d bytes for a small list", c.cacheBytes)
	}

	// A normal ETag is kept as before.
	c2 := newTestChecker(srv.Client(), false, trustAll)
	etag = `"v1"`
	if err := c2.Check(context.Background(), &Reference{Idx: 1, URI: uri}); err != nil {
		t.Fatal(err)
	}
	for _, e := range c2.cache {
		if e.upstreamETag != `"v1"` {
			t.Fatalf("normal ETag not retained: %q", e.upstreamETag)
		}
	}
}

func nested(depth int, leaf any) any {
	v := leaf
	for i := 0; i < depth; i++ {
		v = map[string]any{"n": v}
	}
	return v
}

// JWK data nested past the walk's depth limit must not escape the budget.
func TestCache_DeepJWKMemberNotUncounted(t *testing.T) {
	c := newTestChecker(http.DefaultClient, false, nil)
	c.cacheLimit = 1 << 20
	pad := strings.Repeat("A", 2<<20)
	pl := budgetEntry(c)
	pl.km = &trust.KeyMaterial{Type: "jwk", JWK: map[string]any{"kty": "EC", "x-deep": nested(maxJWKDepth+4, pad)}}
	c.store("k", pl, nil)
	if len(c.cache) != 0 || c.cacheBytes != 0 {
		t.Fatalf("over-depth JWK data bypassed the budget: entries=%d bytes=%d", len(c.cache), c.cacheBytes)
	}

	// Even a small over-depth member is refused: it cannot be measured.
	pl.km = &trust.KeyMaterial{Type: "jwk", JWK: map[string]any{"x-deep": nested(maxJWKDepth+4, "a")}}
	c.store("k", pl, nil)
	if len(c.cache) != 0 {
		t.Fatal("unmeasurable JWK was cached")
	}

	// Within the limit it is counted.
	pad = strings.Repeat("A", 2<<20)
	pl.km = &trust.KeyMaterial{Type: "jwk", JWK: map[string]any{"x-deep": nested(maxJWKDepth-2, pad)}}
	c.store("k", pl, nil)
	if len(c.cache) != 0 {
		t.Fatal("padding within the depth limit bypassed the budget")
	}
	pl.km = &trust.KeyMaterial{Type: "jwk", JWK: map[string]any{"kty": "EC", "x": nested(3, "abc")}}
	c.store("k", pl, nil)
	if len(c.cache) != 1 {
		t.Fatal("normal key material not cached")
	}
}

// A JWK value of a type the walk cannot measure is not cached.
func TestCache_UnknownJWKTypeUncacheable(t *testing.T) {
	c := newTestChecker(http.DefaultClient, false, nil)
	pl := budgetEntry(c)
	pl.km = &trust.KeyMaterial{Type: "jwk", JWK: map[string]any{"x": []string{strings.Repeat("A", 2<<20)}}}
	c.store("k", pl, nil)
	if len(c.cache) != 0 {
		t.Fatal("unmeasurable JWK type was cached")
	}
}

// The accounting is exactly the sum of the retained fields plus the key.
func TestCache_AccountingIsSumOfRetainedFields(t *testing.T) {
	c := newTestChecker(http.DefaultClient, false, nil)
	pl := budgetEntry(c)
	pl.subject = "subj"
	pl.etag = `"0123"`
	pl.upstreamETag = `"up-etag"`
	pl.signerAction = "act"
	pl.km = &trust.KeyMaterial{Type: "x5c", CredentialType: "ct", X5C: []string{"AAAA", "BB"},
		JWK: map[string]any{"kty": "EC", "arr": []any{"abc", float64(1)}}}
	want := entryOverhead +
		len(pl.list) + len(pl.lst) + len("subj") + len(pl.etag) + len(pl.upstreamETag) + len("act") +
		len("x5c") + len("ct") + 4 + 2 +
		len("kty") + len("EC") + len("arr") + len("abc") + 8
	if got := pl.size(); got != want {
		t.Fatalf("size = %d, want %d", got, want)
	}
	c.store("key", pl, nil)
	if c.cacheBytes != want+len("key") {
		t.Fatalf("cacheBytes = %d, want %d", c.cacheBytes, want+len("key"))
	}
	// Replacing and dropping return the budget to zero.
	pl.iat = 2
	c.store("key", pl, nil)
	if c.cacheBytes != want+len("key") {
		t.Fatalf("cacheBytes after replace = %d", c.cacheBytes)
	}
	c.mu.Lock()
	c.dropLocked("key")
	c.mu.Unlock()
	if c.cacheBytes != 0 {
		t.Fatalf("cacheBytes after drop = %d", c.cacheBytes)
	}
}

// The cache key (tenant and uri) is charged.
func TestCache_KeyCountsAgainstBudget(t *testing.T) {
	c := newTestChecker(http.DefaultClient, false, nil)
	c.cacheLimit = 1 << 20
	c.store(strings.Repeat("k", 2<<20), budgetEntry(c), nil)
	if len(c.cache) != 0 {
		t.Fatal("entry with an oversized key was cached")
	}
}
