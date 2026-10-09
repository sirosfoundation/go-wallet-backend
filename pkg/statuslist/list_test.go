package statuslist

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// condServer is a status list host with a controllable ETag/304 behaviour.
type condServer struct {
	mu           sync.Mutex
	token        string // body for a 200
	etag         string // upstream ETag ("" = none)
	cacheControl string
	hits         int
	conditional  int      // requests carrying If-None-Match
	ifNoneMatch  []string // values seen
	allow304     bool
}

func (s *condServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits++
	inm := r.Header.Get("If-None-Match")
	if inm != "" {
		s.conditional++
		s.ifNoneMatch = append(s.ifNoneMatch, inm)
	}
	if s.cacheControl != "" {
		w.Header().Set("Cache-Control", s.cacheControl)
	}
	if s.etag != "" {
		w.Header().Set("ETag", s.etag)
	}
	if s.allow304 && inm != "" && inm == s.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", mediaTypeJWT)
	_, _ = w.Write([]byte(s.token))
}

func newCondServer(t *testing.T) (*condServer, *Checker, string, *time.Time) {
	t.Helper()
	cs := &condServer{allow304: true}
	srv := httptest.NewTLSServer(http.HandlerFunc(cs.handler))
	t.Cleanup(srv.Close)
	uri := srv.URL + "/lists/1"
	clock := testEpoch
	c := newTestChecker(srv.Client(), false, trustAll)
	c.now = func() time.Time { return clock }
	return cs, c, uri, &clock
}

func TestList_ReturnsOriginalLstAndMetadata(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()
	cs, c, uri, _ := newCondServer(t)
	exp := testEpoch.Add(30 * time.Minute)
	tok := makeToken(t, tokenOpts{sub: uri, key: key, bits: 2, exp: exp, values: map[int]int{3: 1}})
	cs.token = tok

	c.WithSignerTrustAction(func(context.Context, string, *trust.KeyMaterial) (bool, string, error) {
		return true, "status-list-signer", nil
	})
	vl, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	// lst must be byte-identical to the signed token's lst.
	var claims struct {
		StatusList struct {
			Lst string `json:"lst"`
		} `json:"status_list"`
	}
	if err := decodeSegment(strings.Split(tok, ".")[1], &claims); err != nil {
		t.Fatal(err)
	}
	want, err := base64.RawURLEncoding.DecodeString(claims.StatusList.Lst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(vl.Lst, want) {
		t.Fatalf("Lst differs from the signed token's lst")
	}
	if vl.Bits != 2 || !vl.IssuedAt.Equal(testEpoch) || vl.ExpiresAt == nil || !vl.ExpiresAt.Equal(exp) || vl.TTL != 0 {
		t.Fatalf("metadata = %+v", vl)
	}
	if vl.SignerAction != "status-list-signer" {
		t.Fatalf("SignerAction = %q", vl.SignerAction)
	}
	if !strings.HasPrefix(vl.ETag, `"`) || !strings.HasSuffix(vl.ETag, `"`) || len(vl.ETag) < 10 {
		t.Fatalf("ETag = %q, want a quoted hash", vl.ETag)
	}
	// Served from cache: same ETag, no refetch.
	vl2, err := c.List(ctx, uri)
	if err != nil || vl2.ETag != vl.ETag || cs.hits != 1 {
		t.Fatalf("second List: %v etag=%q hits=%d", err, vl2.ETag, cs.hits)
	}
}

func TestList_ETagStableAcrossRefetchAndChangesWithToken(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()
	cs, c, uri, clock := newCondServer(t)
	cs.token = makeToken(t, tokenOpts{sub: uri, key: key, values: map[int]int{3: 1}})
	a, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	// Re-signed token with the same content/iat (ECDSA signatures differ): same ETag.
	cs.token = makeToken(t, tokenOpts{sub: uri, key: key, values: map[int]int{3: 1}})
	*clock = clock.Add(10 * time.Minute)
	b, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if cs.hits != 2 || a.ETag != b.ETag {
		t.Fatalf("hits=%d etags %q %q: a refetch of an unchanged list must keep its ETag", cs.hits, a.ETag, b.ETag)
	}
	// Different content: different ETag.
	cs.token = makeToken(t, tokenOpts{sub: uri, key: key, values: map[int]int{3: 1, 9: 1}, iat: testEpoch.Add(11 * time.Minute)})
	*clock = clock.Add(10 * time.Minute)
	d, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if d.ETag == a.ETag {
		t.Fatal("ETag did not change with the list content")
	}
}

// A re-signed list with the same iat but different content must get a new
// ETag, or a client holding the old version would be told "not modified".
func TestList_ETagCoversTheListContent(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()
	cs, c, uri, clock := newCondServer(t)
	cs.token = makeToken(t, tokenOpts{sub: uri, key: key, values: map[int]int{3: 1}})
	a, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	cs.token = makeToken(t, tokenOpts{sub: uri, key: key, values: map[int]int{3: 1, 9: 1}})
	*clock = clock.Add(10 * time.Minute)
	b, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if a.ETag == b.ETag || bytes.Equal(a.Lst, b.Lst) {
		t.Fatalf("same iat, different list: etags %q / %q", a.ETag, b.ETag)
	}
}

// A newer version that cannot be cached must not leave the superseded one to
// be served as fresh.
func TestStore_UncacheableNewerVersionDropsOlder(t *testing.T) {
	now := testEpoch
	c := newTestChecker(http.DefaultClient, false, trustAll)
	c.now = func() time.Time { return now }
	older := parsedList{bits: 1, list: []byte{0x00}, expires: now.Add(time.Hour), iat: 100}
	newer := parsedList{bits: 1, list: []byte{0x02}, expires: now.Add(-time.Second), iat: 200} // already past its deadline
	c.store("k", older, nil)
	if got := c.store("k", newer, nil); got.list[0] != 0x02 {
		t.Fatalf("store returned %v, want the newer list", got.list)
	}
	if _, ok := c.cache["k"]; ok || c.cacheBytes != 0 {
		t.Fatalf("the superseded entry is still cached (%d bytes)", c.cacheBytes)
	}
}

func TestList_ConditionalGetRefreshesOn304(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()
	cs, c, uri, clock := newCondServer(t)
	cs.etag = `"up-1"`
	cs.token = makeToken(t, tokenOpts{sub: uri, key: key, exp: testEpoch.Add(40 * time.Minute), values: map[int]int{3: 1}})

	first, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if cs.conditional != 0 {
		t.Fatal("the first request must not be conditional")
	}
	// Past the 5 minute default freshness: the refresh is conditional.
	*clock = clock.Add(6 * time.Minute)
	second, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if cs.hits != 2 || cs.conditional != 1 || cs.ifNoneMatch[0] != `"up-1"` {
		t.Fatalf("hits=%d conditional=%d inm=%v, want one If-None-Match: \"up-1\"", cs.hits, cs.conditional, cs.ifNoneMatch)
	}
	if second.ETag != first.ETag || !bytes.Equal(second.Lst, first.Lst) || second.Bits != first.Bits {
		t.Fatal("a 304 must return the cached list unchanged")
	}
	if !second.FreshUntil.After(*clock) {
		t.Fatalf("304 did not refresh the entry: fresh until %v, now %v", second.FreshUntil, *clock)
	}
	// Refreshed: within the new window there is no further request.
	*clock = clock.Add(time.Minute)
	if _, err := c.List(ctx, uri); err != nil || cs.hits != 2 {
		t.Fatalf("refreshed entry refetched: err=%v hits=%d", err, cs.hits)
	}
}

func TestList_304HonoursMaxAgeAndCaps(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()
	cs, c, uri, clock := newCondServer(t)
	cs.etag = `"e"`
	cs.token = makeToken(t, tokenOpts{sub: uri, key: key, values: map[int]int{3: 1}})
	if _, err := c.List(ctx, uri); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(6 * time.Minute)
	cs.cacheControl = "private, max-age=30"
	vl, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if got := vl.FreshUntil.Sub(*clock); got != 30*time.Second {
		t.Fatalf("freshness after 304 = %v, want the max-age 30s", got)
	}
	// An absurd max-age is still capped at one hour.
	*clock = clock.Add(time.Minute)
	cs.cacheControl = "max-age=999999999"
	vl, err = c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if got := vl.FreshUntil.Sub(*clock); got != maxCacheTTL {
		t.Fatalf("freshness = %v, want the %v cap", got, maxCacheTTL)
	}
}

func TestList_304WindowFromTTLIsCappedByOneHourAndExp(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()

	t.Run("one hour cap", func(t *testing.T) {
		cs, c, uri, clock := newCondServer(t)
		cs.etag = `"e"`
		cs.token = makeToken(t, tokenOpts{sub: uri, key: key, ttl: 7200, values: map[int]int{3: 1}})
		if _, err := c.List(ctx, uri); err != nil {
			t.Fatal(err)
		}
		*clock = clock.Add(61 * time.Minute)
		vl, err := c.List(ctx, uri)
		if err != nil || cs.conditional != 1 {
			t.Fatalf("err=%v conditional=%d", err, cs.conditional)
		}
		if got := vl.FreshUntil.Sub(*clock); got != maxCacheTTL {
			t.Fatalf("freshness after 304 = %v, want the token ttl (2h) capped at %v", got, maxCacheTTL)
		}
	})

	t.Run("token exp cap", func(t *testing.T) {
		cs, c, uri, clock := newCondServer(t)
		cs.etag = `"e"`
		exp := testEpoch.Add(70 * time.Minute)
		cs.token = makeToken(t, tokenOpts{sub: uri, key: key, ttl: 7200, exp: exp, values: map[int]int{3: 1}})
		if _, err := c.List(ctx, uri); err != nil {
			t.Fatal(err)
		}
		*clock = clock.Add(61 * time.Minute)
		vl, err := c.List(ctx, uri)
		if err != nil || cs.conditional != 1 {
			t.Fatalf("err=%v conditional=%d", err, cs.conditional)
		}
		if !vl.FreshUntil.Equal(exp) {
			t.Fatalf("fresh until %v, want the token exp %v", vl.FreshUntil, exp)
		}
	})
}

func TestList_304ReevaluatesSignerAndExp(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()

	t.Run("signer distrusted meanwhile", func(t *testing.T) {
		cs, c, uri, clock := newCondServer(t)
		cs.etag = `"e"`
		cs.token = makeToken(t, tokenOpts{sub: uri, key: key, values: map[int]int{3: 1}})
		trusted := true
		c.trust = func(context.Context, string, *trust.KeyMaterial) (bool, error) { return trusted, nil }
		if _, err := c.List(ctx, uri); err != nil {
			t.Fatal(err)
		}
		trusted = false
		*clock = clock.Add(6 * time.Minute)
		if _, err := c.List(ctx, uri); !errors.Is(err, ErrSignerUntrusted) {
			t.Fatalf("err = %v, want ErrSignerUntrusted: a 304 must not extend a withdrawn trust decision", err)
		}
		// The entry was dropped: the next request is not conditional.
		before := cs.conditional
		_, _ = c.List(ctx, uri)
		if cs.conditional != before {
			t.Fatal("the dropped entry's ETag was reused")
		}
	})

	t.Run("token expired meanwhile", func(t *testing.T) {
		cs, c, uri, clock := newCondServer(t)
		cs.etag = `"e"`
		cs.token = makeToken(t, tokenOpts{sub: uri, key: key, exp: testEpoch.Add(7 * time.Minute), values: map[int]int{3: 1}})
		if _, err := c.List(ctx, uri); err != nil {
			t.Fatal(err)
		}
		*clock = clock.Add(8 * time.Minute)
		_, err := c.List(ctx, uri)
		if err == nil || Classify(err) != ReasonExpired {
			t.Fatalf("err = %v (%s), want expired: a 304 must not outlive the token's exp", err, Classify(err))
		}
	})
}

func TestList_Unconditional304IsAFetchFailure(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	c := newTestChecker(srv.Client(), false, trustAll)
	_, err := c.List(ctx, srv.URL+"/l")
	if Classify(err) != ReasonFetchFailed {
		t.Fatalf("err = %v (%s), want fetch_failed", err, Classify(err))
	}
}

func TestList_MaxAgeShortensFreshness(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()
	cs, c, uri, clock := newCondServer(t)
	cs.cacheControl = "max-age=20"
	cs.token = makeToken(t, tokenOpts{sub: uri, key: key, values: map[int]int{3: 1}})
	if _, err := c.List(ctx, uri); err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(10 * time.Second)
	if _, err := c.List(ctx, uri); err != nil || cs.hits != 1 {
		t.Fatalf("within max-age: err=%v hits=%d", err, cs.hits)
	}
	*clock = clock.Add(11 * time.Second)
	if _, err := c.List(ctx, uri); err != nil || cs.hits != 2 {
		t.Fatalf("past max-age the list must be refetched: err=%v hits=%d", err, cs.hits)
	}
	// max-age never lengthens the token-derived window.
	cs.cacheControl = "max-age=3000"
	*clock = clock.Add(time.Hour)
	vl, err := c.List(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	if got := vl.FreshUntil.Sub(*clock); got != defaultCacheTTL {
		t.Fatalf("freshness = %v, want the token-derived %v", got, defaultCacheTTL)
	}
}

func TestMaxAgeOf(t *testing.T) {
	d := func(s int) *time.Duration { v := time.Duration(s) * time.Second; return &v }
	for in, want := range map[string]*time.Duration{
		"":                      nil,
		"public":                nil,
		"max-age=60":            d(60),
		"private, max-age=60":   d(60),
		`max-age="60"`:          d(60),
		"max-age=abc":           nil,
		"max-age=-5":            nil,
		"no-store":              d(0),
		"no-cache, max-age=600": d(0),
		"MAX-AGE=5":             d(5),
		"max-age=99999999999":   d(3600),
	} {
		got := maxAgeOf(in)
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("maxAgeOf(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want Reason
	}{
		{nil, ""},
		{ErrSignerUntrusted, ReasonSignerUntrusted},
		{ErrTrustUnavailable, ReasonTrustUnavailable},
		{ErrNoSignerKey, ReasonNoSignerKey},
		{context.DeadlineExceeded, ReasonBudgetExhausted},
		{context.Canceled, ReasonBudgetExhausted},
		{classify(ReasonFetchFailed, context.DeadlineExceeded), ReasonBudgetExhausted},
		{classify(ReasonExpired, errors.New("x")), ReasonExpired},
		{errors.New("anything else"), ReasonMalformed},
	} {
		if got := Classify(tc.err); got != tc.want {
			t.Errorf("Classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestList_Reasons drives every loader-side reason through the real path.
func TestList_Reasons(t *testing.T) {
	key := newKey(t)
	ctx := context.Background()
	future := testEpoch.Add(time.Hour)

	serveRaw := func(t *testing.T, status int, ctype string, body []byte) (*Checker, string) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ctype != "" {
				w.Header().Set("Content-Type", ctype)
			}
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}))
		t.Cleanup(srv.Close)
		return newTestChecker(srv.Client(), false, trustAll), srv.URL + "/l"
	}
	tokenFor := func(t *testing.T, mk func(uri string) string) (*Checker, string) {
		var uri string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", mediaTypeJWT)
			_, _ = w.Write([]byte(mk(uri)))
		}))
		t.Cleanup(srv.Close)
		uri = srv.URL + "/l"
		return newTestChecker(srv.Client(), false, trustAll), uri
	}

	cases := map[Reason]func(t *testing.T) (*Checker, string){
		ReasonFetchFailed: func(t *testing.T) (*Checker, string) { return serveRaw(t, 500, mediaTypeJWT, nil) },
		ReasonUnsupportedMediaType: func(t *testing.T) (*Checker, string) {
			return serveRaw(t, 200, "text/html", []byte("x"))
		},
		ReasonTooLarge: func(t *testing.T) (*Checker, string) {
			return serveRaw(t, 200, mediaTypeJWT, bytes.Repeat([]byte("a"), maxTokenBytes+1))
		},
		ReasonMalformed: func(t *testing.T) (*Checker, string) { return serveRaw(t, 200, mediaTypeJWT, []byte("not a jwt")) },
		ReasonSignatureInvalid: func(t *testing.T) (*Checker, string) {
			return tokenFor(t, func(u string) string {
				tok := makeToken(t, tokenOpts{sub: u, key: key, exp: future})
				p := strings.Split(tok, ".")
				// Swap in a different payload; the signature no longer matches.
				other := makeToken(t, tokenOpts{sub: u, key: key, exp: future, values: map[int]int{1: 1}})
				return p[0] + "." + strings.Split(other, ".")[1] + "." + p[2]
			})
		},
		ReasonExpired: func(t *testing.T) (*Checker, string) {
			return tokenFor(t, func(u string) string {
				return makeToken(t, tokenOpts{sub: u, key: key, exp: testEpoch.Add(-time.Minute), iat: testEpoch.Add(-time.Hour)})
			})
		},
		ReasonNotYetValid: func(t *testing.T) (*Checker, string) {
			return tokenFor(t, func(u string) string { return makeToken(t, tokenOpts{sub: u, key: key, nbf: testEpoch.Add(time.Hour)}) })
		},
		ReasonNoSignerKey: func(t *testing.T) (*Checker, string) {
			return tokenFor(t, func(u string) string {
				claims := jwt.MapClaims{"sub": u, "iat": testEpoch.Unix(), "status_list": map[string]any{"bits": 1, "lst": packList(t, 1, nil, 64)}}
				tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
				tok.Header["typ"] = "statuslist+jwt"
				s, err := tok.SignedString(key)
				if err != nil {
					t.Fatal(err)
				}
				return s
			})
		},
		ReasonListTooSmall: func(t *testing.T) (*Checker, string) {
			c, u := tokenFor(t, func(u string) string { return makeToken(t, tokenOpts{sub: u, key: key}) })
			return c.WithMinEntries(1 << 20), u
		},
		ReasonSignerUntrusted: func(t *testing.T) (*Checker, string) {
			c, u := tokenFor(t, func(u string) string { return makeToken(t, tokenOpts{sub: u, key: key}) })
			c.trust = func(context.Context, string, *trust.KeyMaterial) (bool, error) { return false, nil }
			return c, u
		},
		ReasonTrustUnavailable: func(t *testing.T) (*Checker, string) {
			c, u := tokenFor(t, func(u string) string { return makeToken(t, tokenOpts{sub: u, key: key}) })
			c.trust = func(context.Context, string, *trust.KeyMaterial) (bool, error) { return false, errors.New("pdp down") }
			return c, u
		},
		ReasonURINotAllowed: func(t *testing.T) (*Checker, string) {
			c := newTestChecker(http.DefaultClient, false, trustAll)
			return c, "http://status.example/l"
		},
		ReasonBudgetExhausted: func(t *testing.T) (*Checker, string) {
			block := make(chan struct{})
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
			t.Cleanup(func() { close(block); srv.Close() })
			return newTestChecker(srv.Client(), false, trustAll), srv.URL + "/l"
		},
	}
	for want, setup := range cases {
		t.Run(string(want), func(t *testing.T) {
			c, uri := setup(t)
			cctx := ctx
			if want == ReasonBudgetExhausted {
				var cancel context.CancelFunc
				cctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			vl, err := c.List(cctx, uri)
			if err == nil || vl != nil {
				t.Fatalf("List = %+v, %v; want an error and no list", vl, err)
			}
			if got := Classify(err); got != want {
				t.Fatalf("Classify = %q (%v), want %q", got, err, want)
			}
		})
	}
}
