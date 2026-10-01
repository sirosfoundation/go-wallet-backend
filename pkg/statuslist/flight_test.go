package statuslist

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// slowServer answers every list URI with a valid token after gate is closed,
// counting fetches and the highest number of requests in flight at once.
type slowServer struct {
	srv           *httptest.Server
	gate          chan struct{}
	fetches       atomic.Int32
	inflight, max atomic.Int32
}

func newSlowServer(t *testing.T, mk func(sub string) string) *slowServer {
	s := &slowServer{gate: make(chan struct{})}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fetches.Add(1)
		n := s.inflight.Add(1)
		defer s.inflight.Add(-1)
		for {
			m := s.max.Load()
			if n <= m || s.max.CompareAndSwap(m, n) {
				break
			}
		}
		select {
		case <-s.gate:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", mediaTypeJWT)
		_, _ = w.Write([]byte(mk(s.srv.URL + r.URL.Path)))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestLoad_ConcurrentSameURIFetchesOnce(t *testing.T) {
	key := newKey(t)
	s := newSlowServer(t, func(sub string) string { return makeToken(t, tokenOpts{sub: sub, key: key}) })
	c := NewChecker(s.srv.Client(), false, trustAll)
	ref := &Reference{Idx: 1, URI: s.srv.URL + "/statuslists/1"}

	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { errs <- c.Check(context.Background(), ref) }()
	}
	waitFor(t, "first fetch", func() bool { return s.fetches.Load() >= 1 })
	// Give the other callers time to join the flight before releasing it.
	waitFor(t, "waiters joined", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, f := range c.flights {
			return f.waiters == n
		}
		return false
	})
	close(s.gate)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("check: %v", err)
		}
	}
	if got := s.fetches.Load(); got != 1 {
		t.Fatalf("%d fetches for %d concurrent checks of one URI, want 1", got, n)
	}
}

func TestLoad_GlobalConcurrencyBound(t *testing.T) {
	key := newKey(t)
	s := newSlowServer(t, func(sub string) string { return makeToken(t, tokenOpts{sub: sub, key: key}) })
	const limit, n = 3, 12
	c := NewChecker(s.srv.Client(), false, trustAll).WithMaxConcurrentLoads(limit)

	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		ref := &Reference{Idx: 1, URI: s.srv.URL + "/statuslists/" + string(rune('a'+i))}
		go func() { errs <- c.Check(context.Background(), ref) }()
	}
	waitFor(t, "slots filled", func() bool { return s.inflight.Load() == limit })
	// The rest must be queued, not fetching.
	time.Sleep(50 * time.Millisecond)
	if got := s.inflight.Load(); got != limit {
		t.Fatalf("%d fetches in flight, limit %d", got, limit)
	}
	close(s.gate)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("check: %v", err)
		}
	}
	if m := s.max.Load(); m > limit {
		t.Fatalf("peak %d concurrent fetches, limit %d", m, limit)
	}
	if got := s.fetches.Load(); got != n {
		t.Fatalf("%d fetches, want %d", got, n)
	}
}

func TestLoad_QueuedLoadHonoursContext(t *testing.T) {
	key := newKey(t)
	s := newSlowServer(t, func(sub string) string { return makeToken(t, tokenOpts{sub: sub, key: key}) })
	c := NewChecker(s.srv.Client(), false, trustAll).WithMaxConcurrentLoads(1)

	// Occupy the only slot.
	hold := make(chan error, 1)
	go func() {
		hold <- c.Check(context.Background(), &Reference{Idx: 1, URI: s.srv.URL + "/statuslists/hold"})
	}()
	waitFor(t, "slot held", func() bool { return s.inflight.Load() == 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.Check(ctx, &Reference{Idx: 1, URI: s.srv.URL + "/statuslists/queued"})
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrRevoked) {
		t.Fatalf("queued check = %v, want a deadline error that is not a revocation", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("queued check blocked for %v", time.Since(start))
	}
	close(s.gate)
	if err := <-hold; err != nil {
		t.Fatalf("holder: %v", err)
	}
}

func TestLoad_WaiterCancellationDoesNotPoisonOthers(t *testing.T) {
	key := newKey(t)
	s := newSlowServer(t, func(sub string) string { return makeToken(t, tokenOpts{sub: sub, key: key}) })
	c := NewChecker(s.srv.Client(), false, trustAll)
	ref := &Reference{Idx: 1, URI: s.srv.URL + "/statuslists/1"}

	other := make(chan error, 1)
	go func() { other <- c.Check(context.Background(), ref) }()
	waitFor(t, "flight started", func() bool { return s.fetches.Load() == 1 })

	// The cancelled caller joins the same flight and leaves.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Check(ctx, ref) }()
	waitFor(t, "second waiter", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, f := range c.flights {
			return f.waiters == 2
		}
		return false
	})
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter = %v, want context.Canceled", err)
	}
	close(s.gate)
	if err := <-other; err != nil {
		t.Fatalf("remaining waiter was affected by the other's cancellation: %v", err)
	}
	if got := s.fetches.Load(); got != 1 {
		t.Fatalf("%d fetches, want 1", got)
	}
}

func TestLoad_LastWaiterLeavingCancelsFlight(t *testing.T) {
	key := newKey(t)
	s := newSlowServer(t, func(sub string) string { return makeToken(t, tokenOpts{sub: sub, key: key}) })
	c := NewChecker(s.srv.Client(), false, trustAll)
	ref := &Reference{Idx: 1, URI: s.srv.URL + "/statuslists/1"}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Check(ctx, ref) }()
	waitFor(t, "fetch in flight", func() bool { return s.inflight.Load() == 1 })
	cancel()
	<-done
	waitFor(t, "abandoned fetch cancelled", func() bool { return s.inflight.Load() == 0 })
	waitFor(t, "flight cleared", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return len(c.flights) == 0
	})
	// A later caller starts afresh and succeeds.
	close(s.gate)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); done <- c.Check(context.Background(), ref) }()
	wg.Wait()
	if err := <-done; err != nil {
		t.Fatalf("fresh check after abandonment: %v", err)
	}
}

// An abandoned load that finishes after a newer one must not restore the
// status the newer token superseded.
func TestLoad_OutOfOrderCompletionKeepsNewerStatus(t *testing.T) {
	key := newKey(t)
	var fetch atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub := "https://" + r.Host + r.URL.Path
		var tok string
		if fetch.Add(1) == 1 { // older token: everything VALID
			tok = makeToken(t, tokenOpts{sub: sub, key: key, iat: time.Now().Add(-10 * time.Second)})
		} else { // newer token: index 1 revoked
			tok = makeToken(t, tokenOpts{sub: sub, key: key, iat: time.Now().Add(-time.Second), values: map[int]int{1: 1}})
		}
		w.Header().Set("Content-Type", mediaTypeJWT)
		_, _ = w.Write([]byte(tok))
	}))
	t.Cleanup(srv.Close)

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	slowThenFast := func(context.Context, string, *trust.KeyMaterial) (bool, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release // deliberately ignores the context: a slow signer evaluation
		}
		return true, nil
	}
	c := NewChecker(srv.Client(), false, slowThenFast)
	ref := &Reference{Idx: 1, URI: srv.URL + "/statuslists/1"}

	ctxA, cancelA := context.WithCancel(context.Background())
	aDone := make(chan error, 1)
	go func() { aDone <- c.Check(ctxA, ref) }()
	<-entered
	cancelA()
	<-aDone

	// B starts a fresh flight (A's was abandoned), sees the newer token.
	if err := c.Check(context.Background(), ref); !errors.Is(err, ErrRevoked) {
		t.Fatalf("newer token check = %v, want ErrRevoked", err)
	}
	// Let the older load complete, and wait until it has released its slot.
	close(release)
	waitFor(t, "older load finished", func() bool { return len(c.loadSem) == 0 })

	if err := c.Check(context.Background(), ref); !errors.Is(err, ErrRevoked) {
		t.Fatalf("older load restored stale status: %v", err)
	}
	if got := fetch.Load(); got != 2 {
		t.Fatalf("%d fetches, want 2 (the newer entry must still be cached)", got)
	}
}

// Two revisions issued in the same second tie on iat. An abandoned older
// flight that finishes after the newer one must still not restore the status
// the newer revision superseded.
func TestLoad_OutOfOrderCompletionSameSecondKeepsNewerStatus(t *testing.T) {
	key := newKey(t)
	iat := time.Now().Add(-5 * time.Second).Truncate(time.Second) // shared by both revisions
	var fetch atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub := "https://" + r.Host + r.URL.Path
		var tok string
		if fetch.Add(1) == 1 { // older revision: everything VALID
			tok = makeToken(t, tokenOpts{sub: sub, key: key, iat: iat})
		} else { // newer revision: index 1 revoked
			tok = makeToken(t, tokenOpts{sub: sub, key: key, iat: iat, values: map[int]int{1: 1}})
		}
		w.Header().Set("Content-Type", mediaTypeJWT)
		_, _ = w.Write([]byte(tok))
	}))
	t.Cleanup(srv.Close)

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	slowThenFast := func(context.Context, string, *trust.KeyMaterial) (bool, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release // deliberately ignores the context: a slow signer evaluation
		}
		return true, nil
	}
	c := NewChecker(srv.Client(), false, slowThenFast)
	ref := &Reference{Idx: 1, URI: srv.URL + "/statuslists/1"}

	ctxA, cancelA := context.WithCancel(context.Background())
	aDone := make(chan error, 1)
	go func() { aDone <- c.Check(ctxA, ref) }()
	<-entered
	cancelA()
	<-aDone

	// B starts a fresh flight (A's was abandoned), sees the newer token.
	if err := c.Check(context.Background(), ref); !errors.Is(err, ErrRevoked) {
		t.Fatalf("newer token check = %v, want ErrRevoked", err)
	}
	// Let the older load complete, and wait until it has released its slot.
	close(release)
	waitFor(t, "older load finished", func() bool { return len(c.loadSem) == 0 })

	if err := c.Check(context.Background(), ref); !errors.Is(err, ErrRevoked) {
		t.Fatalf("older load restored stale status: %v", err)
	}
	if got := fetch.Load(); got != 2 {
		t.Fatalf("%d fetches, want 2 (the newer entry must still be cached)", got)
	}
}

func TestStore_SameIatOlderGenerationNeverReplaces(t *testing.T) {
	now := time.Now()
	c := NewChecker(http.DefaultClient, false, trustAll)
	c.now = func() time.Time { return now }
	newer := parsedList{bits: 1, list: []byte{0x02}, expires: now.Add(time.Minute), iat: 100, gen: 2}
	older := parsedList{bits: 1, list: []byte{0x00}, expires: now.Add(time.Hour), iat: 100, gen: 1}
	_, _, _ = c.store("k", newer, nil)
	_, list, _ := c.store("k", older, nil)
	if list[0] != 0x02 || c.cache["k"].gen != 2 {
		t.Fatalf("same-iat older generation replaced the newer: list=%v gen=%d", list, c.cache["k"].gen)
	}
}

func TestStore_NeverReplacesNewerVersion(t *testing.T) {
	now := time.Now()
	c := NewChecker(http.DefaultClient, false, trustAll)
	c.now = func() time.Time { return now }
	newer := parsedList{bits: 1, list: []byte{0x02}, expires: now.Add(time.Minute), iat: 200}
	older := parsedList{bits: 1, list: []byte{0x00}, expires: now.Add(time.Hour), iat: 100}

	if _, _, err := c.store("k", newer, nil); err != nil {
		t.Fatal(err)
	}
	// The older load is answered from the newer entry, which stays cached.
	_, list, _ := c.store("k", older, nil)
	if len(list) != 1 || list[0] != 0x02 {
		t.Fatalf("older load answered with %v, want the newer list", list)
	}
	if got := c.cache["k"]; got.iat != 200 || c.cacheBytes != 1 {
		t.Fatalf("cache entry = iat %d, %d bytes; older replaced the newer", got.iat, c.cacheBytes)
	}
	// Same or newer iat does replace.
	newest := parsedList{bits: 1, list: []byte{0x06}, expires: now.Add(time.Minute), iat: 300}
	_, _, _ = c.store("k", newest, nil)
	if c.cache["k"].iat != 300 {
		t.Fatal("newer version did not replace the cache entry")
	}
	// An expired newer entry is not served to the older load, but is not replaced either.
	now = now.Add(2 * time.Minute)
	_, list, _ = c.store("k", older, nil)
	if list[0] != 0x00 || c.cache["k"].iat != 300 {
		t.Fatalf("older load after expiry: list=%v cached iat=%d", list, c.cache["k"].iat)
	}
}
