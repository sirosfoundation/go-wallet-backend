package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultAndroidAttestationStatusURL is Google's attestation revocation list.
const DefaultAndroidAttestationStatusURL = "https://android.googleapis.com/attestation/status"

const (
	// maxAndroidStatusBytes bounds the revocation list we will read.
	maxAndroidStatusBytes = 16 << 20
	// maxAndroidStatusTTL caps how long a list is trusted whatever the
	// server says.
	maxAndroidStatusTTL = 24 * time.Hour
)

// ErrAndroidStatusUnavailable means there is no fresh revocation list.
var ErrAndroidStatusUnavailable = errors.New("android attestation status list unavailable")

// StatusFreshness is what a response says about how long it may be reused.
type StatusFreshness struct {
	// MaxAge is the Cache-Control max-age: negative when the response did not
	// say, zero for no-store/no-cache (use it for this check only).
	MaxAge time.Duration
	// Age is how old the response already was when it was received (the Age
	// header and the Date header, as RFC 9111 combines them): a copy served
	// by an intermediary cache is older than the moment we fetched it.
	Age time.Duration
}

// AttestationStatusFetcher fetches the revocation list document and what it
// says about its freshness. Injectable so tests need no network.
type AttestationStatusFetcher interface {
	Fetch(ctx context.Context) (body []byte, fresh StatusFreshness, err error)
}

// httpStatusFetcher fetches the list over HTTP.
type httpStatusFetcher struct {
	client *http.Client
	url    string
}

// NewHTTPAttestationStatusFetcher returns a fetcher for url using client (use
// config.HTTPClientConfig.NewHTTPClient so the outbound address policy
// applies).
func NewHTTPAttestationStatusFetcher(client *http.Client, url string) AttestationStatusFetcher {
	return &httpStatusFetcher{client: client, url: url}
}

func (f *httpStatusFetcher) Fetch(ctx context.Context) ([]byte, StatusFreshness, error) {
	none := StatusFreshness{MaxAge: -1}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, none, err
	}
	req.Header.Set("Accept", "application/json")
	sent := time.Now()
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, none, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, none, fmt.Errorf("status list: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAndroidStatusBytes+1))
	if err != nil {
		return nil, none, err
	}
	if len(body) > maxAndroidStatusBytes {
		return nil, none, errors.New("status list too large")
	}
	// The response is complete only now: a slow body counts against its life.
	received := time.Now()
	return body, StatusFreshness{
		MaxAge: cacheControlMaxAge(strings.Join(resp.Header.Values("Cache-Control"), ",")),
		Age:    initialAge(resp.Header, sent, received),
	}, nil
}

// initialAge is RFC 9111 section 4.2.3: the larger of the apparent age (how
// far the Date header lies behind our receipt time) and the Age header plus
// the time the request took.
func initialAge(h http.Header, sent, received time.Time) time.Duration {
	var apparent time.Duration
	if d, err := http.ParseTime(h.Get("Date")); err == nil {
		if a := received.Sub(d); a > 0 {
			apparent = a
		}
	}
	var corrected time.Duration
	// Repeated Age lines: the oldest counts.
	for _, v := range h.Values("Age") {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && n >= 0 {
			if n > int64(maxAndroidStatusTTL/time.Second) {
				n = int64(maxAndroidStatusTTL / time.Second)
			}
			corrected = max(corrected, time.Duration(n)*time.Second+received.Sub(sent))
		}
	}
	return max(apparent, corrected)
}

// cacheControlMaxAge returns the max-age of a Cache-Control header, zero for
// no-store/no-cache (do not reuse), negative when it says nothing usable.
func cacheControlMaxAge(h string) time.Duration {
	maxAge := time.Duration(-1)
	for _, d := range strings.Split(h, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "no-store" || d == "no-cache":
			return 0
		case strings.HasPrefix(d, "max-age="):
			n, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(d, "max-age="), `"`), 10, 64)
			if err == nil && n >= 0 {
				if n > int64(maxAndroidStatusTTL/time.Second) {
					n = int64(maxAndroidStatusTTL / time.Second)
				}
				maxAge = time.Duration(n) * time.Second
			}
		}
	}
	return maxAge
}

// androidStatusFetchTimeout bounds one refresh, whatever the callers' contexts.
const androidStatusFetchTimeout = 15 * time.Second

// androidStatusRetryBackoff is how long a failed refresh is remembered: during
// an outage callers get the failure at once instead of each paying a timeout.
// The list is still never used while unfresh.
const androidStatusRetryBackoff = 5 * time.Second

// ErrAndroidStatusStale means the response was already past its max-age when
// it arrived (an intermediary cache served an old copy).
var ErrAndroidStatusStale = errors.New("android attestation status list response is already stale")

// androidStatusList is a cached, fail-closed view of Google's revocation list.
// A list is used only while fresh; when it has expired and cannot be
// refreshed every check fails with ErrAndroidStatusUnavailable. It never
// serves a stale list. One refresh runs at a time and its result, including a
// failure, is shared by every caller waiting for it; waiting honours the
// caller's context.
type androidStatusList struct {
	fetcher    AttestationStatusFetcher
	defaultTTL time.Duration
	now        func() time.Time

	mu       sync.Mutex
	revoked  map[string]struct{}
	expires  time.Time
	loaded   bool
	inflight *statusRefresh
	failedAt time.Time
	failErr  error
}

// statusRefresh is one in-flight refresh. Its outcome is what every caller
// that waited for it uses, even for a response that may not be cached
// (no-cache): it was fetched after they asked.
type statusRefresh struct {
	done chan struct{}
	set  map[string]struct{}
	err  error
}

func newAndroidStatusList(f AttestationStatusFetcher, defaultTTL time.Duration) *androidStatusList {
	if defaultTTL <= 0 {
		defaultTTL = time.Hour
	}
	if defaultTTL > maxAndroidStatusTTL {
		defaultTTL = maxAndroidStatusTTL
	}
	return &androidStatusList{fetcher: f, defaultTTL: defaultTTL, now: time.Now}
}

// normalizeSerialHex renders a certificate serial the way the list keys it:
// lowercase hex without leading zeros.
func normalizeSerialHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

func serialKey(n *big.Int) string { return normalizeSerialHex(n.Text(16)) }

// parseAndroidStatusList reads {"entries": {"<serial hex>": {"status": ...}}}.
// Every listed serial is treated as not good, whatever its status or reason
// (REVOKED, SUSPENDED, or a status added later).
func parseAndroidStatusList(body []byte) (map[string]struct{}, error) {
	var doc struct {
		Entries map[string]json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("status list: %w", err)
	}
	if doc.Entries == nil {
		return nil, errors.New("status list: no entries object")
	}
	out := make(map[string]struct{}, len(doc.Entries))
	for k := range doc.Entries {
		out[normalizeSerialHex(k)] = struct{}{}
	}
	return out, nil
}

// fetchAndStore runs one refresh (detached from any caller's context, bounded
// by androidStatusFetchTimeout) and caches the list when its freshness allows.
func (l *androidStatusList) fetchAndStore(ctx context.Context) (map[string]struct{}, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), androidStatusFetchTimeout)
	defer cancel()
	body, fresh, err := l.fetcher.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAndroidStatusUnavailable, err)
	}
	set, err := parseAndroidStatusList(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAndroidStatusUnavailable, err)
	}
	lifetime := fresh.MaxAge
	if lifetime < 0 {
		lifetime = l.defaultTTL
	}
	if lifetime == 0 {
		return set, nil // no-cache/no-store: for the callers of this refresh only
	}
	// A copy that was already old when it reached us has less life left; one
	// that is past its life is not evidence of anything current.
	remaining := lifetime - fresh.Age
	if remaining <= 0 {
		return nil, fmt.Errorf("%w: %w", ErrAndroidStatusUnavailable, ErrAndroidStatusStale)
	}
	l.mu.Lock()
	l.revoked = set
	l.expires = l.now().Add(remaining)
	l.loaded = true
	l.mu.Unlock()
	return set, nil
}

func (l *androidStatusList) freshLocked() bool { return l.loaded && l.now().Before(l.expires) }

// check returns the first serial of serials on the list (revoked is true),
// or ErrAndroidStatusUnavailable when no fresh list is available.
func (l *androidStatusList) check(ctx context.Context, serials []*big.Int) (revokedSerial string, revoked bool, err error) {
	l.mu.Lock()
	if l.freshLocked() {
		defer l.mu.Unlock()
		s, r := lookupSerials(l.revoked, serials)
		return s, r, nil
	}
	l.loaded, l.revoked = false, nil
	if l.failErr != nil && l.now().Before(l.failedAt.Add(androidStatusRetryBackoff)) {
		err := l.failErr
		l.mu.Unlock()
		return "", false, err
	}
	r := l.inflight
	if r == nil {
		r = &statusRefresh{done: make(chan struct{})}
		l.inflight = r
		go func() {
			set, ferr := l.fetchAndStore(ctx)
			l.mu.Lock()
			r.set, r.err = set, ferr
			if ferr != nil {
				l.failedAt, l.failErr = l.now(), ferr
			} else {
				l.failErr = nil
			}
			l.inflight = nil
			l.mu.Unlock()
			close(r.done)
		}()
	}
	l.mu.Unlock()

	select {
	case <-r.done:
	case <-ctx.Done():
		return "", false, fmt.Errorf("%w: %v", ErrAndroidStatusUnavailable, ctx.Err())
	}
	if r.err != nil {
		return "", false, r.err
	}
	s, rev := lookupSerials(r.set, serials)
	return s, rev, nil
}

func lookupSerials(set map[string]struct{}, serials []*big.Int) (string, bool) {
	for _, s := range serials {
		if _, ok := set[serialKey(s)]; ok {
			return serialKey(s), true
		}
	}
	return "", false
}
