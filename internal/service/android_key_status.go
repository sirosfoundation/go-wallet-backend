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

// AttestationStatusFetcher fetches the revocation list document. maxAge is
// the freshness the server granted (Cache-Control max-age), negative when the
// response did not say. Injectable so tests need no network.
type AttestationStatusFetcher interface {
	Fetch(ctx context.Context) (body []byte, maxAge time.Duration, err error)
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

func (f *httpStatusFetcher) Fetch(ctx context.Context) ([]byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("status list: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAndroidStatusBytes+1))
	if err != nil {
		return nil, 0, err
	}
	if len(body) > maxAndroidStatusBytes {
		return nil, 0, errors.New("status list too large")
	}
	return body, cacheControlMaxAge(resp.Header.Get("Cache-Control")), nil
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

// androidStatusList is a cached, fail-closed view of Google's revocation list.
// A list is used only while fresh; when it has expired and cannot be
// refreshed every check fails with ErrAndroidStatusUnavailable. It never
// serves a stale list.
type androidStatusList struct {
	fetcher    AttestationStatusFetcher
	defaultTTL time.Duration
	now        func() time.Time

	mu      sync.Mutex
	revoked map[string]struct{}
	expires time.Time
	loaded  bool
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

// refreshLocked loads a fresh list. Caller holds mu.
func (l *androidStatusList) refreshLocked(ctx context.Context) error {
	body, maxAge, err := l.fetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAndroidStatusUnavailable, err)
	}
	set, err := parseAndroidStatusList(body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAndroidStatusUnavailable, err)
	}
	ttl := maxAge
	if ttl < 0 {
		ttl = l.defaultTTL
	}
	l.revoked = set
	l.expires = l.now().Add(ttl)
	l.loaded = true
	return nil
}

// check returns the first serial of serials on the list (revoked is true),
// or ErrAndroidStatusUnavailable when no fresh list is available.
func (l *androidStatusList) check(ctx context.Context, serials []*big.Int) (revokedSerial string, revoked bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.loaded || !l.now().Before(l.expires) {
		l.loaded = false
		l.revoked = nil
		if err := l.refreshLocked(ctx); err != nil {
			return "", false, err
		}
	}
	for _, s := range serials {
		if _, ok := l.revoked[serialKey(s)]; ok {
			return serialKey(s), true, nil
		}
	}
	return "", false, nil
}
