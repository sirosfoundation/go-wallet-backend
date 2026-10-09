package statuslist

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/net/idna"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// Size limits on the fetched token and the inflated bit string.
const (
	maxTokenBytes   = 4 << 20
	maxInflateBytes = 32 << 20

	// defaultCacheTTL applies when the token has neither ttl nor a nearer exp.
	defaultCacheTTL = 5 * time.Minute
	// maxCacheTTL caps any freshness window so a revocation is never hidden longer.
	maxCacheTTL = time.Hour
	// maxTTLSeconds bounds a ttl claim before the Duration conversion (no overflow).
	maxTTLSeconds = 1 << 31
	// The cache is reset when it exceeds maxCacheEntries or maxCacheBytes
	// (inflated list bytes).
	maxCacheEntries = 256
	maxCacheBytes   = 64 << 20

	// DefaultMaxConcurrentLoads bounds concurrent fetch-and-inflate loads; each
	// may hold up to 36 MiB, so the default caps in-flight memory near 290 MiB.
	DefaultMaxConcurrentLoads = 8
	// flightTimeout is the backstop for one shared load.
	flightTimeout = 2 * time.Minute

	statusListTokenTyp = "statuslist+jwt"
	mediaTypeJWT       = "application/statuslist+jwt"
	mediaTypeCWT       = "application/statuslist+cwt"
)

// errKeyMismatch: the header carries both x5c and jwk, and they differ.
var errKeyMismatch = errors.New("status list header jwk does not match the x5c leaf key")

var (
	// ErrSignerUntrusted: the signature verified but the signer key was judged untrusted.
	ErrSignerUntrusted = errors.New("status list signer is not trusted")
	// ErrTrustUnavailable: no trust decision could be obtained (no PDP, or evaluation failed).
	ErrTrustUnavailable = errors.New("status list signer trust could not be evaluated")
	// ErrNoSignerKey: the header has neither x5c nor jwk (a kid alone is not resolvable).
	ErrNoSignerKey = errors.New("status list carries no signer key material (x5c or jwk header)")
)

// SignerTrust reports whether the key that signed a status list may publish
// status lists. subject is the list's iss claim, else its URI's origin; km is
// the x5c chain or jwk from the list header. (false, nil) is a negative
// decision; an error means no decision. The Checker acts on a list only on
// (true, nil).
type SignerTrust func(ctx context.Context, subject string, km *trust.KeyMaterial) (trusted bool, err error)

// SignerTrustAction is a SignerTrust that also reports the trust action that
// accepted the signer (e.g. "status-list-signer"); action is meaningful only
// when trusted is true.
type SignerTrustAction func(ctx context.Context, subject string, km *trust.KeyMaterial) (trusted bool, action string, err error)

// Reference is the `status.status_list` claim of a credential
// (draft-ietf-oauth-status-list §6.2).
type Reference struct {
	Idx int64  `json:"idx"`
	URI string `json:"uri"`
}

// ErrRevoked is wrapped by the error Check returns ONLY when a verified list
// has a non-VALID (non-zero) entry at the credential's index. Every other
// Check error means "could not determine" and must not be read as revocation.
var ErrRevoked = errors.New("credential status is not valid")

// ReferenceFromCredentialClaims extracts the status_list reference from a
// decoded credential payload. present reports whether the credential uses
// Token Status List. A non-empty `status` without a `status_list` member uses
// another mechanism and is present=false (unknown members are ignored). A
// null, non-object or empty `status`, or an unreadable `status_list`, returns
// present=true with an error so callers fail closed.
func ReferenceFromCredentialClaims(claims map[string]any) (ref *Reference, present bool, err error) {
	raw, ok := claims["status"]
	if !ok {
		return nil, false, nil
	}
	if raw == nil {
		return nil, true, errors.New("status claim is null")
	}
	status, ok := raw.(map[string]any)
	if !ok {
		return nil, true, errors.New("status claim is not an object")
	}
	rawList, ok := status["status_list"]
	if !ok {
		if len(status) == 0 {
			return nil, true, errors.New("status claim is an empty object")
		}
		// Another status mechanism only; unknown members are ignored.
		return nil, false, nil
	}
	m, ok := rawList.(map[string]any)
	if !ok {
		return nil, true, errors.New("status_list reference is not an object")
	}
	idx, ok := m["idx"].(float64)
	uri, _ := m["uri"].(string)
	if !ok || idx != float64(int64(idx)) {
		return nil, true, errors.New("status_list reference needs an integer idx and a uri")
	}
	r := Reference{Idx: int64(idx), URI: uri}
	if r.Idx < 0 || r.URI == "" {
		return nil, true, errors.New("status_list reference needs a non-negative idx and a uri")
	}
	return &r, true, nil
}

// Checker fetches, verifies and caches Token Status List tokens and answers
// whether a credential's entry is VALID.
type Checker struct {
	client *http.Client
	trust  SignerTrust
	// trustAction, when set, replaces trust (WithSignerTrustAction).
	trustAction SignerTrustAction
	// allowHTTP permits a plain-http status list URI (development only).
	allowHTTP bool
	now       func() time.Time
	// minEntries is the smallest accepted list (see WithMinEntries); 0 disables.
	minEntries int

	mu         sync.Mutex
	cache      map[string]cachedList
	cacheBytes int
	// cacheLimit is maxCacheBytes; a field so tests can shrink it.
	cacheLimit int

	// flights are the loads in progress by cache key (guarded by mu);
	// loadSem bounds how many run at once.
	flights map[string]*flight
	nextGen uint64 // last flight generation handed out (guarded by mu)
	loadSem chan struct{}
}

// flight is one shared fetch-and-verify; res and err are written before done
// is closed and read only after.
type flight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int // guarded by Checker.mu
	// gen orders flights: a later flight for the same key has a larger gen.
	gen uint64
	// abandoned is set (under Checker.mu) when the last waiter left; the result
	// must not be cached.
	abandoned bool
	res       parsedList
	err       error
}

// parsedList is a verified, trust-evaluated status list. iat orders versions
// of a list; iat is second-granular, so gen (the fetching flight's generation)
// breaks ties.
type parsedList struct {
	bits    int
	list    []byte
	expires time.Time
	iat     int64
	gen     uint64

	// lst is the original compressed `lst`, byte-identical to what was signed.
	lst []byte
	// exp and ttl are the token's claims (nil when absent).
	exp, ttl *int64
	// signerAction is the trust action that accepted the signer.
	signerAction string
	// etag is a stable hash of the uri and token version (iat, bits, lst).
	etag string
	// upstreamETag is the list host's ETag, for If-None-Match.
	upstreamETag string
	// subject and km are kept so a 304 refresh re-evaluates the signer.
	subject string
	km      *trust.KeyMaterial
}

// size is what the entry costs against the cache byte limit.
func (p parsedList) size() int { return len(p.list) + len(p.lst) }

type cachedList = parsedList

// NewChecker returns a Checker that fetches through client, which must be the
// SSRF-guarded client (HTTPClientConfig.NewHTTPClient). With a nil signerTrust
// no list is authoritative and every Check is undetermined.
func NewChecker(client *http.Client, allowHTTP bool, signerTrust SignerTrust) *Checker {
	return &Checker{client: client, trust: signerTrust, allowHTTP: allowHTTP, now: time.Now, cache: map[string]cachedList{}, cacheLimit: maxCacheBytes,
		flights: map[string]*flight{}, loadSem: make(chan struct{}, DefaultMaxConcurrentLoads)}
}

// WithSignerTrustAction makes the Checker use fn instead of the SignerTrust
// given to NewChecker. Call it before the Checker is shared.
func (c *Checker) WithSignerTrustAction(fn SignerTrustAction) *Checker {
	c.trustAction = fn
	return c
}

// WithMinEntries makes the Checker reject a list with fewer than n entries
// once inflated, before the signer is consulted; n <= 0 (default) disables it.
// The draft sets no receiver-side minimum (§12.1, §13.4 leave sizing to the
// issuer), so this is an opt-in policy. Call it before the Checker is shared.
func (c *Checker) WithMinEntries(n int) *Checker {
	if n < 0 {
		n = 0
	}
	c.minEntries = n
	return c
}

// WithMaxConcurrentLoads bounds concurrent fetch-and-inflate loads; further
// loads wait for a slot, honouring their context. n <= 0 selects
// DefaultMaxConcurrentLoads. Call it before the Checker is shared.
func (c *Checker) WithMaxConcurrentLoads(n int) *Checker {
	if n <= 0 {
		n = DefaultMaxConcurrentLoads
	}
	c.loadSem = make(chan struct{}, n)
	return c
}

// Check returns nil only if the entry at ref is VALID in a list that was
// fetched, whose signature verifies against its own x5c/jwk key, whose signer
// the trust service accepts, and that matches ref.URI and is fresh. Only such a
// list can yield an error wrapping ErrRevoked. Every other failure does not
// wrap ErrRevoked; an untrusted signer wraps ErrSignerUntrusted and an
// unobtainable decision ErrTrustUnavailable.
func (c *Checker) Check(ctx context.Context, ref *Reference) error {
	pl, err := c.load(ctx, ref.URI)
	if err != nil {
		return err
	}
	value, err := entry(pl.bits, pl.list, ref.Idx)
	if err != nil {
		return err
	}
	if value != 0 {
		return fmt.Errorf("%w: status value %d", ErrRevoked, value)
	}
	return nil
}

// VerifiedList is a Token Status List that passed the same checks as Check.
// It carries public data only; Lst is shared with the cache and read-only.
type VerifiedList struct {
	// Bits is the number of bits per entry (1, 2, 4 or 8).
	Bits int
	// Lst is the original zlib-compressed `lst`, byte-identical to what was signed.
	Lst []byte
	// IssuedAt is the token's iat.
	IssuedAt time.Time
	// ExpiresAt is the token's exp claim; nil when the token has none.
	ExpiresAt *time.Time
	// TTL is the token's ttl claim; 0 when the token has none.
	TTL time.Duration
	// FreshUntil is the ttl/exp/max-age derived deadline, at most one hour ahead.
	FreshUntil time.Time
	// SignerAction is the accepting trust action; empty without a SignerTrustAction.
	SignerAction string
	// ETag is a quoted, stable hash of the uri and token version.
	ETag string
}

// List returns the verified list at uri, from the cache when fresh, applying
// the same checks as Check; a list that fails is an error (see Classify) and
// no data. uri must be the exact string a credential carries.
func (c *Checker) List(ctx context.Context, uri string) (*VerifiedList, error) {
	pl, err := c.load(ctx, uri)
	if err != nil {
		return nil, err
	}
	vl := &VerifiedList{
		Bits: pl.bits, Lst: pl.lst, IssuedAt: time.Unix(pl.iat, 0).UTC(),
		FreshUntil: pl.expires, SignerAction: pl.signerAction, ETag: pl.etag,
	}
	if pl.exp != nil {
		t := time.Unix(*pl.exp, 0).UTC()
		vl.ExpiresAt = &t
	}
	if pl.ttl != nil && *pl.ttl > 0 {
		secs := *pl.ttl
		if secs > maxTTLSeconds {
			secs = maxTTLSeconds
		}
		vl.TTL = time.Duration(secs) * time.Second
	}
	return vl, nil
}

// load returns the status list for uri. Concurrent callers for the same
// (tenant, uri) share one fetch-and-verify (a flight) and the number of
// flights is bounded, since the cache limit does not bound in-flight memory.
// Each waiter honours its own ctx (its error never wraps ErrRevoked); the
// flight is cancelled only when its last waiter has left.
func (c *Checker) load(ctx context.Context, uri string) (parsedList, error) {
	// Trust is tenant-scoped, so entries are keyed by tenant. The key uses the
	// EXACT uri, not a canonical form: sub is bound to the exact uri string
	// only at load time (draft §5.1/5.2), so an entry is reusable only for the
	// uri it was validated against.
	key := trust.TenantFromContext(ctx) + "\x00" + uri
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e, nil
	}
	f, ok := c.flights[key]
	if !ok {
		// The flight keeps ctx's values (tenant) but not its cancellation.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), flightTimeout)
		c.nextGen++
		f = &flight{done: make(chan struct{}), cancel: cancel, gen: c.nextGen}
		c.flights[key] = f
		go c.runFlight(fctx, key, uri, f)
	}
	f.waiters++
	c.mu.Unlock()

	select {
	case <-f.done:
		return f.res, f.err
	case <-ctx.Done():
		c.mu.Lock()
		f.waiters--
		if f.waiters == 0 {
			// Nobody is left: stop the work; a later caller starts afresh.
			if c.flights[key] == f {
				delete(c.flights, key)
			}
			f.abandoned = true
			f.cancel()
		}
		c.mu.Unlock()
		return parsedList{}, fmt.Errorf("status list load: %w", ctx.Err())
	}
}

// runFlight performs one load and publishes the outcome to its waiters.
func (c *Checker) runFlight(ctx context.Context, key, uri string, f *flight) {
	defer f.cancel()
	f.res, f.err = c.loadOnce(ctx, key, uri, f)
	c.mu.Lock()
	if c.flights[key] == f {
		delete(c.flights, key)
	}
	c.mu.Unlock()
	close(f.done)
}

// loadOnce fetches, verifies and caches one list under a load slot. An expired
// entry with an upstream ETag makes the fetch conditional; a 304 refreshes it.
func (c *Checker) loadOnce(ctx context.Context, key, uri string, f *flight) (parsedList, error) {
	select {
	case c.loadSem <- struct{}{}:
		defer func() { <-c.loadSem }()
	case <-ctx.Done():
		return parsedList{}, fmt.Errorf("waiting for a status list load slot: %w", ctx.Err())
	}
	var stale *parsedList
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && e.upstreamETag != "" && e.km != nil {
		stale = &e
	}
	c.mu.Unlock()
	etag := ""
	if stale != nil {
		etag = stale.upstreamETag
	}
	res, err := c.fetch(ctx, uri, etag)
	if err != nil {
		return parsedList{}, err
	}
	if res.notModified {
		pl, err := c.refresh(ctx, *stale, res)
		if err != nil {
			// The entry can no longer be vouched for.
			c.mu.Lock()
			c.dropLocked(key)
			c.mu.Unlock()
			return parsedList{}, err
		}
		return c.store(key, pl, f), nil
	}
	var pl parsedList
	switch res.mediaType {
	case mediaTypeJWT, "":
		// A missing Content-Type is read as JWT; a CWT body then fails to parse.
		pl, err = c.parseJWT(ctx, strings.TrimSpace(string(res.body)), uri)
	case mediaTypeCWT:
		pl, err = c.parseCWT(ctx, res.body, uri)
	default:
		err = classify(ReasonUnsupportedMediaType, fmt.Errorf("status list has unsupported media type %q", res.mediaType))
	}
	if err != nil {
		return parsedList{}, err
	}
	pl.upstreamETag = res.etag
	// A shorter upstream max-age wins; it never lengthens freshness.
	if res.maxAge != nil {
		if limit := c.now().Add(*res.maxAge); limit.Before(pl.expires) {
			pl.expires = limit
		}
	}
	return c.store(key, pl, f), nil
}

// refresh turns a 304 into a refreshed copy of the stale entry. exp is
// enforced and the signer re-evaluated, so a signer distrusted meanwhile is
// not carried along. The window is the 304's max-age, else the token's ttl,
// else the default, from now, capped by exp and maxCacheTTL.
func (c *Checker) refresh(ctx context.Context, old parsedList, res fetchResult) (parsedList, error) {
	now := c.now()
	if old.exp != nil && !now.Before(time.Unix(*old.exp, 0)) {
		return parsedList{}, classify(ReasonExpired, errors.New("status list token has expired"))
	}
	if _, err := c.evaluateSignerSubject(ctx, old.subject, old.km); err != nil {
		return parsedList{}, err
	}
	window := defaultCacheTTL
	if old.ttl != nil && *old.ttl > 0 {
		secs := *old.ttl
		if secs > maxTTLSeconds {
			secs = maxTTLSeconds
		}
		window = time.Duration(secs) * time.Second
	}
	if res.maxAge != nil {
		window = *res.maxAge
	}
	if window > maxCacheTTL {
		window = maxCacheTTL
	}
	expires := now.Add(window)
	if old.exp != nil {
		if exp := time.Unix(*old.exp, 0); exp.Before(expires) {
			expires = exp
		}
	}
	old.expires = expires
	if res.etag != "" {
		old.upstreamETag = res.etag
	}
	return old, nil
}

// dropLocked removes a cache entry (c.mu held).
func (c *Checker) dropLocked(key string) {
	if e, ok := c.cache[key]; ok {
		c.cacheBytes -= e.size()
		delete(c.cache, key)
	}
}

// store caches pl and returns the list to act on. A cached entry is never
// replaced by an older version (smaller iat): a slow load of an earlier token
// must not restore a status the newer token superseded; if the newer entry is
// still fresh the caller gets it. Ties on iat (second-granular) are broken by
// flight generation, and an abandoned flight or one older than the key's
// current flight never stores. f is nil outside flights (tests set pl.gen).
func (c *Checker) store(key string, pl parsedList, f *flight) parsedList {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if f != nil {
		pl.gen = f.gen
		if cur := c.flights[key]; f.abandoned || (cur != nil && cur.gen > f.gen) {
			return pl
		}
	}
	old, had := c.cache[key]
	if had && (old.iat > pl.iat || (old.iat == pl.iat && old.gen > pl.gen)) {
		if now.Before(old.expires) {
			return old
		}
		return pl
	}
	if pl.expires.After(now) && pl.size() <= c.cacheLimit {
		if had {
			c.cacheBytes -= old.size()
		}
		if len(c.cache) >= maxCacheEntries || c.cacheBytes+pl.size() > c.cacheLimit {
			c.cache = map[string]cachedList{}
			c.cacheBytes = 0
		}
		c.cache[key] = pl
		c.cacheBytes += pl.size()
	} else if had {
		// Do not leave the older version behind to be served as fresh.
		c.dropLocked(key)
	}
	return pl
}

// fetchResult is one upstream response.
type fetchResult struct {
	// notModified is a 304 answer to a conditional request; body is empty.
	notModified bool
	body        []byte
	mediaType   string // "" when the server sent none
	etag        string // upstream ETag, "" when none
	maxAge      *time.Duration
}

// fetch GETs uri, conditionally when ifNoneMatch is set (a 304 is notModified).
func (c *Checker) fetch(ctx context.Context, uri, ifNoneMatch string) (fetchResult, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return fetchResult{}, classify(ReasonURINotAllowed, fmt.Errorf("status list uri: %w", err))
	}
	if u.Scheme != "https" && (!c.allowHTTP || u.Scheme != "http") {
		return fetchResult{}, classify(ReasonURINotAllowed, fmt.Errorf("status list uri must be https: %q", u.Scheme))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fetchResult{}, classify(ReasonURINotAllowed, err)
	}
	req.Header.Set("Accept", mediaTypeJWT+", "+mediaTypeCWT+";q=0.8")
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	// The URI is attacker-influenced; SSRF protection is c.client (private,
	// loopback, link-local and metadata addresses refused on every hop). No
	// allowlist: issuers are arbitrary public hosts.
	resp, err := c.client.Do(req) // lgtm[go/request-forgery]
	if err != nil {
		return fetchResult{}, classify(ReasonFetchFailed, fmt.Errorf("fetch status list: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()
	res := fetchResult{etag: strings.TrimSpace(resp.Header.Get("ETag")), maxAge: maxAgeOf(resp.Header.Get("Cache-Control"))}
	if resp.StatusCode == http.StatusNotModified && ifNoneMatch != "" {
		res.notModified = true
		return res, nil
	}
	if resp.StatusCode != http.StatusOK {
		return fetchResult{}, classify(ReasonFetchFailed, fmt.Errorf("fetch status list: http %d", resp.StatusCode))
	}
	// Only a missing Content-Type is read as JWT; a non-empty one that does not
	// parse (even a valid type with a bad parameter) is unverifiable.
	if ct := strings.TrimSpace(resp.Header.Get("Content-Type")); ct != "" {
		var err error
		if res.mediaType, _, err = mime.ParseMediaType(ct); err != nil {
			return fetchResult{}, classify(ReasonUnsupportedMediaType, fmt.Errorf("status list has malformed Content-Type %q: %w", ct, err))
		}
	}
	res.body, err = io.ReadAll(io.LimitReader(resp.Body, maxTokenBytes+1))
	if err != nil {
		return fetchResult{}, classify(ReasonFetchFailed, fmt.Errorf("read status list: %w", err))
	}
	if len(res.body) > maxTokenBytes {
		return fetchResult{}, classify(ReasonTooLarge, errors.New("status list token too large"))
	}
	return res, nil
}

// maxAgeOf reads Cache-Control's max-age; no-store and no-cache count as 0, a
// missing or unparsable max-age is nil.
func maxAgeOf(cc string) *time.Duration {
	var out *time.Duration
	for _, d := range strings.Split(cc, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "no-store" || d == "no-cache":
			zero := time.Duration(0)
			return &zero
		case strings.HasPrefix(d, "max-age="):
			n, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(d, "max-age="), `"`), 10, 64)
			if err != nil || n < 0 {
				continue
			}
			if n > int64(maxCacheTTL/time.Second) {
				n = int64(maxCacheTTL / time.Second)
			}
			v := time.Duration(n) * time.Second
			out = &v
		}
	}
	return out
}

func (c *Checker) parseJWT(ctx context.Context, token, uri string) (parsedList, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return parsedList{}, errors.New("status list token is not a JWT")
	}
	var header struct {
		Typ  string          `json:"typ"`
		JWK  json.RawMessage `json:"jwk"`
		X5C  json.RawMessage `json:"x5c"`
		Crit json.RawMessage `json:"crit"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return parsedList{}, fmt.Errorf("status list header: %w", err)
	}
	// RFC 7515 §4.1.11: no critical extensions are supported, so any PRESENT
	// crit (even null or empty) makes the list unverifiable.
	if header.Crit != nil {
		return parsedList{}, errors.New("status list token has a crit header, which is not supported")
	}
	if !strings.EqualFold(header.Typ, statusListTokenTyp) {
		return parsedList{}, fmt.Errorf("status list token typ is %q, want %q", header.Typ, statusListTokenTyp)
	}
	// A PRESENT x5c takes precedence, so a null, empty or malformed one is
	// rejected rather than read as absent (which would let a jwk stand in).
	if header.X5C != nil {
		if err := checkX5CHeader(header.X5C); err != nil {
			return parsedList{}, err
		}
	}
	// The header key verifies the JWS; whether it may publish status lists is
	// the trust service's decision, taken in accept.
	km, err := trust.VerifyJWTWithEmbeddedKey(token)
	if errors.Is(err, trust.ErrNoEmbeddedKey) {
		return parsedList{}, ErrNoSignerKey
	}
	if err != nil {
		return parsedList{}, classify(ReasonSignatureInvalid, fmt.Errorf("status list signature: %w", err))
	}
	// x5c is what is verified and evaluated; a jwk also present must be its leaf key.
	if km.Type == "x5c" {
		if err := checkJWKMatchesLeaf(header.JWK, km.X5C[0]); err != nil {
			return parsedList{}, err
		}
	}

	// A member that is present but null or mistyped is rejected, never read as
	// absent (a null iss would change the trust subject; null exp/nbf/ttl would
	// skip temporal checks).
	var members map[string]json.RawMessage
	if err := decodeSegment(parts[1], &members); err != nil {
		return parsedList{}, fmt.Errorf("status list payload: %w", err)
	}
	var lc listClaims
	var cerr error
	if lc.sub, cerr = jwtString(members, "sub"); cerr != nil {
		return parsedList{}, cerr
	}
	if lc.iss, cerr = jwtString(members, "iss"); cerr != nil {
		return parsedList{}, cerr
	}
	for _, f := range []struct {
		dst  **int64
		name string
	}{{&lc.iat, "iat"}, {&lc.exp, "exp"}, {&lc.nbf, "nbf"}, {&lc.ttl, "ttl"}} {
		if *f.dst, cerr = jwtInt(members, f.name); cerr != nil {
			return parsedList{}, cerr
		}
	}
	rawSL, ok := members["status_list"]
	if !ok {
		return parsedList{}, errors.New("status list token has no status_list claim")
	}
	sl, cerr := jwtObject(rawSL, "status_list")
	if cerr != nil {
		return parsedList{}, cerr
	}
	bits, cerr := jwtInt(sl, "bits")
	if cerr != nil {
		return parsedList{}, fmt.Errorf("status_list: %w", cerr)
	}
	if bits == nil {
		return parsedList{}, errors.New("status list token status_list has no bits")
	}
	lstStr, cerr := jwtString(sl, "lst")
	if cerr != nil {
		return parsedList{}, fmt.Errorf("status_list: %w", cerr)
	}
	if _, ok := sl["lst"]; !ok {
		return parsedList{}, errors.New("status list token status_list has no lst")
	}
	lst, err := base64.RawURLEncoding.DecodeString(lstStr)
	if err != nil {
		return parsedList{}, fmt.Errorf("status list lst: %w", err)
	}
	lc.bits, lc.lst = int(*bits), lst
	return c.accept(ctx, uri, km, lc)
}

// jwtString reads an optional string claim; a present member that is not a
// non-blank JSON string (including null) is an error.
func jwtString(m map[string]json.RawMessage, name string) (string, error) {
	raw, ok := m[name]
	if !ok {
		return "", nil
	}
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", fmt.Errorf("status list claim %s is not a string", name)
	}
	if strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("status list claim %s is empty", name)
	}
	return s, nil
}

// jwtInt reads an optional integer claim; a present non-integer (or null) is an error.
func jwtInt(m map[string]json.RawMessage, name string) (*int64, error) {
	raw, ok := m[name]
	if !ok {
		return nil, nil
	}
	var n int64
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) || json.Unmarshal(raw, &n) != nil {
		return nil, fmt.Errorf("status list claim %s is not an integer", name)
	}
	return &n, nil
}

// jwtObject decodes a present member that must be a JSON object.
func jwtObject(raw json.RawMessage, name string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &m) != nil {
		return nil, fmt.Errorf("status list claim %s is not an object", name)
	}
	return m, nil
}

// listClaims is the form-independent content of a Status List Token.
type listClaims struct {
	sub, iss           string
	iat, exp, nbf, ttl *int64
	bits               int
	lst                []byte // zlib-compressed, not base64
}

// accept applies the claim checks shared by the JWT and CWT forms, inflates the
// list and asks the trust service about the signature-verified signer key km.
func (c *Checker) accept(ctx context.Context, uri string, km *trust.KeyMaterial, lc listClaims) (parsedList, error) {
	if lc.iat == nil {
		return parsedList{}, classify(ReasonMalformed, errors.New("status list token has no iat"))
	}
	if lc.sub != uri {
		return parsedList{}, classify(ReasonMalformed, fmt.Errorf("status list sub %q does not match uri %q", lc.sub, uri))
	}
	now := c.now()
	// A future iat is rejected before freshness is derived. Like exp and nbf,
	// no clock-skew leeway is applied (the draft defines none).
	if time.Unix(*lc.iat, 0).After(now) {
		return parsedList{}, classify(ReasonNotYetValid, errors.New("status list token is issued in the future (iat)"))
	}
	// ttl is the freshness window from iat; without it, a default window from
	// now. exp and maxCacheTTL cap it.
	expires := now.Add(defaultCacheTTL)
	if lc.ttl != nil {
		// ttl must be a positive integer; a present zero or negative is malformed.
		if *lc.ttl <= 0 {
			return parsedList{}, fmt.Errorf("status list ttl %d is not a positive integer", *lc.ttl)
		}
		// Clamp first: seconds*1e9 would overflow int64 above ~292 years.
		secs := *lc.ttl
		if secs > maxTTLSeconds {
			secs = maxTTLSeconds
		}
		expires = time.Unix(*lc.iat, 0).Add(time.Duration(secs) * time.Second)
	}
	if lc.nbf != nil && now.Before(time.Unix(*lc.nbf, 0)) {
		return parsedList{}, classify(ReasonNotYetValid, errors.New("status list token is not yet valid (nbf)"))
	}
	if lc.exp != nil {
		exp := time.Unix(*lc.exp, 0)
		if !now.Before(exp) {
			return parsedList{}, classify(ReasonExpired, errors.New("status list token has expired"))
		}
		if exp.Before(expires) {
			expires = exp
		}
	}
	if limit := now.Add(maxCacheTTL); expires.After(limit) {
		expires = limit
	}
	// An already-expired deadline is used for this check but not cached (see store).
	switch lc.bits {
	case 1, 2, 4, 8:
	default:
		return parsedList{}, fmt.Errorf("status list bits %d is not 1, 2, 4 or 8", lc.bits)
	}
	list, err := inflate(lc.lst)
	if err != nil {
		return parsedList{}, err
	}
	if c.minEntries > 0 {
		if n := len(list) * 8 / lc.bits; n < c.minEntries {
			return parsedList{}, classify(ReasonListTooSmall, fmt.Errorf("status list has %d entries, below the configured minimum of %d", n, c.minEntries))
		}
	}
	subject, err := signerSubject(lc.iss, uri)
	if err != nil {
		return parsedList{}, err
	}
	action, err := c.evaluateSignerSubject(ctx, subject, km)
	if err != nil {
		return parsedList{}, err
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%d\x00%d\x00", uri, *lc.iat, lc.bits)
	h.Write(lc.lst)
	return parsedList{
		bits: lc.bits, list: list, expires: expires, iat: *lc.iat,
		lst: lc.lst, exp: lc.exp, ttl: lc.ttl, signerAction: action,
		etag:    `"` + hex.EncodeToString(h.Sum(nil)[:16]) + `"`,
		subject: subject, km: km,
	}, nil
}

// canonicalOrigin returns uri's origin in canonical form (lowercase, punycode
// host, no trailing dot, no default port) so equivalent spellings share one
// trust subject.
func canonicalOrigin(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	return originOf(u)
}

func originOf(u *url.URL) (string, error) {
	scheme := strings.ToLower(u.Scheme)
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if scheme == "" || host == "" {
		return "", errors.New("no origin")
	}
	isIP := false
	if _, err := netip.ParseAddr(host); err == nil {
		isIP = true
	}
	if !isIP {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return "", err
		}
		host = ascii
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// signerSubject is the trust subject for a list: its iss claim, or the
// canonical origin of its URI.
func signerSubject(iss, uri string) (string, error) {
	if iss != "" {
		return iss, nil
	}
	origin, err := canonicalOrigin(uri)
	if err != nil {
		return "", fmt.Errorf("%w: no signer identity", ErrTrustUnavailable)
	}
	return origin, nil
}

// evaluateSigner asks the trust service whether the list signer may publish
// status lists. The subject is the list's iss claim, or the origin of its URI.
func (c *Checker) evaluateSigner(ctx context.Context, iss, uri string, km *trust.KeyMaterial) error {
	subject, err := signerSubject(iss, uri)
	if err != nil {
		return err
	}
	_, err = c.evaluateSignerSubject(ctx, subject, km)
	return err
}

// evaluateSignerSubject is evaluateSigner for a resolved subject; it also
// returns the accepting trust action when one is reported, else "".
func (c *Checker) evaluateSignerSubject(ctx context.Context, subject string, km *trust.KeyMaterial) (string, error) {
	var (
		trusted bool
		action  string
		err     error
	)
	switch {
	case c.trustAction != nil:
		trusted, action, err = c.trustAction(ctx, subject, km)
	case c.trust != nil:
		trusted, err = c.trust(ctx, subject, km)
	default:
		return "", fmt.Errorf("%w: no trust service configured", ErrTrustUnavailable)
	}
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
	}
	if !trusted {
		return "", fmt.Errorf("%w (%s)", ErrSignerUntrusted, subject)
	}
	return action, nil
}

// checkX5CHeader requires a present x5c header parameter to be a non-empty
// JSON array of base64 certificate strings.
func checkX5CHeader(raw json.RawMessage) error {
	if len(raw) == 0 || raw[0] != '[' {
		return errors.New("status list x5c is not an array")
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return fmt.Errorf("status list x5c: %w", err)
	}
	if len(elems) == 0 {
		return errors.New("status list x5c is empty")
	}
	for i, e := range elems {
		var cert string
		if len(e) == 0 || e[0] != '"' || json.Unmarshal(e, &cert) != nil || cert == "" {
			return fmt.Errorf("status list x5c[%d] is not a certificate string", i)
		}
		if _, err := trust.DecodeX5CCert(cert); err != nil {
			return fmt.Errorf("status list x5c[%d]: %w", i, err)
		}
	}
	return nil
}

// checkJWKMatchesLeaf requires a present jwk header member (nil means absent)
// to be a usable key equal to the x5c leaf's public key.
func checkJWKMatchesLeaf(jwkParam json.RawMessage, leaf string) error {
	if jwkParam == nil {
		return nil
	}
	der, err := trust.DecodeX5CCert(leaf)
	if err != nil {
		return fmt.Errorf("status list x5c leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("status list x5c leaf: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(jwkParam, &obj); err != nil || len(obj) == 0 {
		return fmt.Errorf("status list jwk: not a non-empty JSON object")
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(jwkParam); err != nil {
		return fmt.Errorf("status list jwk: %w", err)
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := jwk.Public().Key.(equaler)
	if !ok || !pub.Equal(cert.PublicKey) {
		return errKeyMismatch
	}
	return nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func inflate(compressed []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("status list lst: %w", err)
	}
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(io.LimitReader(r, maxInflateBytes+1))
	if err != nil {
		return nil, fmt.Errorf("status list lst: %w", err)
	}
	if len(out) > maxInflateBytes {
		return nil, classify(ReasonTooLarge, errors.New("status list lst inflates too large"))
	}
	return out, nil
}

// entry reads the idx-th status value; bits within a byte are packed
// least-significant first (draft-ietf-oauth-status-list §4.1).
func entry(bits int, list []byte, idx int64) (int, error) {
	// idx is attacker-supplied: bound it before multiplying so it cannot wrap.
	if idx < 0 || idx >= int64(len(list))*8/int64(bits) {
		return 0, errors.New("status list index is out of range")
	}
	bitPos := idx * int64(bits)
	byteIdx := bitPos / 8
	shift := uint(bitPos % 8)
	return int(list[byteIdx]>>shift) & (1<<uint(bits) - 1), nil
}
