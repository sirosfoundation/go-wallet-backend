package statuslist

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/net/idna"

	"github.com/sirosfoundation/go-wallet-backend/pkg/trust"
)

// Limits that keep a hostile or broken status list host from exhausting
// memory: the fetched token and the inflated bit string are both bounded.
const (
	maxTokenBytes   = 4 << 20
	maxInflateBytes = 32 << 20

	// defaultCacheTTL is used when the token carries neither ttl nor a nearer exp.
	defaultCacheTTL = 5 * time.Minute
	// maxCacheTTL caps a publisher-chosen ttl so a revocation is never hidden
	// for longer than this, whatever the list claims.
	maxCacheTTL = time.Hour
	// maxTTLSeconds bounds a ttl claim before it is converted to a Duration
	// (about 68 years; far above maxCacheTTL, far below overflow).
	maxTTLSeconds = 1 << 31
	// maxCacheEntries and maxCacheBytes bound the cache (the latter counts
	// inflated list bytes, which can be large); on overflow it is reset.
	maxCacheEntries = 256
	maxCacheBytes   = 64 << 20

	// DefaultMaxConcurrentLoads is how many status lists may be fetched and
	// inflated at once when WithMaxConcurrentLoads is not used. Each load can
	// hold up to maxTokenBytes + maxInflateBytes (36 MiB), so the default
	// bounds in-flight memory at about 290 MiB.
	DefaultMaxConcurrentLoads = 8
	// flightTimeout is the backstop for one shared load; callers' own
	// contexts (the status check budget) normally end it far sooner.
	flightTimeout = 2 * time.Minute

	statusListTokenTyp = "statuslist+jwt"
	mediaTypeJWT       = "application/statuslist+jwt"
	mediaTypeCWT       = "application/statuslist+cwt"
)

// errKeyMismatch is returned when a list header carries both x5c and jwk and
// they are different keys.
var errKeyMismatch = errors.New("status list header jwk does not match the x5c leaf key")

var (
	// ErrSignerUntrusted is wrapped when the list's signature verified but
	// the trust decision for the signer key was negative. It is distinct from
	// a failure to obtain a decision (ErrTrustUnavailable).
	ErrSignerUntrusted = errors.New("status list signer is not trusted")
	// ErrTrustUnavailable is wrapped when no trust decision could be had: no
	// trust PDP configured, or the evaluation itself failed.
	ErrTrustUnavailable = errors.New("status list signer trust could not be evaluated")
	// ErrNoSignerKey is returned for a list whose header carries no x5c or
	// jwk (a kid alone identifies nothing this wallet can resolve).
	ErrNoSignerKey = errors.New("status list carries no signer key material (x5c or jwk header)")
)

// SignerTrust evaluates whether the key that signed a status list is trusted
// to publish status lists. subject names the signer (the list's iss claim, else
// the list URI's origin); km is the x5c chain or jwk from the list header.
// trusted=false with a nil error is a negative decision; a non-nil error
// means no decision could be obtained. The Checker never acts on a list
// unless this returns (true, nil).
type SignerTrust func(ctx context.Context, subject string, km *trust.KeyMaterial) (trusted bool, err error)

// Reference is the `status.status_list` claim of a credential
// (draft-ietf-oauth-status-list §6.2).
type Reference struct {
	Idx int64  `json:"idx"`
	URI string `json:"uri"`
}

// ErrRevoked is wrapped by the error Check returns ONLY when the list was
// fetched, its signature, typ, sub and required iat were verified (exp, nbf
// and ttl are optional, and are validated whenever present), and the entry at
// the credential's index is anything other than VALID (0): INVALID (1), SUSPENDED
// (2) or an application-specific value. Every other error Check returns means
// "could not determine" and must not be read as revocation. The distinction is
// what lets a wallet refuse only on a positive determination while leaving the
// authoritative check to the verifier.
var ErrRevoked = errors.New("credential status is not valid")

// ReferenceFromCredentialClaims extracts the status_list reference from a
// decoded credential payload. present reports whether the credential carries
// a `status` claim at all; a credential that does but whose reference cannot
// be read returns present=true with an error, so the caller fails closed
// instead of treating a malformed claim as "no status".
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
		// A status mechanism other than Token Status List, which this
		// package cannot check.
		return nil, true, errors.New("status claim has no status_list reference")
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
	// allowHTTP permits a plain-http status list URI (development only).
	allowHTTP bool
	now       func() time.Time
	// minEntries is the smallest inflated list (entries = bytes*8/bits) the
	// Checker accepts; 0 disables the check. See WithMinEntries.
	minEntries int

	mu         sync.Mutex
	cache      map[string]cachedList
	cacheBytes int
	// cacheLimit is maxCacheBytes; a field so tests can shrink it.
	cacheLimit int

	// flights are the loads in progress, by cache key (guarded by mu);
	// loadSem bounds how many run at once.
	flights map[string]*flight
	nextGen uint64 // last flight generation handed out (guarded by mu)
	loadSem chan struct{}
}

// flight is one shared fetch-and-verify. The result fields are written before
// done is closed and read only after.
type flight struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int // guarded by Checker.mu
	// gen orders flights: it is assigned from Checker.nextGen when the flight
	// starts, so a later flight for the same key always has a larger gen.
	gen uint64
	// abandoned is set (under Checker.mu) when the last waiter gave up and
	// the flight was withdrawn; its result has no consumer and must not be
	// cached.
	abandoned bool
	bits      int
	list      []byte
	err       error
}

// parsedList is a verified, trust-evaluated status list. iat orders versions
// of the same list: a cache entry is never replaced by a list with an older
// iat. iat has one-second granularity and is not a unique version, so gen
// (the generation of the flight that fetched the list) breaks ties: a list
// from an older flight never replaces one from a newer flight.
type parsedList struct {
	bits    int
	list    []byte
	expires time.Time
	iat     int64
	gen     uint64
}

type cachedList = parsedList

// NewChecker returns a Checker that fetches through client, which must be the
// SSRF-guarded client (HTTPClientConfig.NewHTTPClient).
//
// signerTrust decides whether a list's signer key is trusted (go-trust). With
// a nil signerTrust no list can be authoritative and every Check reports the
// list as unverifiable.
func NewChecker(client *http.Client, allowHTTP bool, signerTrust SignerTrust) *Checker {
	return &Checker{client: client, trust: signerTrust, allowHTTP: allowHTTP, now: time.Now, cache: map[string]cachedList{}, cacheLimit: maxCacheBytes,
		flights: map[string]*flight{}, loadSem: make(chan struct{}, DefaultMaxConcurrentLoads)}
}

// WithMinEntries makes the Checker reject a status list that holds fewer than
// n entries once inflated (len(list)*8/bits), before the signer is consulted.
// n <= 0 (the default) disables the check.
//
// draft-ietf-oauth-status-list (-21) sets NO receiver-side minimum: §12.1
// only observes that herd privacy depends on list size ("A larger size
// results in better privacy but also impacts the performance"), and §13.4
// leaves sizing to the Status Issuer. A hard minimum would also reject
// lists real publishers emit (the SIROS status service defaults to 100,000
// entries), so this is an opt-in deployment policy, not a conformance check.
// Call it before the Checker is shared; it is not safe to change afterwards.
func (c *Checker) WithMinEntries(n int) *Checker {
	if n < 0 {
		n = 0
	}
	c.minEntries = n
	return c
}

// WithMaxConcurrentLoads bounds how many status lists the Checker fetches and
// inflates at the same time; further loads wait for a slot (honouring their
// context, so a check that runs out of budget is undetermined rather than
// blocked). n <= 0 selects DefaultMaxConcurrentLoads. Call it before the
// Checker is shared; it is not safe to change afterwards.
func (c *Checker) WithMaxConcurrentLoads(n int) *Checker {
	if n <= 0 {
		n = DefaultMaxConcurrentLoads
	}
	c.loadSem = make(chan struct{}, n)
	return c
}

// Check returns nil only if the entry at ref is VALID in a status list token
// that was fetched, whose JWS verifies against the key in its own x5c/jwk
// header, whose signer key the trust service accepts, that matches ref.URI and
// is fresh. A list is authoritative only under those conditions: only then can
// Check return an error wrapping ErrRevoked (entry non-zero). Every other
// failure (network, non-200, unsupported media type, expired, bad signature, no key, negative or
// unavailable trust decision, malformed token) returns an error that does not
// wrap ErrRevoked; a negative trust decision wraps ErrSignerUntrusted and an
// unobtainable one ErrTrustUnavailable. Callers choose what to do with those.
func (c *Checker) Check(ctx context.Context, ref *Reference) error {
	bits, list, err := c.load(ctx, ref.URI)
	if err != nil {
		return err
	}
	value, err := entry(bits, list, ref.Idx)
	if err != nil {
		return err
	}
	if value != 0 {
		return fmt.Errorf("%w: status value %d", ErrRevoked, value)
	}
	return nil
}

// load returns the status list for uri. Concurrent callers for the same
// (tenant, uri) share ONE fetch-and-verify (a flight), and the number of
// flights running at once is bounded (WithMaxConcurrentLoads), so a burst of
// presentations cannot each allocate a token plus an inflated list; the
// cache limit alone does not bound that in-flight memory.
//
// Every waiter honours its own ctx (which carries the per-presentation status
// check budget): it returns ctx's error, which does not wrap ErrRevoked, as
// soon as it expires, and a caller giving up never cancels the flight for
// the others. The flight itself is cancelled only when its last waiter has
// left.
func (c *Checker) load(ctx context.Context, uri string) (int, []byte, error) {
	// The signer trust decision is tenant-scoped (the tenant travels in ctx),
	// so a cached, already trust-evaluated list is only reused within the
	// tenant it was evaluated for.
	//
	// The key uses the EXACT reference URI, not a canonical form: accept
	// binds the token's sub to the exact uri only when a list is loaded
	// (draft-ietf-oauth-status-list-21 sections 5.1/5.2: sub MUST be equal to the
	// uri claim of the Referenced Token, compared as exact strings), so an entry may only be
	// reused for the uri it was validated against. Only the trust subject
	// (evaluateSigner) uses the canonical origin.
	key := trust.TenantFromContext(ctx) + "\x00" + uri
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.bits, e.list, nil
	}
	f, ok := c.flights[key]
	if !ok {
		// The flight outlives any single caller, so it takes ctx's values
		// (the tenant) but neither its cancellation nor its deadline.
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
		return f.bits, f.list, f.err
	case <-ctx.Done():
		c.mu.Lock()
		f.waiters--
		if f.waiters == 0 {
			// Nobody is left to use the result: stop the work and let a
			// later caller start a fresh flight.
			if c.flights[key] == f {
				delete(c.flights, key)
			}
			f.abandoned = true
			f.cancel()
		}
		c.mu.Unlock()
		return 0, nil, fmt.Errorf("status list load: %w", ctx.Err())
	}
}

// runFlight performs one load and publishes the outcome to its waiters.
func (c *Checker) runFlight(ctx context.Context, key, uri string, f *flight) {
	defer f.cancel()
	f.bits, f.list, f.err = c.loadOnce(ctx, key, uri, f)
	c.mu.Lock()
	if c.flights[key] == f {
		delete(c.flights, key)
	}
	c.mu.Unlock()
	close(f.done)
}

// loadOnce fetches, verifies and caches one list, holding a load slot for
// the duration.
func (c *Checker) loadOnce(ctx context.Context, key, uri string, f *flight) (int, []byte, error) {
	select {
	case c.loadSem <- struct{}{}:
		defer func() { <-c.loadSem }()
	case <-ctx.Done():
		return 0, nil, fmt.Errorf("waiting for a status list load slot: %w", ctx.Err())
	}
	body, mediaType, err := c.fetch(ctx, uri)
	if err != nil {
		return 0, nil, err
	}
	var pl parsedList
	switch mediaType {
	case mediaTypeJWT, "":
		// A missing Content-Type is read as the JWT form, the only one
		// that ever came without one; a CWT body then fails to parse.
		pl, err = c.parseJWT(ctx, strings.TrimSpace(string(body)), uri)
	case mediaTypeCWT:
		pl, err = c.parseCWT(ctx, body, uri)
	default:
		err = fmt.Errorf("status list has unsupported media type %q", mediaType)
	}
	if err != nil {
		return 0, nil, err
	}
	return c.store(key, pl, f)
}

// store caches pl and returns the list to act on. expires is an absolute
// deadline fixed before the (possibly slow) trust call; it is compared against
// a fresh clock reading so the cache never outlives the token deadline.
//
// A cache entry is never replaced by an older version (smaller iat): a load
// that fetched an earlier token but finished after a newer one (say, a slow
// signer evaluation) must not restore the status the newer token superseded.
// When the newer entry is still fresh the caller gets that entry's list too.
//
// iat is second-granular, so two revisions issued in the same second tie on
// it. Flights are therefore also ordered by generation: a flight that was
// abandoned, or whose generation is lower than the cached entry's or than the
// key's current flight, never stores. f is the loading flight (nil outside
// flights, e.g. in tests, which then carry their own gen in pl).
func (c *Checker) store(key string, pl parsedList, f *flight) (int, []byte, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if f != nil {
		pl.gen = f.gen
		if cur := c.flights[key]; f.abandoned || (cur != nil && cur.gen > f.gen) {
			return pl.bits, pl.list, nil
		}
	}
	old, had := c.cache[key]
	if had && (old.iat > pl.iat || (old.iat == pl.iat && old.gen > pl.gen)) {
		if now.Before(old.expires) {
			return old.bits, old.list, nil
		}
		return pl.bits, pl.list, nil
	}
	if pl.expires.After(now) && len(pl.list) <= c.cacheLimit {
		if had {
			c.cacheBytes -= len(old.list)
		}
		if len(c.cache) >= maxCacheEntries || c.cacheBytes+len(pl.list) > c.cacheLimit {
			c.cache = map[string]cachedList{}
			c.cacheBytes = 0
		}
		c.cache[key] = pl
		c.cacheBytes += len(pl.list)
	}
	return pl.bits, pl.list, nil
}

// fetch returns the raw body and the response media type ("" when the server
// sent none).
func (c *Checker) fetch(ctx context.Context, uri string) ([]byte, string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, "", fmt.Errorf("status list uri: %w", err)
	}
	if u.Scheme != "https" && (!c.allowHTTP || u.Scheme != "http") {
		return nil, "", fmt.Errorf("status list uri must be https: %q", u.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", mediaTypeJWT+", "+mediaTypeCWT+";q=0.8")
	// The URI comes from a credential the holder presents, so it is
	// attacker-influenced by nature. The scheme is checked above and c.client
	// is the SSRF-guarded client (NewHTTPClient: private, loopback, link-local
	// and metadata addresses refused on every hop, DNS pinned to the checked
	// address); there is no allowlist because issuers are arbitrary public
	// hosts.
	resp, err := c.client.Do(req) // lgtm[go/request-forgery]
	if err != nil {
		return nil, "", fmt.Errorf("fetch status list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("fetch status list: http %d", resp.StatusCode)
	}
	// A missing Content-Type is distinct from a malformed one: only the
	// former takes the intentional "read as JWT" path. A non-empty value that
	// does not parse (including a valid type with an invalid parameter, for
	// which ParseMediaType returns both a type and an error) is unverifiable.
	var mt string
	if ct := strings.TrimSpace(resp.Header.Get("Content-Type")); ct != "" {
		var err error
		if mt, _, err = mime.ParseMediaType(ct); err != nil {
			return nil, "", fmt.Errorf("status list has malformed Content-Type %q: %w", ct, err)
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read status list: %w", err)
	}
	if len(body) > maxTokenBytes {
		return nil, "", errors.New("status list token too large")
	}
	return body, mt, nil
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
	// RFC 7515 section 4.1.11: a JWS that lists critical extensions this
	// verifier does not implement must be rejected. None are supported, so any
	// PRESENT crit (null, empty or populated) makes the list unverifiable, as
	// on the CWT path.
	if header.Crit != nil {
		return parsedList{}, errors.New("status list token has a crit header, which is not supported")
	}
	if !strings.EqualFold(header.Typ, statusListTokenTyp) {
		return parsedList{}, fmt.Errorf("status list token typ is %q, want %q", header.Typ, statusListTokenTyp)
	}
	// Presence-aware like jwk: a PRESENT x5c always takes precedence, so it
	// must be a usable chain. A null, empty, non-array or malformed x5c is
	// rejected here rather than being read as absent (which would let a jwk
	// stand in for it).
	if header.X5C != nil {
		if err := checkX5CHeader(header.X5C); err != nil {
			return parsedList{}, err
		}
	}
	// The list's own header key verifies the JWS; whether that key may
	// publish status lists is the trust service's decision, taken below once
	// the token is otherwise valid. The credential issuer's key plays no part:
	// an external status service signs with its own key.
	km, err := trust.VerifyJWTWithEmbeddedKey(token)
	if errors.Is(err, trust.ErrNoEmbeddedKey) {
		return parsedList{}, ErrNoSignerKey
	}
	if err != nil {
		return parsedList{}, fmt.Errorf("status list signature: %w", err)
	}
	// Precedence when the header carries both: x5c is what is verified and
	// trust-evaluated; a jwk that is also present must be the x5c leaf's key,
	// otherwise the header is inconsistent and the list unverifiable.
	if km.Type == "x5c" {
		if err := checkJWKMatchesLeaf(header.JWK, km.X5C[0]); err != nil {
			return parsedList{}, err
		}
	}

	// Decode presence-aware: a member that is present but null or of the
	// wrong type is rejected, never read as absent (a null iss would change
	// the trust subject to the URI origin; a null exp/nbf/ttl would skip the
	// temporal checks). The CWT path is equally strict.
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
// JSON string (including null), or is empty or only whitespace, is an error:
// an empty iss must not be read as absent (it would change the trust subject
// to the URI origin).
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

// jwtInt reads an optional integer claim; a present member that is not a JSON
// integer (including null) is an error.
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

// accept applies the claim checks shared by the JWT and CWT forms, inflates
// the list and asks the trust service about the (already signature-verified)
// signer key km. Only a list that passes all of it is returned.
func (c *Checker) accept(ctx context.Context, uri string, km *trust.KeyMaterial, lc listClaims) (parsedList, error) {
	if lc.iat == nil {
		return parsedList{}, errors.New("status list token has no iat")
	}
	if lc.sub != uri {
		return parsedList{}, fmt.Errorf("status list sub %q does not match uri %q", lc.sub, uri)
	}
	now := c.now()
	// A token issued in the future is not yet valid, whatever its ttl or exp
	// say: rejecting it before freshness is derived keeps a pre-issued signed
	// list from yielding a verdict early. Like exp and nbf below, the
	// comparison uses this Checker's clock with no clock-skew leeway; the
	// draft defines none, and a publisher that stamps iat ahead of real time
	// is misconfigured rather than merely skewed.
	if time.Unix(*lc.iat, 0).After(now) {
		return parsedList{}, errors.New("status list token is issued in the future (iat)")
	}
	// The ttl claim is the token's freshness window, measured from its iat
	// (not from when this wallet fetched it). Without ttl, a default window
	// from now applies. exp and maxCacheTTL cap it.
	expires := now.Add(defaultCacheTTL)
	if lc.ttl != nil {
		// draft-ietf-oauth-status-list: ttl is a positive integer. A present
		// ttl of zero or below is a malformed claim (like any other present
		// but invalid claim), never silently read as absent.
		if *lc.ttl <= 0 {
			return parsedList{}, fmt.Errorf("status list ttl %d is not a positive integer", *lc.ttl)
		}
		// Clamp before converting to a Duration: seconds * 1e9 overflows
		// int64 above ~292 years and would wrap to a negative or tiny
		// lifetime. maxCacheTTL below is the effective cap; this bound only
		// has to be far above it and safely inside time.Time's range.
		secs := *lc.ttl
		if secs > maxTTLSeconds {
			secs = maxTTLSeconds
		}
		expires = time.Unix(*lc.iat, 0).Add(time.Duration(secs) * time.Second)
	}
	if lc.nbf != nil && now.Before(time.Unix(*lc.nbf, 0)) {
		return parsedList{}, errors.New("status list token is not yet valid (nbf)")
	}
	if lc.exp != nil {
		exp := time.Unix(*lc.exp, 0)
		if !now.Before(exp) {
			return parsedList{}, errors.New("status list token has expired")
		}
		if exp.Before(expires) {
			expires = exp
		}
	}
	if limit := now.Add(maxCacheTTL); expires.After(limit) {
		expires = limit
	}
	// A token already past its deadline is still used for this check but not
	// cached (load compares expires against the clock after the trust call).
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
			return parsedList{}, fmt.Errorf("status list has %d entries, below the configured minimum of %d", n, c.minEntries)
		}
	}
	if err := c.evaluateSigner(ctx, lc.iss, uri, km); err != nil {
		return parsedList{}, err
	}
	return parsedList{bits: lc.bits, list: list, expires: expires, iat: *lc.iat}, nil
}

// canonicalOrigin returns the serialized origin of uri in canonical form, so
// equivalent spellings of one origin get one trust subject: lowercase scheme
// and host, IDN hosts in their A-label (punycode) form, no trailing dot on
// the host and no port when it is the scheme's default.
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

// evaluateSigner asks the trust service whether the list signer may publish
// status lists. The subject is the list's iss claim, or the origin of its URI.
func (c *Checker) evaluateSigner(ctx context.Context, iss, uri string, km *trust.KeyMaterial) error {
	if c.trust == nil {
		return fmt.Errorf("%w: no trust service configured", ErrTrustUnavailable)
	}
	subject := iss
	if subject == "" {
		origin, err := canonicalOrigin(uri)
		if err != nil {
			return fmt.Errorf("%w: no signer identity", ErrTrustUnavailable)
		}
		subject = origin
	}
	trusted, err := c.trust(ctx, subject, km)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTrustUnavailable, err)
	}
	if !trusted {
		return fmt.Errorf("%w (%s)", ErrSignerUntrusted, subject)
	}
	return nil
}

// checkJWKMatchesLeaf requires a jwk header parameter, when present, to be the
// public key of the x5c leaf certificate.
//
// jwkParam is the raw header member: nil means absent. A present member that is
// null, empty, not an object or not a usable key is malformed key material and
// makes the list unverifiable.
// checkX5CHeader requires a present x5c header parameter to be a non-empty
// JSON array of base64 (standard or URL alphabet, as the verifier accepts)
// certificate strings.
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
		return nil, errors.New("status list lst inflates too large")
	}
	return out, nil
}

// entry reads the idx-th status value; bits within a byte are packed
// least-significant first (draft-ietf-oauth-status-list §4.1).
func entry(bits int, list []byte, idx int64) (int, error) {
	// idx comes from the credential. Bound it by the list size before any
	// multiplication so a huge value cannot wrap around to a valid position.
	if idx < 0 || idx >= int64(len(list))*8/int64(bits) {
		return 0, errors.New("status list index is out of range")
	}
	bitPos := idx * int64(bits)
	byteIdx := bitPos / 8
	shift := uint(bitPos % 8)
	return int(list[byteIdx]>>shift) & (1<<uint(bits) - 1), nil
}
