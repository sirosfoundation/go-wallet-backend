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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

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
	// maxCacheEntries and maxCacheBytes bound the cache (the latter counts
	// inflated list bytes, which can be large); on overflow it is reset.
	maxCacheEntries = 256
	maxCacheBytes   = 64 << 20

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
// fetched, its signature, typ, sub and exp were verified, and the entry at the
// credential's index is anything other than VALID (0): INVALID (1), SUSPENDED
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

	mu         sync.Mutex
	cache      map[string]cachedList
	cacheBytes int
	// cacheLimit is maxCacheBytes; a field so tests can shrink it.
	cacheLimit int
}

type cachedList struct {
	bits    int
	list    []byte
	expires time.Time
}

// NewChecker returns a Checker that fetches through client, which must be the
// SSRF-guarded client (HTTPClientConfig.NewHTTPClient).
//
// signerTrust decides whether a list's signer key is trusted (go-trust). With
// a nil signerTrust no list can be authoritative and every Check reports the
// list as unverifiable.
func NewChecker(client *http.Client, allowHTTP bool, signerTrust SignerTrust) *Checker {
	return &Checker{client: client, trust: signerTrust, allowHTTP: allowHTTP, now: time.Now, cache: map[string]cachedList{}, cacheLimit: maxCacheBytes}
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

func (c *Checker) load(ctx context.Context, uri string) (int, []byte, error) {
	// The signer trust decision is tenant-scoped (the tenant travels in ctx),
	// so a cached, already trust-evaluated list is only reused within the
	// tenant it was evaluated for.
	key := trust.TenantFromContext(ctx) + "\x00" + uri
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.bits, e.list, nil
	}
	c.mu.Unlock()

	body, mediaType, err := c.fetch(ctx, uri)
	if err != nil {
		return 0, nil, err
	}
	var bits int
	var list []byte
	var expires time.Time
	switch mediaType {
	case mediaTypeJWT, "":
		// A missing Content-Type is read as the JWT form, the only one
		// that ever came without one; a CWT body then fails to parse.
		bits, list, expires, err = c.parseJWT(ctx, strings.TrimSpace(string(body)), uri)
	case mediaTypeCWT:
		bits, list, expires, err = c.parseCWT(ctx, body, uri)
	default:
		err = fmt.Errorf("status list has unsupported media type %q", mediaType)
	}
	if err != nil {
		return 0, nil, err
	}
	// expires is an absolute deadline fixed before the (possibly slow) trust
	// call; it is compared against a fresh clock reading so the cache never
	// outlives the token deadline.
	if now := c.now(); expires.After(now) && len(list) <= c.cacheLimit {
		c.mu.Lock()
		if old, ok := c.cache[key]; ok {
			c.cacheBytes -= len(old.list)
		}
		if len(c.cache) >= maxCacheEntries || c.cacheBytes+len(list) > c.cacheLimit {
			c.cache = map[string]cachedList{}
			c.cacheBytes = 0
		}
		c.cache[key] = cachedList{bits: bits, list: list, expires: expires}
		c.cacheBytes += len(list)
		c.mu.Unlock()
	}
	return bits, list, nil
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
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("read status list: %w", err)
	}
	if len(body) > maxTokenBytes {
		return nil, "", errors.New("status list token too large")
	}
	return body, mt, nil
}

func (c *Checker) parseJWT(ctx context.Context, token, uri string) (int, []byte, time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, nil, time.Time{}, errors.New("status list token is not a JWT")
	}
	var header struct {
		Typ string         `json:"typ"`
		JWK map[string]any `json:"jwk"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return 0, nil, time.Time{}, fmt.Errorf("status list header: %w", err)
	}
	if !strings.EqualFold(header.Typ, statusListTokenTyp) {
		return 0, nil, time.Time{}, fmt.Errorf("status list token typ is %q, want %q", header.Typ, statusListTokenTyp)
	}
	// The list's own header key verifies the JWS; whether that key may
	// publish status lists is the trust service's decision, taken below once
	// the token is otherwise valid. The credential issuer's key plays no part:
	// an external status service signs with its own key.
	km, err := trust.VerifyJWTWithEmbeddedKey(token)
	if errors.Is(err, trust.ErrNoEmbeddedKey) {
		return 0, nil, time.Time{}, ErrNoSignerKey
	}
	if err != nil {
		return 0, nil, time.Time{}, fmt.Errorf("status list signature: %w", err)
	}
	// Precedence when the header carries both: x5c is what is verified and
	// trust-evaluated; a jwk that is also present must be the x5c leaf's key,
	// otherwise the header is inconsistent and the list unverifiable.
	if km.Type == "x5c" {
		if err := checkJWKMatchesLeaf(header.JWK, km.X5C[0]); err != nil {
			return 0, nil, time.Time{}, err
		}
	}

	var claims struct {
		Sub        string `json:"sub"`
		Iss        string `json:"iss"`
		Iat        *int64 `json:"iat"`
		Exp        *int64 `json:"exp"`
		TTL        *int64 `json:"ttl"`
		StatusList *struct {
			Bits int    `json:"bits"`
			Lst  string `json:"lst"`
		} `json:"status_list"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return 0, nil, time.Time{}, fmt.Errorf("status list payload: %w", err)
	}
	if claims.StatusList == nil {
		return 0, nil, time.Time{}, errors.New("status list token has no status_list claim")
	}
	lst, err := base64.RawURLEncoding.DecodeString(claims.StatusList.Lst)
	if err != nil {
		return 0, nil, time.Time{}, fmt.Errorf("status list lst: %w", err)
	}
	return c.accept(ctx, uri, km, listClaims{
		sub: claims.Sub, iss: claims.Iss, iat: claims.Iat, exp: claims.Exp, ttl: claims.TTL,
		bits: claims.StatusList.Bits, lst: lst,
	})
}

// listClaims is the form-independent content of a Status List Token.
type listClaims struct {
	sub, iss      string
	iat, exp, ttl *int64
	bits          int
	lst           []byte // zlib-compressed, not base64
}

// accept applies the claim checks shared by the JWT and CWT forms, inflates
// the list and asks the trust service about the (already signature-verified)
// signer key km. Only a list that passes all of it is returned.
func (c *Checker) accept(ctx context.Context, uri string, km *trust.KeyMaterial, lc listClaims) (int, []byte, time.Time, error) {
	if lc.iat == nil {
		return 0, nil, time.Time{}, errors.New("status list token has no iat")
	}
	if lc.sub != uri {
		return 0, nil, time.Time{}, fmt.Errorf("status list sub %q does not match uri %q", lc.sub, uri)
	}
	now := c.now()
	// The ttl claim is the token's freshness window, measured from its iat
	// (not from when this wallet fetched it). Without ttl, a default window
	// from now applies. exp and maxCacheTTL cap it.
	expires := now.Add(defaultCacheTTL)
	if lc.ttl != nil && *lc.ttl > 0 {
		expires = time.Unix(*lc.iat, 0).Add(time.Duration(*lc.ttl) * time.Second)
	}
	if lc.exp != nil {
		exp := time.Unix(*lc.exp, 0)
		if !now.Before(exp) {
			return 0, nil, time.Time{}, errors.New("status list token has expired")
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
		return 0, nil, time.Time{}, fmt.Errorf("status list bits %d is not 1, 2, 4 or 8", lc.bits)
	}
	list, err := inflate(lc.lst)
	if err != nil {
		return 0, nil, time.Time{}, err
	}
	if err := c.evaluateSigner(ctx, lc.iss, uri, km); err != nil {
		return 0, nil, time.Time{}, err
	}
	return lc.bits, list, expires, nil
}

// evaluateSigner asks the trust service whether the list signer may publish
// status lists. The subject is the list's iss claim, or the origin of its URI.
func (c *Checker) evaluateSigner(ctx context.Context, iss, uri string, km *trust.KeyMaterial) error {
	if c.trust == nil {
		return fmt.Errorf("%w: no trust service configured", ErrTrustUnavailable)
	}
	subject := iss
	if subject == "" {
		u, err := url.Parse(uri)
		if err != nil || u.Host == "" {
			return fmt.Errorf("%w: no signer identity", ErrTrustUnavailable)
		}
		subject = u.Scheme + "://" + u.Host
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
func checkJWKMatchesLeaf(jwkParam map[string]any, leaf string) error {
	if len(jwkParam) == 0 {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(leaf)
	if err != nil {
		return fmt.Errorf("status list x5c leaf: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("status list x5c leaf: %w", err)
	}
	b, err := json.Marshal(jwkParam)
	if err != nil {
		return err
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(b); err != nil {
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
