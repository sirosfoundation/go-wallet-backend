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
	// maxCacheEntries bounds the cache; on overflow it is simply reset.
	maxCacheEntries = 256

	statusListTokenTyp = "statuslist+jwt"
)

// errUnbound is returned for a list whose signature cannot be tied to the
// credential's issuer key, so its content must not be acted on.
var errUnbound = errors.New("status list signature cannot be bound to the credential issuer's key (credential header carries no x5c or jwk)")

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
	// allowHTTP permits a plain-http status list URI (development only).
	allowHTTP bool
	now       func() time.Time

	mu    sync.Mutex
	cache map[string]cachedList
}

type cachedList struct {
	bits    int
	list    []byte
	expires time.Time
}

// NewChecker returns a Checker that fetches through client, which must be the
// SSRF-guarded client (HTTPClientConfig.NewHTTPClient).
func NewChecker(client *http.Client, allowHTTP bool) *Checker {
	return &Checker{client: client, allowHTTP: allowHTTP, now: time.Now, cache: map[string]cachedList{}}
}

// Check returns nil only if the entry at ref is VALID in a status list token
// that was fetched, is signed, matches ref.URI and is still fresh. A positive
// determination that the entry is not VALID returns an error wrapping
// ErrRevoked; every failure to find out (network, non-200, CWT, expired list,
// bad or unverifiable signature, malformed token) returns an error that does
// not. Callers choose what to do with the latter.
//
// signer is the key the credential itself was issued under (its x5c or jwk
// header). If the list carries its own key (x5c or jwk header) it must be the
// same key; if it carries none (only a kid, which is what siros-status-service
// publishes) it is verified against signer. When signer is nil the list
// cannot be bound to the issuer and is unverifiable: Check returns an error
// (never ErrRevoked), because a list that vouches for itself proves nothing.
func (c *Checker) Check(ctx context.Context, ref *Reference, signer *trust.KeyMaterial) error {
	bits, list, err := c.load(ctx, ref.URI, signer)
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

func (c *Checker) load(ctx context.Context, uri string, signer *trust.KeyMaterial) (int, []byte, error) {
	key := uri
	if signer != nil {
		key += "\x00" + signerFingerprint(signer)
	}
	c.mu.Lock()
	if e, ok := c.cache[key]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.bits, e.list, nil
	}
	c.mu.Unlock()

	token, err := c.fetch(ctx, uri)
	if err != nil {
		return 0, nil, err
	}
	bits, list, ttl, err := c.parse(token, uri, signer)
	if err != nil {
		return 0, nil, err
	}
	c.mu.Lock()
	if len(c.cache) >= maxCacheEntries {
		c.cache = map[string]cachedList{}
	}
	c.cache[key] = cachedList{bits: bits, list: list, expires: c.now().Add(ttl)}
	c.mu.Unlock()
	return bits, list, nil
}

func (c *Checker) fetch(ctx context.Context, uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("status list uri: %w", err)
	}
	if u.Scheme != "https" && (!c.allowHTTP || u.Scheme != "http") {
		return "", fmt.Errorf("status list uri must be https: %q", u.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/"+statusListTokenTyp)
	// The URI comes from a credential the holder presents, so it is
	// attacker-influenced by nature. The scheme is checked above and c.client
	// is the SSRF-guarded client (NewHTTPClient: private, loopback, link-local
	// and metadata addresses refused on every hop, DNS pinned to the checked
	// address); there is no allowlist because issuers are arbitrary public
	// hosts.
	resp, err := c.client.Do(req) // lgtm[go/request-forgery]
	if err != nil {
		return "", fmt.Errorf("fetch status list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch status list: http %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		mt, _, _ := mime.ParseMediaType(ct)
		if mt == "application/statuslist+cwt" {
			return "", errors.New("status list is a CWT; only the JWT form is supported")
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("read status list: %w", err)
	}
	if len(body) > maxTokenBytes {
		return "", errors.New("status list token too large")
	}
	return strings.TrimSpace(string(body)), nil
}

func (c *Checker) parse(token, uri string, signer *trust.KeyMaterial) (int, []byte, time.Duration, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, nil, 0, errors.New("status list token is not a JWT")
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return 0, nil, 0, fmt.Errorf("status list header: %w", err)
	}
	if !strings.EqualFold(header.Typ, statusListTokenTyp) {
		return 0, nil, 0, fmt.Errorf("status list token typ is %q, want %q", header.Typ, statusListTokenTyp)
	}
	// Trust model: a list is only authoritative when its signature is bound
	// to the key the credential was issued under. A key the list carries for
	// itself proves nothing (whoever substitutes the response can self-sign
	// an all-valid list), so without a signer the list is unverifiable.
	if signer == nil {
		return 0, nil, 0, errUnbound
	}
	km, err := trust.VerifyJWTWithEmbeddedKey(token)
	switch {
	case err == nil:
		if !sameKey(signer, km) {
			return 0, nil, 0, errors.New("status list is not signed by the credential's issuer key")
		}
	case errors.Is(err, trust.ErrNoEmbeddedKey):
		// Only a kid in the header (what siros-status-service publishes):
		// verify against the credential's own issuer key.
		if err := verifyWithKey(token, signer); err != nil {
			return 0, nil, 0, fmt.Errorf("status list signature: %w", err)
		}
	default:
		return 0, nil, 0, fmt.Errorf("status list signature: %w", err)
	}

	var claims struct {
		Sub        string `json:"sub"`
		Iat        *int64 `json:"iat"`
		Exp        *int64 `json:"exp"`
		TTL        *int64 `json:"ttl"`
		StatusList *struct {
			Bits int    `json:"bits"`
			Lst  string `json:"lst"`
		} `json:"status_list"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return 0, nil, 0, fmt.Errorf("status list payload: %w", err)
	}
	if claims.Iat == nil {
		return 0, nil, 0, errors.New("status list token has no iat")
	}
	if claims.Sub != uri {
		return 0, nil, 0, fmt.Errorf("status list sub %q does not match uri %q", claims.Sub, uri)
	}
	if claims.StatusList == nil {
		return 0, nil, 0, errors.New("status list token has no status_list claim")
	}
	now := c.now()
	ttl := defaultCacheTTL
	if claims.TTL != nil && *claims.TTL > 0 {
		ttl = time.Duration(*claims.TTL) * time.Second
	}
	if claims.Exp != nil {
		exp := time.Unix(*claims.Exp, 0)
		if !now.Before(exp) {
			return 0, nil, 0, errors.New("status list token has expired")
		}
		if until := exp.Sub(now); until < ttl {
			ttl = until
		}
	}
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}
	switch claims.StatusList.Bits {
	case 1, 2, 4, 8:
	default:
		return 0, nil, 0, fmt.Errorf("status list bits %d is not 1, 2, 4 or 8", claims.StatusList.Bits)
	}
	list, err := inflate(claims.StatusList.Lst)
	if err != nil {
		return 0, nil, 0, err
	}
	return claims.StatusList.Bits, list, ttl, nil
}

// verifyWithKey verifies the JWS signature of token against a key the caller
// already holds (the credential's issuer key).
func verifyWithKey(token string, km *trust.KeyMaterial) error {
	var pub any
	switch {
	case len(km.X5C) > 0:
		der, err := base64.StdEncoding.DecodeString(km.X5C[0])
		if err != nil {
			return fmt.Errorf("x5c leaf: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("x5c leaf: %w", err)
		}
		pub = cert.PublicKey
	case km.JWK != nil:
		b, err := json.Marshal(km.JWK)
		if err != nil {
			return err
		}
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(b); err != nil {
			return err
		}
		pub = jwk.Key
	default:
		return errors.New("no key to verify with")
	}
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.RS256, jose.PS256, jose.EdDSA})
	if err != nil {
		return err
	}
	_, err = jws.Verify(pub)
	return err
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func inflate(lst string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		return nil, fmt.Errorf("status list lst: %w", err)
	}
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

// keyID reduces a signer's embedded key to a comparable string: the
// SubjectPublicKeyInfo of the x5c leaf, or the RFC 7638 thumbprint of the JWK.
func keyID(km *trust.KeyMaterial) string {
	if km == nil {
		return ""
	}
	if len(km.X5C) > 0 {
		der, err := base64.StdEncoding.DecodeString(km.X5C[0])
		if err != nil {
			return ""
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return ""
		}
		return "spki:" + string(cert.RawSubjectPublicKeyInfo)
	}
	if km.JWK != nil {
		b, err := json.Marshal(km.JWK)
		if err != nil {
			return ""
		}
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(b); err != nil {
			return ""
		}
		tp, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return ""
		}
		return "jwk:" + string(tp)
	}
	return ""
}

func signerFingerprint(km *trust.KeyMaterial) string { return keyID(km) }

func sameKey(a, b *trust.KeyMaterial) bool {
	ka := keyID(a)
	return ka != "" && ka == keyID(b)
}
